import argparse
import json
import yaml
import os
import re
import subprocess
from pathlib import Path
from . import owasp
from .schema_handler import SchemaHandler
from . import pydantic_handler

class DefinitionGenerator:
    def __init__(self, serverless_config, serverless_yml_path, openapi_version='3.0.3'):
        self.serverless_dir = os.path.dirname(serverless_yml_path)
        self.serverless_config = self._resolve_file_references(serverless_config)
        owasp.get_latest()
        self.open_api = {
            "openapi": openapi_version,
            "info": {},
            "paths": {},
            "components": {
                "schemas": {}
            }
        }
        self.schema_handler = SchemaHandler(self.serverless_config, self.open_api, self.serverless_dir)

    def _resolve_file_references(self, value):
        if isinstance(value, dict):
            return {k: self._resolve_file_references(v) for k, v in value.items()}
        elif isinstance(value, list):
            return [self._resolve_file_references(item) for item in value]
        elif isinstance(value, str):
            match = re.match(r'\${file\((.*)\)}', value)
            if match:
                file_path = match.group(1).strip()
                abs_path = os.path.join(self.serverless_dir, file_path)
                try:
                    with open(abs_path, 'r') as f:
                        if file_path.endswith('.json'):
                            return json.load(f)
                        else:
                            return yaml.safe_load(f)
                except (IOError, yaml.YAMLError, json.JSONDecodeError) as e:
                    print(f"Warning: Could not read or parse file reference {abs_path}: {e}")
                    return value
        return value

    def generate(self):
        self.schema_handler.add_models_to_openapi()
        self.create_info()
        self.create_security_schemes()
        self.create_tags()
        self.create_servers()
        self.create_paths()
        return self.open_api

    def _extend_spec(self, spec_dict):
        """Finds and returns all 'x-' prefixed fields from a dictionary."""
        return {k: v for k, v in spec_dict.items() if k.startswith('x-')}

    def create_info(self):
        service = self.serverless_config.get('service', {})
        documentation = self.serverless_config.get('custom', {}).get('documentation', {})

        info = {
            'title': documentation.get('title', service if isinstance(service, str) else service.get('name', 'My API')),
            'description': documentation.get('description', ''),
            'version': documentation.get('version', '1.0.0') # Use a deterministic version
        }

        if documentation.get('termsOfService'):
            info['termsOfService'] = documentation['termsOfService']

        if documentation.get('contact'):
            contact = {
                'name': documentation['contact'].get('name'),
                'url': documentation['contact'].get('url'),
                'email': documentation['contact'].get('email'),
            }
            # Remove None values
            contact = {k: v for k, v in contact.items() if v is not None}
            contact.update(self._extend_spec(documentation['contact']))
            if contact:
                info['contact'] = contact

        if documentation.get('license') and documentation['license'].get('name'):
            license_obj = {
                'name': documentation['license'].get('name'),
                'url': documentation['license'].get('url'),
            }
            license_obj = {k: v for k, v in license_obj.items() if v is not None}
            license_obj.update(self._extend_spec(documentation['license']))
            if license_obj:
                info['license'] = license_obj
        
        info.update(self._extend_spec(documentation))
        
        self.open_api['info'] = info

    def get_http_functions(self):
        functions = self.serverless_config.get('functions', {})
        http_functions = []
        for func_name, func_details in functions.items():
            if 'events' in func_details:
                for event in func_details['events']:
                    if 'http' in event or 'httpApi' in event:
                        http_functions.append({
                            'name': func_name,
                            'details': func_details
                        })
                        break # Only need to find one http event
        return http_functions

    def create_paths(self):
        http_functions = self.get_http_functions()
        paths = {}

        for func in http_functions:
            for event in func['details'].get('events', []):
                http_event = event.get('http') or event.get('httpApi')
                if not http_event:
                    continue

                documentation = http_event.get('documentation', {})
                if not documentation:
                    continue

                path = http_event.get('path')
                method = http_event.get('method', 'get').lower()

                if not path:
                    continue
                
                # Handle path parameters
                if path.startswith('/'):
                    path = path[1:]
                
                if documentation.get('pathParams'):
                    for param in documentation.get('pathParams'):
                        path = path.replace(f"{{{param['name']}}}", "") # Remove if already there
                    path_params_str = "/".join([f"{{{p['name']}}}" for p in documentation.get('pathParams')])
                    full_path = f"/{path}/{path_params_str}"
                else:
                    full_path = f"/{path}"
                
                full_path = full_path.replace('//', '/')


                if full_path not in paths:
                    paths[full_path] = {}
                
                operation_object = self.create_operation_object(documentation, func, http_event)
                paths[full_path][method] = operation_object

        self.open_api['paths'] = paths

    def create_operation_object(self, documentation, func, http_event):
        service_name = self.serverless_config.get('service', 'service')
        stage = self.serverless_config.get('provider', {}).get('stage', 'dev')
        func_name = func['name']
        operation_id = f"{service_name}-{stage}-{func_name}"
        
        obj = {
            'summary': documentation.get('summary', ''),
            'description': documentation.get('description', func['details'].get('description', '')),
            'operationId': operation_id,
            'parameters': [],
            'tags': documentation.get('tags', []),
        }

        if documentation.get('pathParams'):
            obj['parameters'].extend(self.create_param_object('path', documentation.get('pathParams')))
        
        if documentation.get('queryParams'):
            obj['parameters'].extend(self.create_param_object('query', documentation.get('queryParams')))

        if documentation.get('headerParams'):
            obj['parameters'].extend(self.create_param_object('header', documentation.get('headerParams')))

        if documentation.get('cookieParams'):
            obj['parameters'].extend(self.create_param_object('cookie', documentation.get('cookieParams')))

        if documentation.get('methodResponses'):
            obj['responses'] = self.create_responses(documentation)
        else:
            obj['responses'] = {'200': {'description': 'Successful response'}}

        if documentation.get('requestBody'):
            obj['requestBody'] = self.create_request_body(documentation.get('requestBody'))
        elif http_event.get('request', {}).get('schemas'):
            # Handle request schemas defined directly on the event
            schemas = http_event['request']['schemas']
            content = {}
            for media_type, schema_info in schemas.items():
                if isinstance(schema_info, str):
                    schema_name = schema_info
                    # Find the model name from the standardized models
                    model = next((model for model in self.schema_handler.models if model.get('key') == schema_name), None)
                    if model:
                        content[media_type] = {
                            'schema': {
                                '$ref': f"#/components/schemas/{model['name']}"
                            }
                        }
                elif isinstance(schema_info, dict):
                    schema_name = ''.join(word.capitalize() for word in re.split(r'[/_-]', media_type))
                    schema_ref = self.schema_handler.create_schema(schema_name, schema_info)
                    content[media_type] = {'schema': {'$ref': schema_ref}}

            if content:
                obj['requestBody'] = {
                    'description': 'Request body inferred from event schema',
                    'content': content,
                    'required': True
                }

        # Handle private endpoints
        if http_event.get('private') is True:
            api_key_name = 'x-api-key'
            # Ensure the scheme exists
            if 'securitySchemes' not in self.open_api['components']:
                self.open_api['components']['securitySchemes'] = {}
            if api_key_name not in self.open_api['components']['securitySchemes']:
                 self.open_api['components']['securitySchemes'][api_key_name] = {
                     'type': 'apiKey', 'name': 'x-api-key', 'in': 'header'
                 }
            # Add security requirement to the operation
            if 'security' not in obj:
                obj['security'] = []
            obj['security'].append({api_key_name: []})

        return obj

    def create_param_object(self, param_in, params_doc):
        params = []
        for param in params_doc:
            obj = {
                'name': param.get('name'),
                'in': param_in,
                'description': param.get('description', ''),
                'required': param.get('required', True if param_in == 'path' else False),
            }
            if 'schema' in param:
                schema_name = param.get('name')
                schema_ref = self.schema_handler.create_schema(schema_name, param['schema'])
                obj['schema'] = {'$ref': schema_ref}
            else:
                 obj['schema'] = {'type': 'string'}
            
            params.append(obj)
        return params

    def create_responses(self, documentation):
        responses = {}
        for response in documentation.get('methodResponses', []):
            status_code = str(response.get('statusCode', '200'))
            
            obj = {
                'description': response.get('responseBody', {}).get('description', '')
            }
            
            # Placeholder for content/models
            if response.get('responseModels'):
                obj['content'] = self.create_media_type_object(response.get('responseModels'))

            headers = {}
            if response.get('responseHeaders'):
                headers.update(self.create_response_headers(response.get('responseHeaders')))

            if response.get('owasp'):
                owasp_options = response.get('owasp')
                if isinstance(owasp_options, bool) and owasp_options:
                    # The original JS code seems to have a default set of headers if `true` is passed
                    # Replicating a minimal version of that behavior.
                    owasp_options = {h: True for h in owasp.HEADER_NAME_MAP.keys()}
                
                owasp_headers = owasp.get_headers(owasp_options)
                headers.update(self.create_response_headers(owasp_headers))
            
            if headers:
                obj['headers'] = headers

            responses[status_code] = obj
        return responses

    def create_media_type_object(self, models):
        content = {}
        if models:
            for media_type, schema_name in models.items():
                print(f"Schema name: {schema_name}")
                print(f"Models: {self.schema_handler.models}")
                model_info = next((model for model in self.schema_handler.models if model['name'] == schema_name), None)
                if model_info:
                    schema_ref = self.schema_handler.create_schema(schema_name, model_info.get('schema'))
                    content[media_type] = {'schema': {'$ref': schema_ref}}
        return content

    def create_request_body(self, request_body_doc):
        content = self.create_media_type_object(request_body_doc.get('requestModels', {}))
        
        obj = {
            'description': request_body_doc.get('description', ''),
            'required': request_body_doc.get('required', False),
            'content': content,
        }
        
        return obj

    def create_security_schemes(self):
        documentation = self.serverless_config.get('custom', {}).get('documentation', {})
        schemes = documentation.get('securitySchemes', {})
        if not schemes:
            return

        if 'components' not in self.open_api:
            self.open_api['components'] = {}
        
        self.open_api['components']['securitySchemes'] = {}

        for name, definition in schemes.items():
            scheme_type = definition.get('type', '').lower()
            if scheme_type == 'apikey':
                self._validate_api_key_scheme(definition)
            elif scheme_type == 'http':
                self._validate_http_scheme(definition)
            elif scheme_type == 'oauth2':
                self._validate_oauth2_scheme(definition)
            elif scheme_type == 'openidconnect':
                self._validate_openid_scheme(definition)
            
            self.open_api['components']['securitySchemes'][name] = definition

        if documentation.get('security'):
            self.open_api['security'] = documentation.get('security')

    def _validate_api_key_scheme(self, definition):
        if not definition.get('name'):
            raise ValueError('Security Scheme for "apiKey" requires the name of the header, query or cookie parameter to be used')
        if not definition.get('in'):
            raise ValueError('Security Scheme for "apiKey" requires the location of the API key: header, query or cookie parameter')

    def _validate_http_scheme(self, definition):
        if not definition.get('scheme'):
            raise ValueError('Security Scheme for "http" requires scheme')

    def _validate_openid_scheme(self, definition):
        if not definition.get('openIdConnectUrl'):
            raise ValueError('Security Scheme for "openIdConnect" requires openIdConnectUrl')

    def _validate_oauth2_scheme(self, definition):
        if not definition.get('flows'):
            raise ValueError('Security Scheme for "oauth2" requires flows')
        flows = definition.get('flows', {})
        for flow_name, flow in flows.items():
            if flow_name in ['implicit', 'authorizationCode'] and not flow.get('authorizationUrl'):
                raise ValueError(f"oAuth2 {flow_name} flow requires an authorizationUrl")
            if flow_name in ['password', 'clientCredentials', 'authorizationCode'] and not flow.get('tokenUrl'):
                raise ValueError(f"oAuth2 {flow_name} flow requires a tokenUrl")
            if not flow.get('scopes'):
                raise ValueError(f"oAuth2 {flow_name} flow requires scopes")

    def create_tags(self):
        documentation = self.serverless_config.get('custom', {}).get('documentation', {})
        tags = documentation.get('tags')
        if tags:
            self.open_api['tags'] = tags

    def create_servers(self):
        documentation = self.serverless_config.get('custom', {}).get('documentation', {})
        servers = documentation.get('servers')
        if servers:
            self.open_api['servers'] = servers

    def create_response_headers(self, headers_doc):
        headers = {}
        if isinstance(headers_doc, list):
            for header in headers_doc:
                header_name = header.get('name')
                if not header_name:
                    continue
                header_obj = {
                    'description': header.get('description', '')
                }
                if 'schema' in header:
                    schema_ref = self.schema_handler.create_schema(header_name, header['schema'])
                    header_obj['schema'] = {'$ref': schema_ref}
                headers[header_name] = header_obj
        elif isinstance(headers_doc, dict):
            for header_name, header_details in headers_doc.items():
                header_obj = {
                    'description': header_details.get('description', '')
                }
                if 'schema' in header_details:
                    # Following the pattern of creating a schema in components for the header
                    schema_ref = self.schema_handler.create_schema(header_name, header_details['schema'])
                    header_obj['schema'] = {'$ref': schema_ref}
                
                headers[header_name] = header_obj
        return headers

def main():
    parser = argparse.ArgumentParser(description='Generate OpenAPI v3 documentation from a serverless.yml file.')
    parser.add_argument('output_file_path', type=str, help='Path to the output OpenAPI JSON file')
    parser.add_argument('--serverless-yml-path', type=str, help='Path to the serverless.yml file. Required if --pydantic-source is not used.')
    parser.add_argument('--openApiVersion', type=str, default='3.0.3', help='OpenAPI version to use')
    parser.add_argument('--pre-hook', type=str, help='Path to a Python script to run before generation')
    parser.add_argument('--pydantic-source', type=str, help='Path to the Pydantic models source directory')
    parser.add_argument('--validate', action='store_true', help='Validate the generated OpenAPI spec')
    args = parser.parse_args()

    if not args.serverless_yml_path and not args.pydantic_source:
        parser.error("Either --serverless-yml-path or --pydantic-source must be provided.")

    # Execute the pre-hook script if provided
    if args.pre_hook:
        print(f"--- Running pre-hook script: {args.pre_hook} ---")
        try:
            subprocess.run(['python', args.pre_hook], check=True, text=True)
            print("--- Pre-hook script finished successfully ---")
        except FileNotFoundError:
            print(f"Error: Pre-hook script not found at {args.pre_hook}")
            return
        except subprocess.CalledProcessError as e:
            print(f"Error executing pre-hook script: {e}")
            return

    # Execute the Pydantic schema generation if the source is provided
    if args.pydantic_source:
        print(f"--- Running Pydantic schema generation from: {args.pydantic_source} ---")
        project_root = Path(args.pydantic_source)
        output_dir = project_root / "openapi_models"
        
        generated_schemas = pydantic_handler.generate_dto_schemas(project_root, output_dir, project_root)
        project_meta = pydantic_handler.load_project_meta(project_root)
        
        serverless_config = pydantic_handler.generate_serverless_config(generated_schemas, project_meta, project_root)
        
        # Use a virtual file path in the project root for correct base directory resolution
        effective_sls_path = project_root / "serverless.yml"
        
        print("--- Pydantic schema generation finished successfully ---")
    else:
        try:
            with open(args.serverless_yml_path, 'r') as f:
                serverless_config = yaml.safe_load(f)
            effective_sls_path = args.serverless_yml_path
        except FileNotFoundError:
            print(f"Error: The file {args.serverless_yml_path} was not found.")
            return
        except yaml.YAMLError as e:
            print(f"Error parsing YAML file: {e}")
            return

    generator = DefinitionGenerator(serverless_config, str(effective_sls_path), args.openApiVersion)
    open_api_spec = generator.generate()

    try:
        with open(args.output_file_path, 'w') as f:
            json.dump(open_api_spec, f, indent=2)
        print(f"OpenAPI specification successfully written to {args.output_file_path}")
    except IOError as e:
        print(f"Error writing to output file: {e}")

    if args.validate:
        from openapi_spec_validator import validate
        print("Validating generated spec...")
        try:
            validate(open_api_spec)
            print("Validation successful.")
        except Exception as e:
            print(f"Validation failed: {e}")

if __name__ == '__main__':
    main()
