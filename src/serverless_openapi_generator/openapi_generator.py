import argparse
import json
import yaml
import os
import re
import tomllib
from pathlib import Path
from typing import Dict, List, Optional
from rich import print as rprint
from . import owasp
from .schema_handler import SchemaHandler
from . import pydantic_handler
from .endpoint_mapper import EndpointMapper


def extract_metadata_from_pyproject(source_dir: Path) -> Dict[str, str]:
    """
    Extract metadata from pyproject.toml file.
    
    Args:
        source_dir: Directory to search for pyproject.toml
        
    Returns:
        Dictionary with title, description, and version if found
    """
    metadata = {}
    
    # Look for pyproject.toml in source_dir and parent directories
    current_dir = Path(source_dir).resolve()
    pyproject_path = None
    
    # Search up to 3 levels up from source directory
    for _ in range(4):
        potential_path = current_dir / 'pyproject.toml'
        if potential_path.exists():
            pyproject_path = potential_path
            break
        current_dir = current_dir.parent
        if current_dir == current_dir.parent:  # reached root
            break
    
    if not pyproject_path:
        return metadata
    
    try:
        with open(pyproject_path, 'rb') as f:
            pyproject_data = tomllib.load(f)
        
        # Extract from [tool.poetry] section
        if 'tool' in pyproject_data and 'poetry' in pyproject_data['tool']:
            poetry_config = pyproject_data['tool']['poetry']
            
            if 'name' in poetry_config:
                metadata['title'] = poetry_config['name'].replace('_', ' ').title()
            if 'description' in poetry_config:
                metadata['description'] = poetry_config['description']
            if 'version' in poetry_config:
                metadata['version'] = poetry_config['version']
        
        # Extract from [project] section (PEP 621)
        elif 'project' in pyproject_data:
            project_config = pyproject_data['project']
            
            if 'name' in project_config:
                metadata['title'] = project_config['name'].replace('_', ' ').title()
            if 'description' in project_config:
                metadata['description'] = project_config['description']
            if 'version' in project_config:
                metadata['version'] = project_config['version']
    
    except (FileNotFoundError, tomllib.TOMLDecodeError, KeyError) as e:
        rprint(f"[yellow]Warning: Could not parse pyproject.toml at {pyproject_path}: {e}[/yellow]")
    
    return metadata


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
                    rprint(f"[yellow]Warning: Could not read or parse file reference {abs_path}: {e}[/yellow]")
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

                documentation = http_event.get('documentation')

                if documentation is False:
                    continue
                
                if documentation is None:
                    documentation = {}

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
        
        tags = documentation.get('tags', [])
        if not tags:
            handler_path = func.get('details', {}).get('handler', '')
            if handler_path:
                # e.g. src.api.users.handler -> users
                parts = handler_path.split('.')
                if len(parts) > 2:
                    tags.append(parts[-2])
        
        obj = {
            'summary': documentation.get('summary', ''),
            'description': documentation.get('description', func['details'].get('description', '')),
            'operationId': operation_id,
            'parameters': [],
            'tags': tags,
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


class PythonBasedGenerator:
    """Generate OpenAPI specs directly from Python code."""
    
    def __init__(self, openapi_version='3.0.3'):
        self.openapi_version = openapi_version
        self.endpoint_mapper = EndpointMapper()
        
    def generate_from_python(self, source_dir: Path, 
                           endpoint_pattern: str = "**/handler.py",
                           docs_pattern: str = "**/docs.py",
                           title: Optional[str] = None,
                           version: Optional[str] = None,
                           description: Optional[str] = None) -> dict:
        """
        Generate OpenAPI specification from Python source code.
        
        Args:
            source_dir: Root directory containing Python source code
            endpoint_pattern: Glob pattern for endpoint files
            docs_pattern: Glob pattern for documentation files
            title: API title (if None, extracted from pyproject.toml)
            version: API version (if None, extracted from pyproject.toml)
            description: API description (if None, extracted from pyproject.toml)
            
        Returns:
            Complete OpenAPI specification dictionary
        """
        # Extract metadata from pyproject.toml as fallback
        pyproject_metadata = extract_metadata_from_pyproject(source_dir)
        
        # Use provided values or fallback to pyproject.toml or defaults
        final_title = title or pyproject_metadata.get('title', 'Generated API')
        final_version = version or pyproject_metadata.get('version', '1.0.0')
        final_description = description or pyproject_metadata.get('description', '')
        
        if pyproject_metadata:
            rprint(f"[dim]Using metadata from pyproject.toml: title='{pyproject_metadata.get('title', 'N/A')}', version='{pyproject_metadata.get('version', 'N/A')}', description='{pyproject_metadata.get('description', 'N/A')}'[/dim]")
        # Initialize OpenAPI spec structure
        openapi_spec = {
            "openapi": self.openapi_version,
            "info": {
                "title": final_title,
                "version": final_version,
                "description": final_description
            },
            "servers": [
                {
                    "url": "https://api.example.com",
                    "description": "Production server"
                },
                {
                    "url": "https://staging-api.example.com", 
                    "description": "Staging server"
                }
            ],
            "paths": {},
            "components": {
                "schemas": {},
                "securitySchemes": {
                    "bearerAuth": {
                        "type": "http",
                        "scheme": "bearer",
                        "bearerFormat": "JWT",
                        "description": "JWT Bearer token authentication"
                    },
                    "oauth2": {
                        "type": "oauth2",
                        "description": "OAuth2 authentication",
                        "flows": {
                            "authorizationCode": {
                                "authorizationUrl": "/oauth2/authorize",
                                "tokenUrl": "/oauth2/token",
                                "scopes": {
                                    "read": "Read access",
                                    "write": "Write access"
                                }
                            }
                        }
                    }
                }
            }
        }
        
        # Initialize the schema handler with the spec
        schema_handler = SchemaHandler(openapi_spec, openapi_spec, str(source_dir.parent))
        
        # Discover all endpoints
        endpoints = self.endpoint_mapper.discover_all_endpoints(
            source_dir, endpoint_pattern, docs_pattern
        )
        
        if not endpoints:
            rprint("[yellow]Warning: No endpoints discovered[/yellow]")
            return openapi_spec
        
        rprint(f"[green]Discovered {len(endpoints)} endpoints[/green]")
        
        # Collect all referenced schemas first
        self._collect_schemas(endpoints, openapi_spec, source_dir, schema_handler)
        
        # Group endpoints by path
        grouped_endpoints = self.endpoint_mapper.group_by_path(endpoints)
        
        # Generate paths
        for path, methods in grouped_endpoints.items():
            openapi_spec["paths"][path] = {}
            
            for method, endpoint in methods.items():
                operation = self._create_operation_from_endpoint(endpoint, openapi_spec)
                openapi_spec["paths"][path][method] = operation
        
        return openapi_spec
    
    def _create_operation_from_endpoint(self, endpoint, openapi_spec: dict) -> dict:
        """Create OpenAPI operation object from endpoint info."""
        # Create a meaningful operation ID
        operation_id = f"{endpoint.endpoint_name}_{endpoint.http_method.lower()}"
        if endpoint.endpoint_name == endpoint.function_name:
            operation_id = f"{endpoint.function_name}_{endpoint.http_method.lower()}"
        
        # Use rich documentation from docs.py when available
        summary = endpoint.summary or self._generate_summary(endpoint)
        description = endpoint.description or self._generate_description(endpoint)
        
        # Enhance description with OAuth2/OIDC context if available
        if hasattr(endpoint, 'response_description') and endpoint.response_description:
            if description and not description.endswith('.'):
                description += '. '
            description += endpoint.response_description
        
        operation = {
            "operationId": operation_id,
            "summary": summary,
            "description": description,
            "tags": endpoint.tags or [endpoint.endpoint_name or "api"],
            "parameters": [],
            "responses": self._create_enhanced_responses_from_docs(endpoint)
        }
        
        # Add path parameters
        path_params = self.endpoint_mapper.infer_parameters_from_path(endpoint.path)
        operation["parameters"].extend(path_params)
        
        # Add query parameters for GET requests
        if endpoint.http_method.upper() == 'GET' and endpoint.request_model:
            query_params = self._infer_query_parameters(endpoint)
            operation["parameters"].extend(query_params)
        
        # Add request body for non-GET methods
        if endpoint.http_method.upper() not in ['GET', 'DELETE', 'HEAD', 'OPTIONS'] and endpoint.request_model:
            # Pass valid schemas to validate references
            valid_schemas = set(openapi_spec.get("components", {}).get("schemas", {}).keys())
            request_body = self.endpoint_mapper.infer_request_body_from_function(endpoint, valid_schemas)
            if request_body:
                operation["requestBody"] = request_body
        
        # Add security if this looks like a protected endpoint
        if self._requires_authentication(endpoint):
            operation["security"] = [{"bearerAuth": []}]
        
        return operation
    
    def _create_enhanced_responses_from_docs(self, endpoint) -> Dict[str, Dict]:
        """Create enhanced OpenAPI responses using docs.py metadata."""
        responses = {}
        
        # Use responses from docs.py if available
        if hasattr(endpoint, 'responses') and endpoint.responses:
            for status_code, response_info in endpoint.responses.items():
                status_str = str(status_code)
                response_def = {
                    'description': response_info.get('description', f'Response {status_code}')
                }
                
                # Add schema reference if model is specified
                if 'model' in response_info:
                    model_name = response_info['model']
                    if model_name:
                        # Determine content type based on endpoint type
                        content_type = self._determine_content_type(endpoint, status_code)
                        response_def['content'] = {
                            content_type: {
                                'schema': {
                                    '$ref': f'#/components/schemas/{model_name}'
                                }
                            }
                        }
                
                responses[status_str] = response_def
        
        # Add success response if not already present from docs
        success_status = str(getattr(endpoint, 'status_code', 200))
        if success_status not in responses:
            success_response = {
                'description': getattr(endpoint, 'response_description', 'Successful response')
            }
            
            # Add response schema if we have a response model
            if hasattr(endpoint, 'response_model') and endpoint.response_model:
                model_name = self._extract_model_name(endpoint.response_model)
                if model_name:
                    content_type = self._determine_content_type(endpoint, int(success_status))
                    success_response['content'] = {
                        content_type: {
                            'schema': {
                                '$ref': f'#/components/schemas/{model_name}'
                            }
                        }
                    }
            
            responses[success_status] = success_response
        
        # Add OAuth2 specific responses for authorize endpoint (302 redirect)
        if (hasattr(endpoint, 'endpoint_name') and endpoint.endpoint_name and 
            'authorize' in endpoint.endpoint_name.lower() and 
            endpoint.http_method.upper() == 'GET' and 
            '302' not in responses):
            responses['302'] = {
                'description': 'Redirect response for OAuth2 authorization',
                'headers': {
                    'Location': {
                        'schema': {'type': 'string', 'format': 'uri'},
                        'description': 'URL to redirect to with authorization code or error'
                    }
                }
            }
        
        # Add default error responses if not specified in docs
        if '400' not in responses:
            responses['400'] = {
                'description': 'Bad Request - Invalid request parameters',
                'content': {
                    'application/json': {
                        'schema': {
                            '$ref': '#/components/schemas/ErrorResponse'
                        }
                    }
                }
            }
        
        if '500' not in responses:
            responses['500'] = {
                'description': 'Internal Server Error',
                'content': {
                    'application/json': {
                        'schema': {
                            '$ref': '#/components/schemas/ErrorResponse'
                        }
                    }
                }
            }
        
        return responses
    
    def _determine_content_type(self, endpoint, status_code: int) -> str:
        """Determine appropriate content type based on endpoint and status."""
        # OAuth2 token endpoints typically use form-encoded for requests but JSON for responses
        if (hasattr(endpoint, 'endpoint_name') and endpoint.endpoint_name and 
            'token' in endpoint.endpoint_name.lower() and 
            endpoint.http_method.upper() == 'POST'):
            return 'application/json'  # Token responses are JSON
        
        # Default to JSON for most API responses
        return 'application/json'
    
    def _create_enhanced_responses(self, endpoint) -> Dict[str, Dict]:
        """Create enhanced OpenAPI responses with multiple status codes."""
        responses = {}
        
        # Start with any existing responses from endpoint
        if hasattr(endpoint, 'responses') and endpoint.responses:
            responses.update(self.endpoint_mapper.create_openapi_responses(endpoint))
        
        # Add standard responses if not already present
        if '200' not in responses:
            success_response = {
                'description': 'Successful response'
            }
            
            # Add response schema if we have a response model
            if endpoint.response_model:
                model_name = self.endpoint_mapper._extract_model_name(endpoint.response_model)
                if model_name:
                    success_response['content'] = {
                        'application/json': {
                            'schema': {
                                '$ref': f'#/components/schemas/{model_name}'
                            }
                        }
                    }
            
            responses['200'] = success_response
        
        # Add OAuth2 specific responses for authorize endpoint (302 redirect)
        if endpoint.endpoint_name and 'authorize' in endpoint.endpoint_name.lower() and endpoint.http_method.upper() == 'GET':
            responses['302'] = {
                'description': 'Redirect response',
                'headers': {
                    'Location': {
                        'schema': {'type': 'string', 'format': 'uri'},
                        'description': 'URL to redirect to'
                    }
                }
            }
        
        # Add common error responses
        if '400' not in responses:
            responses['400'] = {
                'description': 'Bad Request',
                'content': {
                    'application/json': {
                        'schema': {
                            '$ref': '#/components/schemas/ErrorResponse'
                        }
                    }
                }
            }
        
        if '401' not in responses and self._requires_authentication(endpoint):
            responses['401'] = {
                'description': 'Unauthorized',
                'content': {
                    'application/json': {
                        'schema': {
                            '$ref': '#/components/schemas/ErrorResponse'
                        }
                    }
                }
            }
        
        if '500' not in responses:
            responses['500'] = {
                'description': 'Internal Server Error',
                'content': {
                    'application/json': {
                        'schema': {
                            '$ref': '#/components/schemas/ErrorResponse'
                        }
                    }
                }
            }
        
        return responses
    
    def _generate_summary(self, endpoint) -> str:
        """Generate a meaningful summary for the endpoint."""
        method = endpoint.http_method.upper()
        name = endpoint.endpoint_name or endpoint.function_name
        
        # OAuth2 specific summaries based on endpoint name
        oauth2_summaries = {
            'authorize': 'OAuth2 Authorization Endpoint',
            'token': 'OAuth2 Token Endpoint', 
            'userinfo': 'OAuth2 UserInfo Endpoint',
            'revoke': 'OAuth2 Token Revocation',
            'introspect': 'OAuth2 Token Introspection',
            'register': 'User Registration',
            'login': 'User Login',
            'logout': 'User Logout',
            'jwks': 'JSON Web Key Set',
            'oidc_discovery': 'OIDC Discovery Document',
            'discovery': 'OIDC Discovery',
            'well-known': 'OIDC Discovery',
            'sso_login': 'Single Sign-On Login',
            'password_reset': 'Password Reset'
        }
        
        # Check if this is a known OAuth2/OIDC endpoint
        if name in oauth2_summaries:
            return oauth2_summaries[name]
        
        # Check for partial matches for OAuth2 endpoints
        for oauth_name, oauth_summary in oauth2_summaries.items():
            if oauth_name in name:
                return oauth_summary
        
        # Generic summaries based on HTTP method
        action_verbs = {
            'GET': 'Get',
            'POST': 'Create',
            'PUT': 'Update', 
            'PATCH': 'Modify',
            'DELETE': 'Delete'
        }
        
        verb = action_verbs.get(method, method.title())
        clean_name = name.replace('_', ' ').replace('handler', '').replace('lambda', '').strip().title()
        return f"{verb} {clean_name}"
    
    def _generate_description(self, endpoint) -> str:
        """Generate a meaningful description for the endpoint."""
        if endpoint.docstring:
            # Extract first sentence from docstring
            sentences = endpoint.docstring.strip().split('.')
            if sentences:
                return sentences[0].strip() + '.'
        
        # Fallback descriptions
        method = endpoint.http_method.upper()
        name = endpoint.endpoint_name or endpoint.function_name
        
        if method == 'GET':
            return f"Retrieve {name.replace('_', ' ')} information."
        elif method == 'POST':
            return f"Create or process {name.replace('_', ' ')} operation."
        elif method == 'PUT':
            return f"Update {name.replace('_', ' ')} information."
        elif method == 'DELETE':
            return f"Delete {name.replace('_', ' ')} resource."
        else:
            return f"Perform {name.replace('_', ' ')} operation."
    
    def _infer_query_parameters(self, endpoint) -> List[Dict]:
        """Infer query parameters for GET requests."""
        parameters = []
        
        # For GET requests with request models, try to infer query parameters
        if not endpoint.request_model:
            return parameters
        
        # OAuth2 specific query parameters for /authorize endpoint
        if endpoint.endpoint_name and 'authorize' in endpoint.endpoint_name.lower():
            oauth2_params = [
                {
                    'name': 'response_type',
                    'in': 'query',
                    'required': True,
                    'schema': {'type': 'string', 'enum': ['code']},
                    'description': 'The response type for OAuth2 authorization code flow'
                },
                {
                    'name': 'client_id',
                    'in': 'query', 
                    'required': True,
                    'schema': {'type': 'string'},
                    'description': 'The client identifier'
                },
                {
                    'name': 'redirect_uri',
                    'in': 'query',
                    'required': True,
                    'schema': {'type': 'string', 'format': 'uri'},
                    'description': 'The redirection URI'
                },
                {
                    'name': 'scope',
                    'in': 'query',
                    'required': False,
                    'schema': {'type': 'string'},
                    'description': 'The scope of the access request'
                },
                {
                    'name': 'state',
                    'in': 'query',
                    'required': False,
                    'schema': {'type': 'string'},
                    'description': 'An opaque value to maintain state'
                },
                {
                    'name': 'code_challenge',
                    'in': 'query',
                    'required': False,
                    'schema': {'type': 'string'},
                    'description': 'PKCE code challenge'
                },
                {
                    'name': 'code_challenge_method',
                    'in': 'query',
                    'required': False,
                    'schema': {'type': 'string', 'enum': ['S256']},
                    'description': 'PKCE code challenge method'
                }
            ]
            parameters.extend(oauth2_params)
            
        return parameters
    
    def _requires_authentication(self, endpoint) -> bool:
        """Determine if endpoint requires authentication."""
        # OAuth2 endpoints that typically don't require auth
        public_endpoints = ['authorize', 'token', 'discovery', 'well-known', 'jwks']
        
        endpoint_name = (endpoint.endpoint_name or '').lower()
        if any(public in endpoint_name for public in public_endpoints):
            return False
        
        # Most other endpoints require auth
        return True
    
    def _collect_schemas(self, endpoints, openapi_spec, source_dir: Path, schema_handler):
        """Collect and add all available schemas to the spec."""
        referenced_models = set()
        
        for endpoint in endpoints:
            if endpoint.request_model:
                # Clean up the model name to extract just the class name
                model_name = self._extract_model_name(endpoint.request_model)
                if model_name:
                    referenced_models.add(model_name)
            if endpoint.response_model:
                model_name = self._extract_model_name(endpoint.response_model)
                if model_name:
                    referenced_models.add(model_name)
            
            for response in endpoint.responses.values():
                if 'model' in response:
                    model_name = self._extract_model_name(response['model'])
                    if model_name:
                        referenced_models.add(model_name)
        
        rprint(f"[blue]Found {len(referenced_models)} referenced models: {', '.join(referenced_models)}[/blue]")
        
        # Try to discover and generate Pydantic schemas
        try:
            from . import pydantic_handler
            import tempfile
            
            # Create temporary directory for schema generation
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_output = Path(temp_dir)
                
                # Generate schemas from the source directory
                successfully_generated_schemas = pydantic_handler.generate_dto_schemas(
                    source_dir, temp_output, source_dir
                )
                
                rprint(f"[blue]Generated {len(successfully_generated_schemas)} schemas from Pydantic models[/blue]")
                
                # Include ALL successfully generated schemas, not just referenced ones
                schemas_added = 0
                valid_schema_names = set()
                
                for model_name, schema_filename in successfully_generated_schemas.items():
                    schema_file = temp_output / schema_filename
                    if schema_file.exists():
                        try:
                            with open(schema_file, 'r') as f:
                                schema_data = json.load(f)
                            
                            # Clean the schema to handle $defs and other Pydantic-specific constructs
                            cleaned_schema = schema_handler._clean_schema(schema_data)
                            
                            # Validate that the schema is valid and usable
                            if self._is_valid_schema(cleaned_schema, model_name):
                                openapi_spec["components"]["schemas"][model_name] = cleaned_schema
                                valid_schema_names.add(model_name)
                                schemas_added += 1
                                if model_name in referenced_models:
                                    rprint(f"[green]✓ Added referenced schema for {model_name}[/green]")
                                else:
                                    rprint(f"[dim]✓ Added additional schema for {model_name}[/dim]")
                            else:
                                rprint(f"[yellow]Skipping invalid schema for {model_name}[/yellow]")
                        except Exception as e:
                            rprint(f"[yellow]Could not load schema for {model_name}: {e}[/yellow]")
                    else:
                        rprint(f"[yellow]Schema file not found for {model_name}: {schema_filename}[/yellow]")
                
                # Update endpoints to remove references to invalid schemas
                self._clean_invalid_schema_references(endpoints, valid_schema_names)
                
                rprint(f"[green]Successfully added {schemas_added} schemas to OpenAPI components[/green]")
                        
        except Exception as e:
            rprint(f"[yellow]Could not generate Pydantic schemas: {e}[/yellow]")
        
        # Add placeholder for missing schemas
        if "ErrorResponse" not in openapi_spec["components"]["schemas"]:
            openapi_spec["components"]["schemas"]["ErrorResponse"] = {
                "type": "object",
                "properties": {
                    "message": {"type": "string"}
                }
            }
    
    def _extract_model_name(self, model_ref: str) -> Optional[str]:
        """
        Extract clean model name from a model reference.
        
        Args:
            model_ref: Model reference string (could be module.Class or just Class)
            
        Returns:
            Clean model name
        """
        if not model_ref:
            return None
        
        # Remove module path if present (e.g., "module.dto.TokenRequest" -> "TokenRequest")
        if '.' in model_ref:
            model_name = model_ref.split('.')[-1]
        else:
            model_name = model_ref
            
        # Clean up any extra characters
        model_name = model_name.strip('[]()<>')
        
        return model_name if model_name else None

    def _is_valid_schema(self, schema_data: dict, model_name: str) -> bool:
        """
        Validate that a schema is valid and usable for OpenAPI.
        
        Args:
            schema_data: The schema dictionary to validate
            model_name: The name of the model (for logging)
            
        Returns:
            True if the schema is valid and should be included
        """
        if not schema_data or not isinstance(schema_data, dict):
            return False
            
        # Skip schemas that couldn't be properly generated
        if (schema_data.get('type') == 'object' and 
            not schema_data.get('properties') and
            not schema_data.get('additionalProperties') and
            not schema_data.get('allOf') and
            not schema_data.get('anyOf') and
            not schema_data.get('oneOf')):
            return False
            
        return True

    def _clean_invalid_schema_references(self, endpoints, valid_schema_names: set):
        """
        Remove references to invalid schemas from endpoints.
        
        Args:
            endpoints: List of endpoint objects to clean
            valid_schema_names: Set of schema names that are valid and available
        """
        for endpoint in endpoints:
            # Clean request model references
            if endpoint.request_model:
                model_name = self._extract_model_name(endpoint.request_model)
                if model_name and model_name not in valid_schema_names:
                    rprint(f"[yellow]Removing invalid request model reference: {model_name} from {endpoint.path}[/yellow]")
                    endpoint.request_model = None
            
            # Clean response model references
            if endpoint.response_model:
                model_name = self._extract_model_name(endpoint.response_model)
                if model_name and model_name not in valid_schema_names:
                    rprint(f"[yellow]Removing invalid response model reference: {model_name} from {endpoint.path}[/yellow]")
                    endpoint.response_model = None
            
            # Clean response schema references
            for status_code, response in endpoint.responses.items():
                if 'model' in response:
                    model_name = self._extract_model_name(response['model'])
                    if model_name and model_name not in valid_schema_names:
                        rprint(f"[yellow]Removing invalid response model reference: {model_name} from {endpoint.path} {status_code}[/yellow]")
                        del response['model']


def generate_schemas(args):
    rprint(f"[bold]--- Running Pydantic schema generation from: {args.pydantic_source} ---[/bold]")
    project_root = Path(args.pydantic_source)
    output_dir = Path(args.output_dir)
    
    pydantic_handler.generate_dto_schemas(project_root, output_dir, project_root)
    rprint(f"[bold green]--- Pydantic schema generation finished successfully. Schemas are in {args.output_dir} ---[/bold green]")

def generate_serverless(args):
    rprint(f"[bold]--- Generating serverless.yml from schemas in {args.schema_dir} ---[/bold]")
    schema_dir = Path(args.schema_dir)
    project_root = Path(args.project_dir) if args.project_dir else schema_dir.parent

    schemas = []
    for file_path in schema_dir.glob("*.json"):
        with open(file_path, 'r') as f:
            schema = json.load(f)
            schemas.append({
                "name": file_path.stem,
                "schema": schema
            })

    project_meta = pydantic_handler.load_project_meta(project_root)
    serverless_config = pydantic_handler.generate_serverless_config(schemas, project_meta, project_root)
    
    output_path = project_root / "serverless.yml"
    with open(output_path, 'w') as f:
        yaml.dump(serverless_config, f)
    
    rprint(f"[bold green]--- serverless.yml generated at {output_path} ---[/bold green]")

def generate_spec(args):
    try:
        with open(args.serverless_yml_path, 'r') as f:
            serverless_config = yaml.safe_load(f)
        effective_sls_path = args.serverless_yml_path
    except FileNotFoundError:
        rprint(f"[red]Error: The file {args.serverless_yml_path} was not found.[/red]")
        return
    except yaml.YAMLError as e:
        rprint(f"[red]Error parsing YAML file: {e}[/red]")
        return

    generator = DefinitionGenerator(serverless_config, str(effective_sls_path), args.openApiVersion)
    open_api_spec = generator.generate()

    try:
        with open(args.output_file_path, 'w') as f:
            json.dump(open_api_spec, f, indent=2)
        rprint(f"[bold green]OpenAPI specification successfully written to {args.output_file_path}[/bold green]")
    except IOError as e:
        rprint(f"[red]Error writing to output file: {e}[/red]")

    if args.validate:
        rprint("[bold]Validating generated spec...[/bold]")
        validation_errors = _validate_openapi_spec(open_api_spec)
        if validation_errors:
            rprint(f"[bold red]Validation failed with {len(validation_errors)} errors:[/bold red]")
            for i, error in enumerate(validation_errors[:5], 1):
                rprint(f"  {i}. {error}")
            if len(validation_errors) > 5:
                rprint(f"  ... and {len(validation_errors) - 5} more errors")
        else:
            rprint("[bold green]Validation successful.[/bold green]")

def generate_spec_python(args):
    """Generate OpenAPI spec directly from Python source code."""
    rprint(f"[bold]--- Generating OpenAPI spec from Python source: {args.python_source} ---[/bold]")
    
    source_dir = Path(args.python_source)
    if not source_dir.exists():
        rprint(f"[red]Error: Source directory {source_dir} does not exist.[/red]")
        return
    
    generator = PythonBasedGenerator(args.openApiVersion)
    
    openapi_spec = generator.generate_from_python(
        source_dir=source_dir,
        endpoint_pattern=args.endpoint_pattern,
        docs_pattern=args.docs_pattern,
        title=args.title,
        version=args.version,
        description=args.description
    )
    
    try:
        with open(args.output_file_path, 'w') as f:
            json.dump(openapi_spec, f, indent=2)
        rprint(f"[bold green]OpenAPI specification successfully written to {args.output_file_path}[/bold green]")
    except IOError as e:
        rprint(f"[red]Error writing to output file: {e}[/red]")
        return
    
    if args.validate:
        rprint("[bold]Validating generated spec...[/bold]")
        validation_errors = _validate_openapi_spec(openapi_spec)
        if validation_errors:
            rprint(f"[bold red]Validation failed with {len(validation_errors)} errors:[/bold red]")
            for i, error in enumerate(validation_errors[:5], 1):  # Show first 5 errors
                rprint(f"  {i}. {error}")
            if len(validation_errors) > 5:
                rprint(f"  ... and {len(validation_errors) - 5} more errors")
        else:
            rprint("[bold green]Validation successful.[/bold green]")

def _validate_openapi_spec(spec: dict) -> List[str]:
    """Validate OpenAPI specification and return list of errors."""
    errors = []
    
    try:
        # Try using openapi-spec-validator if available
        from openapi_spec_validator import validate
        try:
            validate(spec)
            return []  # No errors
        except Exception as e:
            errors.append(f"OpenAPI validation error: {str(e)}")
    except ImportError:
        # Fall back to basic validation
        pass
    
    # Basic validation checks
    if not isinstance(spec, dict):
        errors.append("Specification must be a dictionary")
        return errors
    
    # Check required top-level fields
    required_fields = ['openapi', 'info', 'paths']
    for field in required_fields:
        if field not in spec:
            errors.append(f"Missing required field: {field}")
    
    # Validate info object
    if 'info' in spec:
        info = spec['info']
        if not isinstance(info, dict):
            errors.append("'info' must be an object")
        else:
            required_info_fields = ['title', 'version']
            for field in required_info_fields:
                if field not in info:
                    errors.append(f"Missing required info field: {field}")
    
    # Validate paths
    if 'paths' in spec:
        paths = spec['paths']
        if not isinstance(paths, dict):
            errors.append("'paths' must be an object")
        else:
            for path, path_item in paths.items():
                if not isinstance(path_item, dict):
                    errors.append(f"Path item for '{path}' must be an object")
                    continue
                
                # Check HTTP methods
                valid_methods = ['get', 'post', 'put', 'delete', 'patch', 'options', 'head', 'trace']
                for method, operation in path_item.items():
                    if method.lower() not in valid_methods:
                        continue  # Skip non-method fields
                    
                    if not isinstance(operation, dict):
                        errors.append(f"Operation for {method.upper()} {path} must be an object")
                        continue
                    
                    # Check required operation fields
                    if 'responses' not in operation:
                        errors.append(f"Missing 'responses' in {method.upper()} {path}")
    
    # Validate components/schemas if present
    if 'components' in spec and 'schemas' in spec['components']:
        schemas = spec['components']['schemas']
        if not isinstance(schemas, dict):
            errors.append("'components.schemas' must be an object")
        else:
            for schema_name, schema in schemas.items():
                if not isinstance(schema, dict):
                    errors.append(f"Schema '{schema_name}' must be an object")
    
    return errors

def main():
    parser = argparse.ArgumentParser(description='Generate OpenAPI v3 documentation from a serverless.yml file.')
    subparsers = parser.add_subparsers(dest='command', required=True)

    # Sub-parser for generating schemas
    parser_schemas = subparsers.add_parser('generate-schemas', help='Generate JSON schemas from Pydantic models.')
    parser_schemas.add_argument('--pydantic-source', type=str, required=True, help='Path to the Pydantic models source directory')
    parser_schemas.add_argument('--output-dir', type=str, required=True, help='Directory to save the generated JSON schemas')
    parser_schemas.set_defaults(func=generate_schemas)

    # Sub-parser for generating serverless.yml
    parser_serverless = subparsers.add_parser('generate-serverless', help='Generate serverless.yml from JSON schemas.')
    parser_serverless.add_argument('--schema-dir', type=str, required=True, help='Directory containing the JSON schemas')
    parser_serverless.add_argument('--project-dir', type=str, help='Path to the project root directory (for pyproject.toml)')
    parser_serverless.set_defaults(func=generate_serverless)

    # Sub-parser for generating the OpenAPI spec
    parser_spec = subparsers.add_parser('generate-spec', help='Generate the full OpenAPI spec from a serverless.yml file.')
    parser_spec.add_argument('output_file_path', type=str, help='Path to the output OpenAPI JSON file')
    parser_spec.add_argument('--serverless-yml-path', type=str, required=True, help='Path to the serverless.yml file.')
    parser_spec.add_argument('--openApiVersion', type=str, default='3.0.3', help='OpenAPI version to use')
    parser_spec.add_argument('--validate', action='store_true', help='Validate the generated OpenAPI spec')
    parser_spec.set_defaults(func=generate_spec)

    # Sub-parser for generating OpenAPI spec from Python source
    parser_python = subparsers.add_parser('generate-spec-python', help='Generate OpenAPI spec directly from Python source code.')
    parser_python.add_argument('output_file_path', type=str, help='Path to the output OpenAPI JSON file')
    parser_python.add_argument('--python-source', type=str, required=True, help='Path to the Python source directory')
    parser_python.add_argument('--endpoint-pattern', type=str, default='**/handler.py', help='Glob pattern for endpoint files')
    parser_python.add_argument('--docs-pattern', type=str, default='**/docs.py', help='Glob pattern for docs files')
    parser_python.add_argument('--title', type=str, default=None, help='API title (defaults to pyproject.toml name)')
    parser_python.add_argument('--version', type=str, default=None, help='API version (defaults to pyproject.toml version)')
    parser_python.add_argument('--description', type=str, default=None, help='API description (defaults to pyproject.toml description)')
    parser_python.add_argument('--openApiVersion', type=str, default='3.0.3', help='OpenAPI version to use')
    parser_python.add_argument('--validate', action='store_true', help='Validate the generated OpenAPI spec')
    parser_python.set_defaults(func=generate_spec_python)

    # Sub-parser for generating HTML documentation
    parser_html = subparsers.add_parser('generate-html', help='Generate HTML documentation from an OpenAPI spec file.')
    parser_html.add_argument('spec_file_path', type=str, help='Path to the OpenAPI JSON file')
    parser_html.add_argument('output_file_path', type=str, help='Path to the output HTML file')
    parser_html.set_defaults(func=generate_html)

    args = parser.parse_args()
    args.func(args)

def generate_html(args):
    """Generate HTML documentation from an OpenAPI spec file."""
    rprint(f"[bold]--- Generating HTML documentation from: {args.spec_file_path} ---[/bold]")
    
    spec_file = Path(args.spec_file_path)
    if not spec_file.exists():
        rprint(f"[red]Error: Spec file {spec_file} does not exist.[/red]")
        return
        
    output_file = Path(args.output_file_path)
    
    try:
        import subprocess
        subprocess.run(
            ["redoc-cli", "bundle", str(spec_file), "-o", str(output_file)],
            check=True
        )
        rprint(f"[bold green]HTML documentation successfully written to {output_file}[/bold green]")
    except FileNotFoundError:
        rprint("[red]Error: redoc-cli not found. Please install it with 'pip install redoc-cli'[/red]")
    except subprocess.CalledProcessError as e:
        rprint(f"[red]Error generating HTML documentation: {e}[/red]")

if __name__ == '__main__':
    main()
