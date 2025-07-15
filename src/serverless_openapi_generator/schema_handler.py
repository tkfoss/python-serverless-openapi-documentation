import json
import uuid
import os
import re
import yaml
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT4
import requests

class SchemaHandler:
    def __init__(self, serverless_config, open_api_spec, serverless_dir='.'):
        self.serverless_config = serverless_config
        self.open_api = open_api_spec
        self.serverless_dir = serverless_dir
        self.models = self._standardize_models()

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

    def _standardize_models(self):
        documentation = self.serverless_config.get('custom', {}).get('documentation', {})

        standardized_models = []
        model_sources = []
        if 'models' in documentation:
            models_config = self._resolve_file_references(documentation['models'])
            if isinstance(models_config, list):
                model_sources.extend(models_config)
            elif isinstance(models_config, dict):
                for name, definition in models_config.items():
                    model_sources.append({'name': name, **definition})
        
        if 'modelsList' in documentation:
            model_sources.extend(self._resolve_file_references(documentation['modelsList']))

        for model in model_sources:
            if not isinstance(model, dict) or 'name' not in model:
                continue
            
            model = self._resolve_file_references(model)

            std_model = {
                'name': model.get('name'),
                'description': model.get('description', ''),
            }
            if 'contentType' in model and 'schema' in model:
                std_model['contentType'] = model['contentType']
                std_model['schema'] = model['schema']
            elif 'content' in model and isinstance(model['content'], dict):
                content_type, content_details = next(iter(model['content'].items()))
                std_model['contentType'] = content_type
                std_model['schema'] = content_details.get('schema', {})
            elif 'schema' in model:
                std_model['contentType'] = model.get('contentType', 'application/json')
                std_model['schema'] = model['schema']
            standardized_models.append(std_model)
        return standardized_models

    def add_models_to_openapi(self):
        for model in self.models:
            self.create_schema(model['name'], model['schema'])

    def create_schema(self, name, schema_definition):
        if not schema_definition:
            raise ValueError("Schema definition cannot be empty.")
        final_schema = self._resolve_schema_references(schema_definition)
        if name in self.open_api['components']['schemas'] and self.open_api['components']['schemas'][name] != final_schema:
            name = f"{name}-{uuid.uuid4()}"
        self.open_api['components']['schemas'][name] = final_schema
        return f"#/components/schemas/{name}"

    def _resolve_schema_references(self, schema):
        schema = self._resolve_file_references(schema)
        if not isinstance(schema, dict):
            if isinstance(schema, str) and schema.startswith('http'):
                try:
                    response = requests.get(schema)
                    response.raise_for_status()
                    schema = response.json()
                except (requests.exceptions.RequestException, json.JSONDecodeError):
                    return {"description": "Failed to resolve schema from URL"}
            else:
                return schema
        
        registry = Registry()
        if "definitions" in schema:
            for name, sub_schema in schema["definitions"].items():
                resource = Resource.from_contents(sub_schema, default_specification=DRAFT4)
                registry = registry.with_resource(f"#/definitions/{name}", resource)
        
        main_resource = Resource.from_contents(schema, default_specification=DRAFT4)
        registry = registry.with_resource("root", main_resource)
        resolver = registry.resolver("root")
        dereferenced_schema = self._recursive_dereference(schema, resolver)
        
        if isinstance(dereferenced_schema, dict):
            dereferenced_schema.pop("definitions", None)
        return dereferenced_schema

    def _recursive_dereference(self, node, resolver):
        if isinstance(node, dict):
            if "$ref" in node:
                resolved = resolver.lookup(node["$ref"])
                return self._recursive_dereference(resolved.contents, resolver)
            return {k: self._recursive_dereference(v, resolver) for k, v in node.items()}
        elif isinstance(node, list):
            return [self._recursive_dereference(item, resolver) for item in node]
        return node
