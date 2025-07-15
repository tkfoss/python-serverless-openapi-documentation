import unittest
import json
import requests_mock
from src.schema_handler import SchemaHandler

# Mock data similar to the JS test helpers
MODELS_DOCUMENT = {
  "models": [{
      "name": "ErrorResponse", "description": "The Error Response",
      "content": {"application/json": {"schema": {"type": "object", "properties": {"error": {"type": "string"}}}}}
  }]
}

MODELS_ALT_DOCUMENT = {
    "models": [{
        "name": "ErrorResponse", "description": "The Error Response", "contentType": "application/json",
        "schema": {"type": "object", "properties": {"error": {"type": "string"}}}
    }]
}

MODELS_LIST_DOCUMENT = {
    "modelsList": [{
        "name": "ErrorResponse", "description": "The Error Response",
        "content": {"application/json": {"schema": {"type": "object", "properties": {"error": {"type": "string"}}}}}
    }]
}

MODELS_LIST_ALT_DOCUMENT = {
    "modelsList": [{
        "name": "ErrorResponse", "description": "The Error Response", "contentType": "application/json",
        "schema": {"type": "object", "properties": {"error": {"type": "string"}}}
    }]
}

class TestSchemaHandler(unittest.TestCase):

    def setUp(self):
        """Set up a mock serverless config for each test."""
        self.open_api_spec = {"components": {"schemas": {}}}
        self.mock_serverless = {
            "service": {
                "custom": {
                    "documentation": {}
                }
            }
        }

    def test_constructor_standardizes_models(self):
        self.mock_serverless["service"]["custom"]["documentation"] = MODELS_DOCUMENT
        handler = SchemaHandler(self.mock_serverless, self.open_api_spec)
        self.assertEqual(len(handler.models), 1)
        model = handler.models[0]
        self.assertEqual(model['name'], 'ErrorResponse')
        self.assertEqual(model['contentType'], 'application/json')
        self.assertIn('schema', model)

    def test_constructor_standardizes_models_alt(self):
        self.mock_serverless["service"]["custom"]["documentation"] = MODELS_ALT_DOCUMENT
        handler = SchemaHandler(self.mock_serverless, self.open_api_spec)
        self.assertEqual(len(handler.models), 1)
        model = handler.models[0]
        self.assertEqual(model['name'], 'ErrorResponse')
        self.assertEqual(model['contentType'], 'application/json')

    def test_constructor_standardizes_models_list(self):
        self.mock_serverless["service"]["custom"]["documentation"] = MODELS_LIST_DOCUMENT
        handler = SchemaHandler(self.mock_serverless, self.open_api_spec)
        self.assertEqual(len(handler.models), 1)
        model = handler.models[0]
        self.assertEqual(model['name'], 'ErrorResponse')

    def test_constructor_standardizes_models_list_alt(self):
        self.mock_serverless["service"]["custom"]["documentation"] = MODELS_LIST_ALT_DOCUMENT
        handler = SchemaHandler(self.mock_serverless, self.open_api_spec)
        self.assertEqual(len(handler.models), 1)
        model = handler.models[0]
        self.assertEqual(model['name'], 'ErrorResponse')

    def test_constructor_standardizes_mixed_models(self):
        # Deep copy to avoid modifying the original dict
        mixed_docs = json.loads(json.dumps(MODELS_DOCUMENT))
        mixed_docs['models'].append({
            "name": "SuccessResponse", "description": "A success response", "contentType": "application/json",
            "schema": {"type": "string"}
        })
        self.mock_serverless["service"]["custom"]["documentation"] = mixed_docs
        handler = SchemaHandler(self.mock_serverless, self.open_api_spec)
        self.assertEqual(len(handler.models), 2)
        self.assertEqual(handler.models[0]['name'], 'ErrorResponse')
        self.assertEqual(handler.models[1]['name'], 'SuccessResponse')

    def test_add_models_with_internal_ref(self):
        # Test bundling of internal #/definitions/
        schema = {
            "name": "SuccessResponse", "contentType": "application/json",
            "schema": {
                "type": "object",
                "properties": {"name": {"$ref": "#/definitions/nameObject"}},
                "definitions": {
                    "nameObject": {"type": "object", "properties": {"firstName": {"type": "string"}}}
                }
            }
        }
        self.mock_serverless["service"]["custom"]["documentation"]["models"] = [schema]
        handler = SchemaHandler(self.mock_serverless, self.open_api_spec)
        handler.add_models_to_openapi()
        
        # The referencing library should resolve and bundle the definition
        generated_schema = self.open_api_spec["components"]["schemas"]["SuccessResponse"]
        self.assertNotIn("definitions", generated_schema)
        self.assertIn("firstName", generated_schema["properties"]["name"]["properties"])

    @requests_mock.Mocker()
    def test_add_model_from_url(self, m):
        # Mock the HTTP request for the remote schema
        remote_schema = {"type": "object", "properties": {"memberId": {"type": "string"}}}
        m.get("https://example.com/schema.json", json=remote_schema)

        schema_def = {"name": "RemoteSuccess", "schema": "https://example.com/schema.json"}
        self.mock_serverless["service"]["custom"]["documentation"]["models"] = [schema_def]
        handler = SchemaHandler(self.mock_serverless, self.open_api_spec)
        handler.add_models_to_openapi()

        generated_schema = self.open_api_spec["components"]["schemas"]["RemoteSuccess"]
        self.assertEqual(generated_schema, remote_schema)

    def test_create_schema_name_collision(self):
        handler = SchemaHandler(self.mock_serverless, self.open_api_spec)
        
        schema1 = {"type": "string"}
        schema2 = {"type": "number"}

        ref1 = handler.create_schema("MySchema", schema1)
        self.assertEqual(ref1, "#/components/schemas/MySchema")
        
        # Create again with the same schema, should return the same ref
        ref2 = handler.create_schema("MySchema", schema1)
        self.assertEqual(ref2, "#/components/schemas/MySchema")
        
        # Create with a different schema, should create a new entry
        ref3 = handler.create_schema("MySchema", schema2)
        self.assertNotEqual(ref3, "#/components/schemas/MySchema")
        self.assertIn("MySchema-", ref3)


if __name__ == '__main__':
    unittest.main()
