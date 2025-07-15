import json
import pytest
import requests_mock
from serverless_openapi_generator.schema_handler import SchemaHandler

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

@pytest.fixture
def base_config():
    """Provides a base serverless config and OpenAPI spec."""
    return {
        "open_api_spec": {"components": {"schemas": {}}},
        "serverless_config": {
            "service": "test-service",
            "custom": {
                "documentation": {}
            }
        }
    }


def test_constructor_standardizes_models(base_config):
    base_config["serverless_config"]["custom"]["documentation"] = MODELS_DOCUMENT
    handler = SchemaHandler(base_config["serverless_config"], base_config["open_api_spec"])
    assert len(handler.models) == 1
    model = handler.models[0]
    assert model['name'] == 'ErrorResponse'
    assert model['contentType'] == 'application/json'
    assert 'schema' in model


def test_constructor_standardizes_models_alt(base_config):
    base_config["serverless_config"]["custom"]["documentation"] = MODELS_ALT_DOCUMENT
    handler = SchemaHandler(base_config["serverless_config"], base_config["open_api_spec"])
    assert len(handler.models) == 1
    model = handler.models[0]
    assert model['name'] == 'ErrorResponse'
    assert model['contentType'] == 'application/json'


def test_constructor_standardizes_models_list(base_config):
    base_config["serverless_config"]["custom"]["documentation"] = MODELS_LIST_DOCUMENT
    handler = SchemaHandler(base_config["serverless_config"], base_config["open_api_spec"])
    assert len(handler.models) == 1
    model = handler.models[0]
    assert model['name'] == 'ErrorResponse'


def test_constructor_standardizes_models_list_alt(base_config):
    base_config["serverless_config"]["custom"]["documentation"] = MODELS_LIST_ALT_DOCUMENT
    handler = SchemaHandler(base_config["serverless_config"], base_config["open_api_spec"])
    assert len(handler.models) == 1
    model = handler.models[0]
    assert model['name'] == 'ErrorResponse'


def test_constructor_standardizes_mixed_models(base_config):
    # Deep copy to avoid modifying the original dict
    mixed_docs = json.loads(json.dumps(MODELS_DOCUMENT))
    mixed_docs['models'].append({
        "name": "SuccessResponse", "description": "A success response", "contentType": "application/json",
        "schema": {"type": "string"}
    })
    base_config["serverless_config"]["custom"]["documentation"] = mixed_docs
    handler = SchemaHandler(base_config["serverless_config"], base_config["open_api_spec"])
    assert len(handler.models) == 2
    assert handler.models[0]['name'] == 'ErrorResponse'
    assert handler.models[1]['name'] == 'SuccessResponse'


def test_add_models_with_internal_ref(base_config):
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
    base_config["serverless_config"]["custom"]["documentation"]["models"] = [schema]
    handler = SchemaHandler(base_config["serverless_config"], base_config["open_api_spec"])
    handler.add_models_to_openapi()
    
    # The referencing library should resolve and bundle the definition
    generated_schema = base_config["open_api_spec"]["components"]["schemas"]["SuccessResponse"]
    assert "definitions" not in generated_schema
    assert "firstName" in generated_schema["properties"]["name"]["properties"]


def test_add_model_from_url(requests_mock, base_config):
    # Mock the HTTP request for the remote schema
    remote_schema = {"type": "object", "properties": {"memberId": {"type": "string"}}}
    requests_mock.get("https://example.com/schema.json", json=remote_schema)

    schema_def = {"name": "RemoteSuccess", "schema": "https://example.com/schema.json"}
    base_config["serverless_config"]["custom"]["documentation"]["models"] = [schema_def]
    handler = SchemaHandler(base_config["serverless_config"], base_config["open_api_spec"])
    handler.add_models_to_openapi()

    generated_schema = base_config["open_api_spec"]["components"]["schemas"]["RemoteSuccess"]
    assert generated_schema == remote_schema


def test_create_schema_name_collision(base_config):
    handler = SchemaHandler(base_config["serverless_config"], base_config["open_api_spec"])
    
    schema1 = {"type": "string"}
    schema2 = {"type": "number"}

    ref1 = handler.create_schema("MySchema", schema1)
    assert ref1 == "#/components/schemas/MySchema"
    
    # Create again with the same schema, should return the same ref
    ref2 = handler.create_schema("MySchema", schema1)
    assert ref2 == "#/components/schemas/MySchema"
    
    # Create with a different schema, should create a new entry
    ref3 = handler.create_schema("MySchema", schema2)
    assert ref3 != "#/components/schemas/MySchema"
    assert "MySchema-" in ref3
