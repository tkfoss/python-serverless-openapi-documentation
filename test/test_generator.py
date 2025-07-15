import json
import yaml
import os
import pytest

from serverless_openapi_generator.openapi_generator import DefinitionGenerator


def test_serverless_1_scenario():
    # Paths to the test files
    serverless_yml_path = os.path.join(os.path.dirname(__file__), 'serverless-tests', 'serverless 1', 'serverless.yml')
    expected_openapi_path = os.path.join(os.path.dirname(__file__), 'json', 'expected_from_serverless_1.json')

    # Load the serverless.yml configuration
    with open(serverless_yml_path, 'r') as f:
        serverless_config = yaml.safe_load(f)

    # Generate the OpenAPI spec using the Python script
    generator = DefinitionGenerator(serverless_config, serverless_yml_path)
    generated_spec = generator.generate()

    # Load the expected OpenAPI spec
    with open(expected_openapi_path, 'r') as f:
        expected_spec = json.load(f)

        # Compare the generated spec with the expected spec
        assert generated_spec == expected_spec


def test_owasp_headers_scenario():
    # Paths to the test files
    serverless_yml_path = os.path.join(os.path.dirname(__file__), 'serverless-tests', 'owasp', 'serverless.yml')

    # Load the serverless.yml configuration
    with open(serverless_yml_path, 'r') as f:
        serverless_config = yaml.safe_load(f)

    # Generate the OpenAPI spec using the Python script
    generator = DefinitionGenerator(serverless_config, serverless_yml_path)
    generated_spec = generator.generate()

    # Check for OWASP headers in the 200 response
    response_200 = generated_spec.get('paths', {}).get('/test', {}).get('get', {}).get('responses', {}).get('200', {})
    assert 'headers' in response_200
    
    headers = response_200['headers']
    assert 'X-Frame-Options' in headers
    assert 'Strict-Transport-Security' in headers
    assert 'X-Content-Type-Options' in headers
    
    # Check that the schema ref was created
    assert '$ref' in headers['X-Frame-Options']['schema']
    assert 'X-Frame-Options' in generated_spec.get('components', {}).get('schemas', {})


def test_extensions_scenario():
    # Paths to the test files
    serverless_yml_path = os.path.join(os.path.dirname(__file__), 'serverless-tests', 'extensions', 'serverless.yml')

    # Load the serverless.yml configuration
    with open(serverless_yml_path, 'r') as f:
        serverless_config = yaml.safe_load(f)

    # Generate the OpenAPI spec using the Python script
    generator = DefinitionGenerator(serverless_config, serverless_yml_path)
    generated_spec = generator.generate()

    # Check for extension fields
    info = generated_spec.get('info', {})
    assert 'x-logo' in info
    assert info['x-logo']['url'] == 'https://example.com/logo.png'
    
    contact = info.get('contact', {})
    assert 'x-slack-channel' in contact
    assert contact['x-slack-channel'] == '#api-support'

    license_obj = info.get('license', {})
    assert 'x-license-id' in license_obj
    assert license_obj['x-license-id'] == 'MIT'


def test_security_schemes_scenario():
    # Paths to the test files
    serverless_yml_path = os.path.join(os.path.dirname(__file__), 'serverless-tests', 'security', 'serverless.yml')

    # Load the serverless.yml configuration
    with open(serverless_yml_path, 'r') as f:
        serverless_config = yaml.safe_load(f)

    # Generate the OpenAPI spec using the Python script
    generator = DefinitionGenerator(serverless_config, serverless_yml_path)
    generated_spec = generator.generate()

    # Check for security schemes
    schemes = generated_spec.get('components', {}).get('securitySchemes', {})
    assert 'my_api_key' in schemes
    assert schemes['my_api_key']['type'] == 'apiKey'
    assert 'my_oauth' in schemes
    assert schemes['my_oauth']['type'] == 'oauth2'

    # Test validation
    invalid_config = json.loads(json.dumps(serverless_config))
    del invalid_config['custom']['documentation']['securitySchemes']['my_api_key']['name']
    
    with pytest.raises(ValueError, match='Security Scheme for "apiKey" requires the name'):
        DefinitionGenerator(invalid_config, serverless_yml_path).generate()


def test_inferred_logic_scenario():
    # Paths to the test files
    serverless_yml_path = os.path.join(os.path.dirname(__file__), 'serverless-tests', 'inferred', 'serverless.yml')

    # Load the serverless.yml configuration
    with open(serverless_yml_path, 'r') as f:
        serverless_config = yaml.safe_load(f)

    # Generate the OpenAPI spec using the Python script
    generator = DefinitionGenerator(serverless_config, serverless_yml_path)
    generated_spec = generator.generate()

    # Check private endpoint
    private_op = generated_spec.get('paths', {}).get('/private', {}).get('get', {})
    assert 'security' in private_op
    assert private_op['security'] == [{'x-api-key': []}]
    assert 'x-api-key' in generated_spec.get('components', {}).get('securitySchemes', {})

    # Check inferred request body
    inferred_op = generated_spec.get('paths', {}).get('/inferred', {}).get('post', {})
    assert 'requestBody' in inferred_op
    assert 'application/json' in inferred_op['requestBody']['content']
