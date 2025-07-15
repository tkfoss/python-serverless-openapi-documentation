import unittest
import json
import yaml
import sys
import os

# Add src directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from openapi_generator import DefinitionGenerator

class TestOpenAPIGenerator(unittest.TestCase):

    def test_serverless_1_scenario(self):
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
        self.maxDiff = None
        self.assertDictEqual(generated_spec, expected_spec)

    def test_owasp_headers_scenario(self):
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
        self.assertIn('headers', response_200)
        
        headers = response_200['headers']
        self.assertIn('X-Frame-Options', headers)
        self.assertIn('Strict-Transport-Security', headers)
        self.assertIn('X-Content-Type-Options', headers)
        
        # Check that the schema ref was created
        self.assertIn('$ref', headers['X-Frame-Options']['schema'])
        self.assertIn('X-Frame-Options', generated_spec.get('components', {}).get('schemas', {}))

    def test_extensions_scenario(self):
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
        self.assertIn('x-logo', info)
        self.assertEqual(info['x-logo']['url'], 'https://example.com/logo.png')
        
        contact = info.get('contact', {})
        self.assertIn('x-slack-channel', contact)
        self.assertEqual(contact['x-slack-channel'], '#api-support')

        license_obj = info.get('license', {})
        self.assertIn('x-license-id', license_obj)
        self.assertEqual(license_obj['x-license-id'], 'MIT')

    def test_security_schemes_scenario(self):
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
        self.assertIn('my_api_key', schemes)
        self.assertEqual(schemes['my_api_key']['type'], 'apiKey')
        self.assertIn('my_oauth', schemes)
        self.assertEqual(schemes['my_oauth']['type'], 'oauth2')

        # Test validation
        invalid_config = json.loads(json.dumps(serverless_config))
        del invalid_config['custom']['documentation']['securitySchemes']['my_api_key']['name']
        
        with self.assertRaisesRegex(ValueError, 'Security Scheme for "apiKey" requires the name'):
            DefinitionGenerator(invalid_config, serverless_yml_path).generate()

    def test_inferred_logic_scenario(self):
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
        self.assertIn('security', private_op)
        self.assertEqual(private_op['security'], [{'x-api-key': []}])
        self.assertIn('x-api-key', generated_spec.get('components', {}).get('securitySchemes', {}))

        # Check inferred request body
        inferred_op = generated_spec.get('paths', {}).get('/inferred', {}).get('post', {})
        self.assertIn('requestBody', inferred_op)
        self.assertIn('application/json', inferred_op['requestBody']['content'])


if __name__ == '__main__':
    unittest.main()
