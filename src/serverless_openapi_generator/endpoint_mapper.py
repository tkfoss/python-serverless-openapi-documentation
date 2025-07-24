from pathlib import Path
from typing import Dict, List, Optional

from .docs_extractor import CompleteEndpointInfo, DocsExtractor
from .python_discovery import PythonEndpointDiscovery


class EndpointMapper:
    """Maps Python functions to HTTP endpoints and merges with documentation."""
    
    def __init__(self):
        self.discovery = PythonEndpointDiscovery()
        self.docs_extractor = DocsExtractor()
        
    def discover_all_endpoints(self, 
                             source_dir: Path,
                             endpoint_pattern: str = "**/handler.py",
                             docs_pattern: str = "**/docs.py") -> List[CompleteEndpointInfo]:
        """
        Discover all endpoints in a source directory and merge with documentation.
        
        Args:
            source_dir: Root directory to search
            endpoint_pattern: Glob pattern for endpoint files
            docs_pattern: Glob pattern for docs files
            
        Returns:
            List of complete endpoint information
        """
        # Discover handler functions
        handler_functions = self.discovery.discover_handlers(source_dir, endpoint_pattern)
        
        # Discover docs files
        docs_modules = self.docs_extractor.discover_docs_files(source_dir, docs_pattern)
        
        # Create a mapping of endpoint names to docs
        docs_map = {}
        for docs_module in docs_modules:
            docs_meta = self.docs_extractor.extract_docs_metadata(docs_module, source_dir)
            if docs_meta:
                docs_map[docs_module.endpoint_name] = docs_meta
        
        # Merge function info with docs
        complete_endpoints = []
        for func_info in handler_functions:
            route_info = self.discovery.extract_route_info(func_info)
            
            # Find matching docs
            docs_meta = None
            if route_info.endpoint_name:
                docs_meta = docs_map.get(route_info.endpoint_name)
            
            # Merge all information
            complete_info = self.docs_extractor.merge_with_function_metadata(
                func_info, route_info, docs_meta
            )
            
            complete_endpoints.append(complete_info)
        
        return complete_endpoints
    
    def group_by_path(self, endpoints: List[CompleteEndpointInfo]) -> Dict[str, Dict[str, CompleteEndpointInfo]]:
        """
        Group endpoints by path and method for OpenAPI spec generation.
        
        Args:
            endpoints: List of complete endpoint information
            
        Returns:
            Dictionary mapping paths to methods to endpoint info
        """
        grouped = {}
        
        for endpoint in endpoints:
            path = endpoint.path
            method = endpoint.http_method.lower()
            
            if path not in grouped:
                grouped[path] = {}
                
            grouped[path][method] = endpoint
        
        return grouped
    
    def infer_parameters_from_path(self, path: str) -> List[Dict[str, str]]:
        """
        Infer path parameters from OpenAPI path format.
        
        Args:
            path: OpenAPI path with parameters like /users/{user_id}
            
        Returns:
            List of parameter definitions
        """
        import re
        
        parameters = []
        
        # Find path parameters in {param_name} format
        param_matches = re.findall(r'\{([^}]+)\}', path)
        
        for param_name in param_matches:
            parameters.append({
                'name': param_name,
                'in': 'path',
                'required': True,
                'schema': {'type': 'string'},
                'description': f'Path parameter: {param_name}'
            })
        
        return parameters
    
    def infer_parameters_from_function(self, endpoint: CompleteEndpointInfo) -> List[Dict[str, any]]:
        """
        Infer query and header parameters from function signature and OAuth2 patterns.
        
        Args:
            endpoint: Complete endpoint information
            
        Returns:
            List of parameter definitions
        """
        parameters = []
        
        # Add path parameters
        if endpoint.path:
            parameters.extend(self.infer_parameters_from_path(endpoint.path))
        
        # OAuth2 specific parameter patterns
        oauth2_parameters = self._get_oauth2_parameters(endpoint)
        parameters.extend(oauth2_parameters)
        
        # Extract parameters from function signature
        function_parameters = self._extract_function_parameters(endpoint)
        parameters.extend(function_parameters)
        
        return parameters
    
    def _get_oauth2_parameters(self, endpoint: CompleteEndpointInfo) -> List[Dict[str, any]]:
        """Get OAuth2 specific parameters based on endpoint patterns."""
        parameters = []
        endpoint_name = endpoint.path.strip('/').lower() if endpoint.path else ''
        
        # OAuth2 Authorization endpoint parameters (RFC 6749)
        if 'authorize' in endpoint_name and endpoint.http_method.upper() == 'GET':
            oauth2_auth_params = [
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
            parameters.extend(oauth2_auth_params)
        
        # OAuth2 Token endpoint parameters (RFC 6749)
        if 'token' in endpoint_name and endpoint.http_method.upper() == 'POST':
            oauth2_token_params = [
                {
                    'name': 'grant_type',
                    'in': 'query',
                    'required': True,
                    'schema': {
                        'type': 'string',
                        'enum': ['authorization_code', 'refresh_token', 'client_credentials']
                    },
                    'description': 'The grant type for OAuth2 token request'
                },
                {
                    'name': 'code',
                    'in': 'query',
                    'required': False,
                    'schema': {'type': 'string'},
                    'description': 'The authorization code (required for authorization_code grant)'
                },
                {
                    'name': 'redirect_uri',
                    'in': 'query',
                    'required': False,
                    'schema': {'type': 'string', 'format': 'uri'},
                    'description': 'The redirection URI (required for authorization_code grant)'
                },
                {
                    'name': 'client_id',
                    'in': 'query',
                    'required': True,
                    'schema': {'type': 'string'},
                    'description': 'The client identifier'
                },
                {
                    'name': 'client_secret',
                    'in': 'query',
                    'required': False,
                    'schema': {'type': 'string'},
                    'description': 'The client secret (for confidential clients)'
                },
                {
                    'name': 'refresh_token',
                    'in': 'query',
                    'required': False,
                    'schema': {'type': 'string'},
                    'description': 'The refresh token (required for refresh_token grant)'
                },
                {
                    'name': 'code_verifier',
                    'in': 'query',
                    'required': False,
                    'schema': {'type': 'string'},
                    'description': 'PKCE code verifier'
                }
            ]
            parameters.extend(oauth2_token_params)
        
        # Add custom OAuth2 parameters
        if 'authorize' in endpoint_name:
            parameters.append({
                'name': 'next_challenge',
                'in': 'query',
                'required': False,
                'schema': {
                    'type': 'string',
                    'enum': ['INIT_AUTH'],
                    'default': 'INIT_AUTH'
                },
                'description': 'Custom parameter to indicate which challenge should be used for the flow'
            })
        
        # Token refresh endpoint headers (AWS Cognito pattern)
        if endpoint_name == '' or 'root' in endpoint_name:  # Root endpoint
            parameters.append({
                'name': 'x-amz-target',
                'in': 'header',
                'required': True,
                'schema': {
                    'type': 'string',
                    'enum': ['AWSCognitoIdentityProviderService.InitiateAuth']
                },
                'description': 'AWS Cognito service target for token refresh'
            })
        
        return parameters
    
    def _extract_function_parameters(self, endpoint: CompleteEndpointInfo) -> List[Dict[str, any]]:
        """Extract parameters from function signature analysis."""
        parameters = []
        
        # Check function parameters for query/header parameters
        for param in endpoint.parameters:
            param_name = param.get('name', '')
            param_annotation = param.get('annotation', '')
            
            # Skip common lambda parameters
            if param_name in ['event', 'context', 'request']:
                continue
            
            # Skip request body models
            if param.get('is_request_model', False):
                continue
            
            # Look for query string or header parameter patterns
            if 'query' in param_name.lower() or 'Query' in param_annotation:
                # Extract query parameters if the type is a model
                if param_annotation and param_annotation not in ['str', 'dict', 'Any']:
                    # This could be a query parameter model - would need schema lookup
                    # For now, create a generic query parameter
                    parameters.append({
                        'name': param_name.replace('_query', '').replace('Query', ''),
                        'in': 'query',
                        'required': False,
                        'schema': {'type': 'string'},
                        'description': f'Query parameter from {param_annotation}'
                    })
                else:
                    # Simple string query parameter
                    parameters.append({
                        'name': param_name,
                        'in': 'query', 
                        'required': False,
                        'schema': {'type': 'string'},
                        'description': f'Query parameter: {param_name}'
                    })
            
            # Look for header parameter patterns  
            elif 'header' in param_name.lower() or 'Header' in param_annotation:
                if param_annotation and param_annotation not in ['str', 'dict', 'Any']:
                    # This could be a header parameter model
                    parameters.append({
                        'name': param_name.replace('_header', '').replace('Header', ''),
                        'in': 'header',
                        'required': False,
                        'schema': {'type': 'string'},
                        'description': f'Header parameter from {param_annotation}'
                    })
                else:
                    # Simple string header parameter
                    parameters.append({
                        'name': param_name,
                        'in': 'header',
                        'required': False, 
                        'schema': {'type': 'string'},
                        'description': f'Header parameter: {param_name}'
                    })
            
            # Look for Pydantic model parameters that might be query parameter models
            elif param_annotation and param_annotation not in ['str', 'dict', 'Any', 'int', 'bool'] and \
                 ('Query' in param_annotation or 'Header' in param_annotation):
                # This is likely a Pydantic model for query/header parameters
                # We should expand it into individual parameters based on the model schema
                model_name = self._extract_model_name(param_annotation)
                if model_name:
                    # For now, create a placeholder - in a full implementation, we'd 
                    # inspect the Pydantic model to extract individual fields
                    parameters.append({
                        'name': f'{model_name.lower()}_params',
                        'in': 'query' if 'Query' in param_annotation else 'header',
                        'required': False,
                        'schema': {'$ref': f'#/components/schemas/{model_name}'},
                        'description': f'Parameters from {model_name} model'
                    })
                    
            # Look for simple string/int parameters that might be query parameters
            elif param_annotation in ['str', 'int', 'bool', 'Optional[str]', 'Optional[int]', 'Optional[bool]']:
                # These could be query parameters
                param_schema = {'type': 'string'}
                if param_annotation in ['int', 'Optional[int]']:
                    param_schema = {'type': 'integer'}
                elif param_annotation in ['bool', 'Optional[bool]']:
                    param_schema = {'type': 'boolean'}
                
                required = not param_annotation.startswith('Optional')
                
                parameters.append({
                    'name': param_name,
                    'in': 'query',
                    'required': required,
                    'schema': param_schema,
                    'description': f'Query parameter: {param_name}'
                })
        
        return parameters
    
    def infer_request_body_from_function(self, endpoint: CompleteEndpointInfo, valid_schemas: set = None) -> Optional[Dict[str, any]]:
        """
        Infer request body schema from function parameters and type hints.
        
        Args:
            endpoint: Complete endpoint information
            valid_schemas: Set of valid schema names to validate against
            
        Returns:
            Request body schema or None
        """
        if not endpoint.request_model:
            return None
        
        # Clean up the model name to extract just the class name
        model_name = self._extract_model_name(endpoint.request_model)
        if not model_name:
            return None
        
        # Check if the schema is valid if validation set is provided
        if valid_schemas is not None and model_name not in valid_schemas:
            return None
        
        # Enhanced request body structure with detailed description
        description = self._generate_request_body_description(endpoint, model_name)
        
        # Support multiple content types based on endpoint analysis
        content_types = self._determine_content_types(endpoint)
        
        content = {}
        for content_type in content_types:
            content[content_type] = {
                'schema': {
                    '$ref': f'#/components/schemas/{model_name}'
                }
            }
        
        return {
            'description': description,
            'required': True,
            'content': content
        }
    
    def _generate_request_body_description(self, endpoint: CompleteEndpointInfo, model_name: str) -> str:
        """Generate detailed request body description."""
        # Use description from docs if available
        if endpoint.description and len(endpoint.description) > 10:
            return endpoint.description
        
        # Use summary if available
        if endpoint.summary:
            return f'Request body for {endpoint.summary}'
        
        # Generate based on endpoint pattern and model
        endpoint_name = endpoint.path.strip('/') if endpoint.path else endpoint.function_name
        
        # OAuth2 specific descriptions
        oauth2_descriptions = {
            'register': 'Client registration request with authentication parameters and session configuration',
            'token': 'OAuth2 token exchange request with authorization code and PKCE parameters',
            'authorize': 'OAuth2 authorization request parameters', 
            'login': 'Authentication request with challenge-response parameters',
            'logout': 'Logout request to terminate user session',
            'password_reset': 'Password reset request with user credentials'
        }
        
        for pattern, desc in oauth2_descriptions.items():
            if pattern in endpoint_name.lower():
                return desc
        
        return f'Request body for {endpoint.function_name} containing {model_name} data'
    
    def _determine_content_types(self, endpoint: CompleteEndpointInfo) -> List[str]:
        """Determine supported content types based on endpoint analysis."""
        # Default to JSON
        content_types = ['application/json']
        
        # OAuth2 token endpoint often supports form encoding
        if 'token' in endpoint.path.lower() and endpoint.http_method.upper() == 'POST':
            content_types.append('application/x-www-form-urlencoded')
        
        # Check for specific patterns in the request model and function decorators
        if endpoint.request_model:
            model_name = endpoint.request_model.lower()
            if 'refresh' in model_name or 'token' in model_name or 'form' in model_name:
                if 'application/x-www-form-urlencoded' not in content_types:
                    content_types.append('application/x-www-form-urlencoded')
        
        # Check decorators for content-type hints
        for decorator in endpoint.decorators:
            if 'urlencoded' in decorator.lower() and 'application/x-www-form-urlencoded' not in content_types:
                content_types.append('application/x-www-form-urlencoded')
            if 'json' in decorator.lower() and 'application/json' not in content_types:
                content_types.append('application/json')
        
        # If both are present, prioritize form-urlencoded for token endpoints
        if 'token' in endpoint.path.lower() and 'application/x-www-form-urlencoded' in content_types and 'application/json' in content_types:
            content_types.remove('application/json')
            content_types.insert(0, 'application/x-www-form-urlencoded')
        
        return content_types
    
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
    
    def create_openapi_responses(self, endpoint: CompleteEndpointInfo) -> Dict[str, Dict]:
        """
        Create OpenAPI responses from endpoint information with enhanced details.
        
        Args:
            endpoint: Complete endpoint information
            
        Returns:
            OpenAPI responses dictionary
        """
        responses = {}
        
        # Add documented responses first
        for status_code, response_info in endpoint.responses.items():
            response_obj = {
                'description': response_info.get('description', f'Response {status_code}')
            }
            
            # Add content if there's a model
            if 'model' in response_info:
                response_obj['content'] = {
                    'application/json': {
                        'schema': {
                            '$ref': f'#/components/schemas/{response_info["model"]}'
                        }
                    }
                }
            
            responses[str(status_code)] = response_obj
        
        # Add success response from return type annotation if available
        success_response = self._create_success_response_from_return_type(endpoint)
        if success_response and '200' not in responses:
            responses['200'] = success_response
        
        # Add standard responses if not already present
        enhanced_responses = self._add_standard_responses(endpoint, responses)
        responses.update(enhanced_responses)
        
        # Add OAuth2 specific responses
        oauth2_responses = self._add_oauth2_responses(endpoint, responses)
        responses.update(oauth2_responses)
        
        return responses
    
    def _create_success_response_from_return_type(self, endpoint: CompleteEndpointInfo) -> Optional[Dict[str, any]]:
        """Create 200 success response from function return type annotation."""
        # Check if endpoint has return annotation (from original EndpointInfo)
        return_type = getattr(endpoint, 'return_annotation', None)
        
        # Fall back to response_model if available
        if not return_type and endpoint.response_model:
            return_type = endpoint.response_model
        
        if not return_type:
            return None
        
        # Handle common patterns
        if 'Response' in return_type:
            # Extract model name from response annotation
            model_name = self._extract_model_name(return_type)
            if model_name:
                description = self._generate_response_description(endpoint, model_name)
                return {
                    'description': description,
                    'content': {
                        'application/json': {
                            'schema': {
                                '$ref': f'#/components/schemas/{model_name}'
                            }
                        }
                    }
                }
        
        # Handle Dict, List return types
        if return_type.startswith('Dict') or return_type.startswith('List') or return_type.startswith('dict') or return_type.startswith('list'):
            return {
                'description': 'Successful response',
                'content': {
                    'application/json': {
                        'schema': {
                            'type': 'object' if 'Dict' in return_type or 'dict' in return_type else 'array'
                        }
                    }
                }
            }
        
        # Handle simple types
        simple_type_mapping = {
            'str': 'string',
            'int': 'integer', 
            'bool': 'boolean',
            'float': 'number'
        }
        
        if return_type in simple_type_mapping:
            return {
                'description': 'Successful response',
                'content': {
                    'application/json': {
                        'schema': {
                            'type': simple_type_mapping[return_type]
                        }
                    }
                }
            }
        
        return None
    
    def _generate_response_description(self, endpoint: CompleteEndpointInfo, model_name: str) -> str:
        """Generate description for response based on endpoint and model."""
        # Use existing summary/description if available
        if endpoint.summary and len(endpoint.summary) > 5:
            return f'{endpoint.summary} response'
        
        # Generate based on endpoint pattern
        endpoint_name = endpoint.path.strip('/') if endpoint.path else endpoint.function_name
        
        oauth2_descriptions = {
            'register': 'Session registration response with client credentials',
            'token': 'OAuth2 token response with access and refresh tokens',
            'authorize': 'Authorization response or redirect',
            'login': 'Authentication response with session information',
            'logout': 'Logout confirmation response',
            'password_reset': 'Password reset confirmation'
        }
        
        for pattern, desc in oauth2_descriptions.items():
            if pattern in endpoint_name.lower():
                return desc
        
        return f'Successful {endpoint.function_name} response with {model_name} data'
    
    def _add_standard_responses(self, endpoint: CompleteEndpointInfo, existing_responses: Dict) -> Dict[str, Dict]:
        """Add standard HTTP responses if not already present."""
        responses = {}
        
        # Always add 500 Internal Server Error if not present
        if '500' not in existing_responses:
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
        
        # Add 400 Bad Request for POST/PUT/PATCH endpoints
        if endpoint.http_method.upper() in ['POST', 'PUT', 'PATCH'] and '400' not in existing_responses:
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
        
        return responses
    
    def _add_oauth2_responses(self, endpoint: CompleteEndpointInfo, existing_responses: Dict) -> Dict[str, Dict]:
        """Add OAuth2 specific responses based on endpoint patterns."""
        responses = {}
        endpoint_name = endpoint.path.strip('/').lower() if endpoint.path else ''
        
        # OAuth2 Authorization endpoint responses
        if 'authorize' in endpoint_name and endpoint.http_method.upper() == 'GET':
            if '302' not in existing_responses:
                responses['302'] = {
                    'description': 'Redirect response',
                    'headers': {
                        'Location': {
                            'schema': {
                                'type': 'string',
                                'format': 'uri'
                            },
                            'description': 'URL to redirect to'
                        }
                    }
                }
        
        # Add 401 Unauthorized for protected endpoints
        protected_patterns = ['logout', 'sso_login', 'options', 'region', 'testable_features', 'user_successfully_logged_in', 'password_reset']
        if any(pattern in endpoint_name for pattern in protected_patterns) and '401' not in existing_responses:
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
        
        return responses
    
    def detect_security_requirements(self, endpoint: CompleteEndpointInfo) -> List[Dict[str, List[str]]]:
        """
        Detect security requirements for an endpoint based on patterns and metadata.
        
        Args:
            endpoint: Complete endpoint information
            
        Returns:
            List of security requirement objects
        """
        security_requirements = []
        endpoint_name = endpoint.path.strip('/').lower() if endpoint.path else ''
        
        # Public endpoints (no authentication required)
        public_patterns = [
            'register', 'token', 'authorize', 'oidc_discovery', 
            'jwks', 'login', '.well-known'
        ]
        
        # Check if endpoint is public
        is_public = any(pattern in endpoint_name for pattern in public_patterns)
        
        if not is_public:
            # Protected endpoints require bearer authentication
            security_requirements.append({
                'bearerAuth': []
            })
        
        # OAuth2 specific security for certain endpoints
        oauth2_endpoints = ['options', 'user_successfully_logged_in']
        if any(pattern in endpoint_name for pattern in oauth2_endpoints):
            if {'bearerAuth': []} not in security_requirements:
                security_requirements.append({
                    'bearerAuth': []
                })
        
        return security_requirements