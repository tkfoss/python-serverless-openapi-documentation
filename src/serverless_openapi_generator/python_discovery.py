import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich import print as rprint


@dataclass
class EndpointInfo:
    """Information about a discovered endpoint."""
    function_name: str
    file_path: Path
    module_path: str
    docstring: Optional[str]
    function_signature: Optional[str]
    line_number: int
    is_async: bool
    decorators: List[str]
    parameters: List[Dict[str, Any]]
    return_annotation: Optional[str]
    response_model: Optional[str] = None
    request_model: Optional[str] = None


@dataclass
class DocstringMetadata:
    """Parsed docstring metadata."""
    summary: Optional[str]
    description: Optional[str]
    args: Dict[str, str]
    returns: Optional[str]
    raises: Dict[str, str]
    openapi_info: Dict[str, Any]


@dataclass
class RouteInfo:
    """Extracted route information."""
    path: Optional[str]
    method: Optional[str]
    endpoint_name: Optional[str]


class PythonEndpointDiscovery:
    """Discovers HTTP handler functions in Python codebases."""
    
    def __init__(self):
        self.lambda_handler_patterns = [
            r'lambda_handler',
            r'handler',
            r'main'
        ]
        self.endpoint_patterns = [
            r'http_endpoints',
            r'endpoints',
            r'handlers',
            r'api'
        ]
        self.docs_file_pattern = r'docs\.py$'
        
    def discover_handlers(self, source_dir: Path, 
                         endpoint_pattern: str = "**/handler.py",
                         docs_pattern: str = "**/docs.py") -> List[EndpointInfo]:
        """
        Discover HTTP handler functions in the source directory.
        
        Args:
            source_dir: Root directory to search
            endpoint_pattern: Glob pattern for endpoint files
            docs_pattern: Glob pattern for docs files
            
        Returns:
            List of discovered endpoint information
        """
        endpoints = []
        
        # Find handler files
        handler_files = list(source_dir.glob(endpoint_pattern))
        
        for file_path in handler_files:
            try:
                file_endpoints = self._analyze_python_file(file_path, source_dir)
                endpoints.extend(file_endpoints)
            except Exception as e:
                rprint(f"[yellow]Warning: Could not analyze {file_path}: {e}[/yellow]")
                
        return endpoints
    
    def _analyze_python_file(self, file_path: Path, source_dir: Path) -> List[EndpointInfo]:
        """Analyze a Python file for handler functions."""
        endpoints = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            tree = ast.parse(content)
            module_path = self._get_module_path(file_path, source_dir)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    if self._is_handler_function(node):
                        endpoint_info = self._create_endpoint_info(
                            node, file_path, module_path, content
                        )
                        endpoints.append(endpoint_info)
                        
        except Exception as e:
            rprint(f"[yellow]Warning: Could not parse {file_path}: {e}[/yellow]")
            
        return endpoints
    
    def _is_handler_function(self, node: ast.FunctionDef) -> bool:
        """Check if a function is likely an HTTP handler."""
        # Check for lambda_handler pattern
        for pattern in self.lambda_handler_patterns:
            if re.search(pattern, node.name, re.IGNORECASE):
                return True
                
        # Check for specific decorators that indicate handlers
        handler_decorators = [
            'event_parser',
            'tracer.wrap',
            'app.middleware',
            'route',
            'post',
            'get',
            'put',
            'delete',
            'patch'
        ]
        
        for decorator in node.decorator_list:
            decorator_name = self._get_decorator_name(decorator)
            if any(hd in decorator_name for hd in handler_decorators):
                return True
                
        # Check function signature for typical handler patterns
        if len(node.args.args) >= 2:
            arg_names = [arg.arg for arg in node.args.args]
            # Lambda handler pattern: (event, context)
            if len(arg_names) >= 2 and ('event' in arg_names[0] or 'context' in arg_names[1]):
                return True
                
        return False
    
    def _get_decorator_name(self, decorator) -> str:
        """Extract decorator name from AST node."""
        if isinstance(decorator, ast.Name):
            return decorator.id
        elif isinstance(decorator, ast.Attribute):
            return ast.unparse(decorator) if hasattr(ast, 'unparse') else str(decorator.attr)
        elif isinstance(decorator, ast.Call):
            if isinstance(decorator.func, ast.Name):
                return decorator.func.id
            elif isinstance(decorator.func, ast.Attribute):
                return ast.unparse(decorator.func) if hasattr(ast, 'unparse') else str(decorator.func.attr)
        return ""
    
    def _create_endpoint_info(self, node: ast.FunctionDef, file_path: Path, 
                            module_path: str, content: str) -> EndpointInfo:
        """Create EndpointInfo from AST function node."""
        
        # Extract docstring
        docstring = ast.get_docstring(node)
        
        # Extract function signature
        function_signature = self._get_function_signature(node)
        
        # Extract decorators
        decorators = [self._get_decorator_name(d) for d in node.decorator_list]
        
        # Extract parameters
        parameters = self._extract_parameters(node)
        
        # Extract return annotation
        return_annotation = None
        response_model = None
        if node.returns:
            try:
                return_annotation = ast.unparse(node.returns) if hasattr(ast, 'unparse') else str(node.returns)
                # Extract response model from return annotation
                if 'Response' in return_annotation and 'Body' in return_annotation:
                    response_model = return_annotation
                elif return_annotation not in ['None', 'dict', 'Dict', 'Any', 'str', 'int', 'bool', 'Response', 'aws_lambda_powertools.event_handler.Response']:
                    # If it's a custom type, assume it's a response model
                    response_model = return_annotation
            except Exception:
                return_annotation = 'Any'
        
        # Extract request model from decorators first (more reliable)
        request_model = None
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Call):
                decorator_name = self._get_decorator_name(decorator)
                if 'event_parser' in decorator_name:
                    # Extract model from @event_parser(model=SomeModel)
                    for keyword in decorator.keywords:
                        if keyword.arg == 'model':
                            try:
                                request_model = ast.unparse(keyword.value) if hasattr(ast, 'unparse') else str(keyword.value)
                                break
                            except Exception:
                                pass
                    break
        
        # Fallback: Extract request model from parameters
        if not request_model:
            for param in parameters:
                if param.get('is_request_model', False):
                    request_model = param['annotation']
                    break
        
        return EndpointInfo(
            function_name=node.name,
            file_path=file_path,
            module_path=module_path,
            docstring=docstring,
            function_signature=function_signature,
            line_number=node.lineno,
            is_async=isinstance(node, ast.AsyncFunctionDef),
            decorators=decorators,
            parameters=parameters,
            return_annotation=return_annotation,
            response_model=response_model,
            request_model=request_model
        )
    
    def _get_function_signature(self, node: ast.FunctionDef) -> str:
        """Extract function signature as string."""
        try:
            if hasattr(ast, 'unparse'):
                # Python 3.9+
                return f"def {node.name}({ast.unparse(node.args)})"
            else:
                # Fallback for older Python versions
                args = []
                for arg in node.args.args:
                    args.append(arg.arg)
                return f"def {node.name}({', '.join(args)})"
        except Exception:
            return f"def {node.name}(...)"
    
    def _extract_parameters(self, node: ast.FunctionDef) -> List[Dict[str, Any]]:
        """Extract function parameters with type hints."""
        parameters = []
        
        for i, arg in enumerate(node.args.args):
            param_info = {
                'name': arg.arg,
                'annotation': None,
                'default': None,
                'is_request_model': False,
                'is_response_model': False
            }
            
            if arg.annotation:
                try:
                    annotation_str = ast.unparse(arg.annotation) if hasattr(ast, 'unparse') else str(arg.annotation)
                    param_info['annotation'] = annotation_str
                    
                    # Detect request models by common patterns
                    if ('Request' in annotation_str or 'DTO' in annotation_str or 'Body' in annotation_str) and \
                       arg.arg not in ['event', 'context']:
                        param_info['is_request_model'] = True
                        
                except Exception:
                    param_info['annotation'] = 'Any'
            
            # Add default value if available
            defaults_offset = len(node.args.args) - len(node.args.defaults)
            if i >= defaults_offset:
                default_idx = i - defaults_offset
                if default_idx < len(node.args.defaults):
                    try:
                        param_info['default'] = ast.unparse(node.args.defaults[default_idx]) if hasattr(ast, 'unparse') else 'default'
                    except Exception:
                        param_info['default'] = 'default'
                    
            parameters.append(param_info)
            
        return parameters
    
    def _get_module_path(self, file_path: Path, source_dir: Path) -> str:
        """Convert file path to Python module path."""
        try:
            relative_path = file_path.relative_to(source_dir)
            # Remove .py extension and convert to module path
            module_parts = list(relative_path.with_suffix('').parts)
            return '.'.join(module_parts)
        except Exception:
            return str(file_path.stem)
    
    def extract_docstring_docs(self, func_info: EndpointInfo) -> DocstringMetadata:
        """Extract documentation from function docstring."""
        if not func_info.docstring:
            return DocstringMetadata(
                summary=None,
                description=None,
                args={},
                returns=None,
                raises={},
                openapi_info={}
            )
        
        # Parse Google/NumPy style docstrings
        return self._parse_docstring(func_info.docstring)
    
    def _parse_docstring(self, docstring: str) -> DocstringMetadata:
        """Parse docstring in Google or NumPy format."""
        lines = docstring.strip().split('\n')
        
        summary = None
        description_lines = []
        args = {}
        returns = None
        raises = {}
        openapi_info = {}
        
        current_section = None
        i = 0
        
        # Extract summary (first line)
        if lines:
            summary = lines[0].strip()
            i = 1
            
        # Skip empty lines and extract description
        while i < len(lines) and not lines[i].strip():
            i += 1
            
        # Extract description until we hit a section
        while i < len(lines):
            line = lines[i].strip()
            if self._is_section_header(line):
                break
            if line:
                description_lines.append(line)
            i += 1
            
        description = ' '.join(description_lines) if description_lines else None
        
        # Parse sections
        while i < len(lines):
            line = lines[i].strip()
            
            if line.startswith('Args:') or line.startswith('Arguments:') or line.startswith('Parameters:'):
                current_section = 'args'
                i += 1
                continue
            elif line.startswith('Returns:') or line.startswith('Return:'):
                current_section = 'returns'
                i += 1
                continue
            elif line.startswith('Raises:'):
                current_section = 'raises'
                i += 1
                continue
            elif line.startswith('OpenAPI:'):
                current_section = 'openapi'
                i += 1
                continue
            
            if current_section == 'args' and line:
                # Parse "param_name: description" format
                if ':' in line:
                    parts = line.split(':', 1)
                    param_name = parts[0].strip()
                    param_desc = parts[1].strip()
                    args[param_name] = param_desc
                    
            elif current_section == 'returns' and line:
                returns = line
                
            elif current_section == 'raises' and line:
                if ':' in line:
                    parts = line.split(':', 1)
                    exception_name = parts[0].strip()
                    exception_desc = parts[1].strip()
                    raises[exception_name] = exception_desc
                    
            elif current_section == 'openapi' and line:
                # Parse YAML-like OpenAPI info
                if ':' in line:
                    parts = line.split(':', 1)
                    key = parts[0].strip()
                    value = parts[1].strip()
                    openapi_info[key] = value
                    
            i += 1
        
        return DocstringMetadata(
            summary=summary,
            description=description,
            args=args,
            returns=returns,
            raises=raises,
            openapi_info=openapi_info
        )
    
    def _is_section_header(self, line: str) -> bool:
        """Check if line is a docstring section header."""
        headers = ['Args:', 'Arguments:', 'Parameters:', 'Returns:', 'Return:', 'Raises:', 'OpenAPI:']
        return any(line.startswith(header) for header in headers)
    
    def infer_http_method(self, func_info: EndpointInfo) -> str:
        """Infer HTTP method from function name and context."""
        function_name = func_info.function_name.lower()
        
        # OAuth2 specific method detection based on standard patterns
        # Extract endpoint name from path structure
        endpoint_name = self._extract_endpoint_name_from_path(func_info.file_path)
        
        # OAuth2/OIDC standard method mappings based on RFC specifications
        oauth2_get_endpoints = [
            'authorize',           # RFC 6749 - Authorization endpoint
            'userinfo',           # OIDC - UserInfo endpoint  
            'well-known',         # OIDC Discovery
            'jwks',               # OIDC - JSON Web Key Set
            'discovery',          # OIDC Discovery
            'oidc_discovery',     # Alternative naming
            '.well-known'         # Standard discovery path
        ]
        oauth2_post_endpoints = [
            'token',              # RFC 6749 - Token endpoint
            'revoke',             # RFC 7009 - Token revocation
            'introspect',         # RFC 7662 - Token introspection
            'login',              # Authentication/login flows
            'register',           # Client registration
            'logout',             # Logout endpoint
            'sso_login',          # SSO login
            'password_reset'      # Password reset
        ]
        
        if endpoint_name:
            endpoint_lower = endpoint_name.lower()
            
            # Check for exact matches first
            if endpoint_lower in oauth2_get_endpoints:
                return 'GET'
            elif endpoint_lower in oauth2_post_endpoints:
                return 'POST'
            
            # Check for partial matches
            for get_endpoint in oauth2_get_endpoints:
                if get_endpoint in endpoint_lower:
                    return 'GET'
            for post_endpoint in oauth2_post_endpoints:
                if post_endpoint in endpoint_lower:
                    return 'POST'
        
        # Check function signature for request body parameters (indicates POST/PUT)
        has_request_body = False
        for param in func_info.parameters:
            if param['annotation'] and ('Request' in param['annotation'] or 'Body' in param['annotation']):
                has_request_body = True
                break
        
        # Check for HTTP method keywords in function name
        if 'get' in function_name or 'retrieve' in function_name or 'fetch' in function_name or 'list' in function_name:
            return 'GET'
        elif 'post' in function_name or 'create' in function_name or 'register' in function_name or 'submit' in function_name:
            return 'POST'
        elif 'put' in function_name or 'update' in function_name or 'replace' in function_name:
            return 'PUT'
        elif 'delete' in function_name or 'remove' in function_name or 'destroy' in function_name:
            return 'DELETE'
        elif 'patch' in function_name or 'modify' in function_name:
            return 'PATCH'
        elif 'option' in function_name or 'head' in function_name:
            return 'OPTIONS' if 'option' in function_name else 'HEAD'
        
        # Check decorators for HTTP method hints
        for decorator in func_info.decorators:
            decorator_lower = decorator.lower()
            if 'post' in decorator_lower:
                return 'POST'
            elif 'get' in decorator_lower:
                return 'GET'
            elif 'put' in decorator_lower:
                return 'PUT'
            elif 'delete' in decorator_lower:
                return 'DELETE'
            elif 'patch' in decorator_lower:
                return 'PATCH'
            elif 'options' in decorator_lower:
                return 'OPTIONS'
            elif 'head' in decorator_lower:
                return 'HEAD'
        
        # If function has request body parameters, likely POST
        if has_request_body:
            return 'POST'
        
        # Default based on common AWS Lambda patterns
        # Read-only endpoints typically use GET, others use POST
        if any(readonly in function_name for readonly in ['info', 'status', 'health', 'discovery', 'keys']):
            return 'GET'
        
        # Default for lambda handlers is POST
        return 'POST'
    
    def _extract_endpoint_name_from_path(self, file_path: Path) -> Optional[str]:
        """Extract endpoint name from file path."""
        path_parts = file_path.parts
        
        try:
            if 'http_endpoints' in path_parts:
                idx = path_parts.index('http_endpoints')
                if idx + 1 < len(path_parts):
                    return path_parts[idx + 1]
        except (ValueError, IndexError):
            pass
        
        return None
    
    def extract_route_info(self, func_info: EndpointInfo) -> RouteInfo:
        """Extract route information from function and file structure."""
        # Look for http_endpoints pattern
        endpoint_name = None
        path = None
        
        try:
            if func_info.file_path.name == 'handler.py':
                endpoint_name = func_info.file_path.parent.name
                path = f"/{endpoint_name}"
        except (ValueError, IndexError):
            pass
        
        # Fallback: use function name
        if not endpoint_name:
            endpoint_name = func_info.function_name.replace('_handler', '').replace('lambda_', '')
            path = f"/{endpoint_name}"
        
        method = self.infer_http_method(func_info)
        
        return RouteInfo(
            path=path,
            method=method,
            endpoint_name=endpoint_name
        )
