import importlib.util
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich import print as rprint

from .python_discovery import EndpointInfo, RouteInfo


@dataclass
class DocsModule:
    """Information about a discovered docs.py module."""
    file_path: Path
    module_name: str
    endpoint_name: str


@dataclass
class EndpointDocs:
    """Documentation extracted from docs.py files."""
    summary: Optional[str]
    description: Optional[str]
    response_model: Optional[str]
    status_code: Optional[int]
    responses: Dict[int, Dict[str, Any]]
    tags: List[str]
    name: Optional[str]
    response_description: Optional[str]
    request_model: Optional[str]


@dataclass
class CompleteEndpointInfo:
    """Complete endpoint information combining function metadata and docs."""
    function_name: str
    file_path: Path
    module_path: str
    endpoint_name: str
    http_method: str
    path: str
    
    # Documentation
    summary: Optional[str]
    description: Optional[str]
    
    # Request/Response
    request_model: Optional[str]
    response_model: Optional[str]
    status_code: int
    responses: Dict[int, Dict[str, Any]]
    
    # OpenAPI metadata
    tags: List[str]
    parameters: List[Dict[str, Any]]
    
    # Function metadata
    docstring: Optional[str]
    function_signature: Optional[str]
    is_async: bool
    decorators: List[str]


class DocsExtractor:
    """Extracts documentation from docs.py files and merges with function metadata."""
    
    def __init__(self):
        self.docs_cache = {}
        
    def discover_docs_files(self, source_dir: Path, 
                           docs_pattern: str = "**/docs.py") -> List[DocsModule]:
        """
        Discover docs.py files in the source directory.
        
        Args:
            source_dir: Root directory to search
            docs_pattern: Glob pattern for docs files
            
        Returns:
            List of discovered docs modules
        """
        docs_modules = []
        
        for docs_file in source_dir.glob(docs_pattern):
            try:
                # Extract endpoint name from directory structure
                endpoint_name = self._extract_endpoint_name(docs_file)
                module_name = self._get_module_name(docs_file, source_dir)
                
                docs_modules.append(DocsModule(
                    file_path=docs_file,
                    module_name=module_name,
                    endpoint_name=endpoint_name
                ))
                
            except Exception as e:
                rprint(f"[yellow]Warning: Could not process docs file {docs_file}: {e}[/yellow]")
                
        return docs_modules
    
    def _extract_endpoint_name(self, docs_file: Path) -> str:
        """Extract endpoint name from docs.py file path."""
        # For path like .../http_endpoints/register/docs.py -> "register"
        parts = docs_file.parts
        
        if len(parts) >= 2 and docs_file.name == 'docs.py':
            return parts[-2]  # Parent directory name
        
        return docs_file.stem
    
    def _get_module_name(self, docs_file: Path, source_dir: Path) -> str:
        """Convert docs file path to Python module path."""
        try:
            relative_path = docs_file.relative_to(source_dir)
            module_parts = list(relative_path.with_suffix('').parts)
            return '.'.join(module_parts)
        except Exception:
            return str(docs_file.stem)
    
    def extract_docs_metadata(self, docs_module: DocsModule, source_dir: Optional[Path] = None) -> Optional[EndpointDocs]:
        """
        Extract documentation metadata from a docs.py module.
        
        Args:
            docs_module: Information about the docs module
            source_dir: Source directory to add to Python path for imports
            
        Returns:
            Extracted documentation metadata or None if extraction fails
        """
        try:
            # Add source directory to Python path temporarily for imports
            old_path = sys.path.copy()
            if source_dir:
                # Add parent directory of source_dir to handle project imports
                parent_dir = str(source_dir.parent)
                if parent_dir not in sys.path:
                    sys.path.insert(0, parent_dir)
                    
            try:
                # Load the module dynamically
                spec = importlib.util.spec_from_file_location(
                    docs_module.module_name, 
                    docs_module.file_path
                )
                if not spec or not spec.loader:
                    return None
                    
                module = importlib.util.module_from_spec(spec)
                
                # Add to sys.modules temporarily to handle relative imports
                old_module = sys.modules.get(docs_module.module_name)
                sys.modules[docs_module.module_name] = module
                
                try:
                    spec.loader.exec_module(module)
                
                    # Extract docs_input dictionary
                    docs_input = getattr(module, 'docs_input', {})
                    
                    if not docs_input:
                        rprint(f"[yellow]Warning: No docs_input found in {docs_module.file_path}[/yellow]")
                        return None
                    
                    return self._parse_docs_input(docs_input)
                    
                finally:
                    # Restore original module
                    if old_module is not None:
                        sys.modules[docs_module.module_name] = old_module
                    else:
                        sys.modules.pop(docs_module.module_name, None)
                        
            finally:
                # Restore original Python path
                sys.path[:] = old_path
                    
        except Exception as e:
            rprint(f"[yellow]Warning: Could not extract docs from {docs_module.file_path}: {e}[/yellow]")
            return None
    
    def _parse_docs_input(self, docs_input: Dict[str, Any]) -> EndpointDocs:
        """Parse the docs_input dictionary into structured documentation."""
        
        # Extract response model information
        response_model = None
        if 'response_model' in docs_input:
            response_model_obj = docs_input['response_model']
            if hasattr(response_model_obj, '__name__'):
                response_model = response_model_obj.__name__
            else:
                response_model = str(response_model_obj)
        
        # Extract request model information
        request_model = None
        if 'request_model' in docs_input:
            request_model_obj = docs_input['request_model']
            if hasattr(request_model_obj, '__name__'):
                request_model = request_model_obj.__name__
            else:
                request_model = str(request_model_obj)
        
        # Extract error responses - check both 'responses' and 'error_responses'
        responses = {}
        
        # Handle 'responses' field
        if 'responses' in docs_input:
            for status_code, response_info in docs_input['responses'].items():
                if isinstance(response_info, dict) and 'model' in response_info:
                    model_obj = response_info['model']
                    model_name = model_obj.__name__ if hasattr(model_obj, '__name__') else str(model_obj)
                    responses[int(status_code)] = {
                        'description': response_info.get('description', f'Error response {status_code}'),
                        'model': model_name
                    }
                elif isinstance(response_info, dict):
                    responses[int(status_code)] = {
                        'description': response_info.get('description', f'Response {status_code}')
                    }
                else:
                    responses[int(status_code)] = {
                        'description': str(response_info)
                    }
        
        # Handle 'error_responses' field
        if 'error_responses' in docs_input:
            for status_code, response_info in docs_input['error_responses'].items():
                if isinstance(response_info, dict) and 'model' in response_info:
                    model_obj = response_info['model']
                    model_name = model_obj.__name__ if hasattr(model_obj, '__name__') else str(model_obj)
                    responses[int(status_code)] = {
                        'description': response_info.get('description', f'Error response {status_code}'),
                        'model': model_name
                    }
                elif isinstance(response_info, dict):
                    responses[int(status_code)] = {
                        'description': response_info.get('description', f'Error response {status_code}')
                    }
                else:
                    responses[int(status_code)] = {
                        'description': str(response_info)
                    }
        
        # Add success response if we have a response model
        status_code = docs_input.get('status_code', 200)
        if response_model and status_code not in responses:
            responses[status_code] = {
                'description': docs_input.get('response_description', 'Successful response'),
                'model': response_model
            }
        
        return EndpointDocs(
            summary=docs_input.get('summary'),
            description=docs_input.get('description'),
            response_model=response_model,
            status_code=status_code,
            responses=responses,
            tags=docs_input.get('tags', []),
            name=docs_input.get('name'),
            response_description=docs_input.get('response_description'),
            request_model=request_model
        )
    
    def merge_with_function_metadata(self, 
                                   func_info: 'EndpointInfo',  # Forward reference
                                   route_info: 'RouteInfo',     # Forward reference
                                   docs_meta: Optional[EndpointDocs] = None) -> CompleteEndpointInfo:
        """
        Merge function metadata with documentation metadata.
        
        Args:
            func_info: Function information from PythonEndpointDiscovery
            route_info: Route information 
            docs_meta: Documentation metadata from docs.py (optional)
            
        Returns:
            Complete endpoint information
        """
        from .python_discovery import DocstringMetadata
        
        # Parse docstring for additional info
        docstring_meta = DocstringMetadata(
            summary=None, description=None, args={}, 
            returns=None, raises={}, openapi_info={}
        )
        
        if func_info.docstring:
            # Simple parsing - could be enhanced
            lines = func_info.docstring.strip().split('\n')
            if lines:
                docstring_meta.summary = lines[0].strip()
                if len(lines) > 2:
                    docstring_meta.description = ' '.join(line.strip() for line in lines[2:] if line.strip())
        
        # Determine final values, preferring docs.py over docstring
        summary = (docs_meta.summary if docs_meta else None) or docstring_meta.summary or func_info.function_name
        description = (docs_meta.description if docs_meta else None) or docstring_meta.description or ""
        
        # Determine request model - prefer docs.py over function signature
        request_model = None
        if docs_meta and docs_meta.request_model:
            request_model = docs_meta.request_model
        elif func_info.request_model:
            request_model = func_info.request_model
        else:
            # Fallback: extract from function parameters
            for param in func_info.parameters:
                if param['annotation'] and param['name'] not in ['context', 'event']:
                    annotation = param['annotation']
                    if 'Request' in annotation or 'DTO' in annotation or param.get('is_request_model', False):
                        request_model = annotation
                        break
        
        # Determine response model - prefer docs.py over function signature
        response_model = None
        if docs_meta and docs_meta.response_model:
            response_model = docs_meta.response_model
        elif func_info.response_model:
            response_model = func_info.response_model
        
        # Merge responses
        responses = docs_meta.responses if docs_meta else {}
        if not responses:
            # Default response
            responses[200] = {'description': 'Successful response'}
        
        # Determine tags
        tags = []
        if docs_meta and docs_meta.tags:
            tags = docs_meta.tags
        else:
            # Infer from path
            if route_info.endpoint_name:
                tags = [route_info.endpoint_name]
        
        return CompleteEndpointInfo(
            function_name=func_info.function_name,
            file_path=func_info.file_path,
            module_path=func_info.module_path,
            endpoint_name=route_info.endpoint_name or func_info.function_name,
            http_method=route_info.method or 'POST',
            path=route_info.path or f"/{func_info.function_name}",
            
            summary=summary,
            description=description,
            
            request_model=request_model,
            response_model=response_model,
            status_code=docs_meta.status_code if docs_meta else 200,
            responses=responses,
            
            tags=tags,
            parameters=[],  # Will be populated later
            
            docstring=func_info.docstring,
            function_signature=func_info.function_signature,
            is_async=func_info.is_async,
            decorators=func_info.decorators
        )
