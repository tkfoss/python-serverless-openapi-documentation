# type: ignore
import importlib.util
import inspect
import json
import re
import sys
import tomllib
from pathlib import Path
import yaml
from rich import print as rprint
from pydantic import BaseModel
from pydantic.json_schema import GenerateJsonSchema, JsonSchemaValue
from pydantic_core import core_schema

try:
    from pydantic.errors import PydanticInvalidForJsonSchema
except ImportError:
    PydanticInvalidForJsonSchema = Exception

# --- Custom JSON Schema Generator to handle unsupported types ---
class CustomJsonSchemaGenerator(GenerateJsonSchema):
    def core_schema_schema(self, core_schema: core_schema.CoreSchema) -> JsonSchemaValue:
        # Handle aws-lambda-powertools types that Pydantic can't process by default
        if isinstance(core_schema, core_schema.IsInstanceSchema):
            if 'CaseInsensitiveDict' in str(core_schema.cls) or 'Cookie' in str(core_schema.cls):
                return {'type': 'object'}
        
        # Fallback to the default behavior for all other types
        return super().core_schema_schema(core_schema)


def is_pydantic_model(obj):
    """Checks if an object is a Pydantic model class, excluding BaseModel itself."""
    return inspect.isclass(obj) and issubclass(obj, BaseModel) and obj is not BaseModel


def patch_token_region_request_schema(schema_file_path):
    """Specifically patches the TokenRegionRequest.json schema for the body.anyOf[1] issue."""
    try:
        with open(schema_file_path, "r") as f:
            schema_data = json.load(f)

        body_prop = schema_data.get("properties", {}).get("body", {})
        any_of_list = body_prop.get("anyOf")

        if isinstance(any_of_list, list) and len(any_of_list) > 1:
            if any_of_list[1] == {}:  # Check if the problematic empty object is at index 1
                rprint(
                    f"    [yellow]Patching {schema_file_path}: changing properties.body.anyOf[1] from {{}} to {{'type': 'object'}}[/yellow]"
                )
                any_of_list[1] = {"type": "object"}

                with open(schema_file_path, "w") as f:
                    json.dump(schema_data, f, indent=2)
                rprint(f"    [green]Successfully patched {schema_file_path}[/green]")
    except Exception as e:
        rprint(f"    [red]Error patching {schema_file_path}: {e}[/red]")


def generate_dto_schemas(source_dir: Path, output_dir: Path, project_root: Path):
    """Generates JSON schemas for Pydantic DTOs and returns a dict of successful ones."""
    rprint(f"[bold]Searching for DTOs in: {source_dir}[/bold]")
    
    # Add the parent of the source directory to the path to allow for package-level imports
    import_root = source_dir.parent
    sys.path.insert(0, str(import_root))
    
    output_dir.mkdir(parents=True, exist_ok=True)

    discovered_models = []
    processed_dto_files = set()
    successfully_generated_schemas = {}
    
    dto_files = list(source_dir.rglob("**/dtos.py"))
    
    for pass_num in range(3): # Try to resolve imports up to 3 times
        if not dto_files:
            break
            
        rprint(f"\n[bold]Import Pass {pass_num + 1}...[/bold]")
        
        remaining_files = []
        
        for dto_file_path in dto_files:
            if dto_file_path in processed_dto_files:
                continue

            rprint(f"  [cyan]Processing DTO file: {dto_file_path}[/cyan]")
            relative_path = dto_file_path.relative_to(import_root)
            module_name_parts = list(relative_path.parts)
            if module_name_parts[-1] == "dtos.py":
                module_name_parts[-1] = "dtos"
            module_name = ".".join(part for part in module_name_parts if part != "__pycache__")

            try:
                spec = importlib.util.spec_from_file_location(module_name, dto_file_path)
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    sys.modules[module_name] = module
                    spec.loader.exec_module(module)
                else:
                    rprint(f"\t[yellow]Could not create module spec for {dto_file_path}[/yellow]")
                    continue
            except ImportError as e:
                rprint(f"\t[yellow]Deferring import of {dto_file_path} due to ImportError: {e}[/yellow]")
                remaining_files.append(dto_file_path)
                if module_name in sys.modules:
                    del sys.modules[module_name]
                continue
            except Exception as e:
                rprint(f"\t[red]Error importing module {module_name} from {dto_file_path}: {e}[/red]")
                if module_name in sys.modules:
                    del sys.modules[module_name]
                continue

            processed_dto_files.add(dto_file_path)
            for name, obj in inspect.getmembers(module):
                if is_pydantic_model(obj):
                    if hasattr(obj, "__module__") and obj.__module__ == module_name:
                        discovered_models.append((obj, name, module_name))
        
        dto_files = remaining_files

    if dto_files:
        rprint("\n[bold red]Could not resolve all imports after multiple passes. The following files failed:[/bold red]")
        for f in dto_files:
            rprint(f"  - {f}")

    rprint(f"\n[bold]Found {len(discovered_models)} Pydantic models from {len(processed_dto_files)} DTO file(s).[/bold]")

    rprint("\n[bold]Phase 2: Rebuilding all discovered models...[/bold]")
    rebuilt_models_count = 0
    models_for_schema_gen = []
    for model_class, model_name, module_name in discovered_models:
        try:
            if hasattr(model_class, "model_rebuild"):
                model_class.model_rebuild(force=True)
            elif hasattr(model_class, "update_forward_refs"):
                model_class.update_forward_refs()
            rebuilt_models_count += 1
            models_for_schema_gen.append((model_class, model_name, module_name))
        except Exception as e:
            rprint(f"  [red]Error rebuilding model {module_name}.{model_name}: {e}[/red]")
            models_for_schema_gen.append((model_class, model_name, module_name))

    rprint(f"Attempted to rebuild {rebuilt_models_count} models.")

    rprint("\n[bold]Phase 3: Generating JSON schemas for DTOs...[/bold]")
    for model_class, model_name, module_name in models_for_schema_gen:
        rprint(f"  [cyan]Generating schema for: {module_name}.{model_name}[/cyan]")
        try:
            if hasattr(model_class, "model_json_schema"):
                schema = model_class.model_json_schema(schema_generator=CustomJsonSchemaGenerator)
            elif hasattr(model_class, "schema_json"):
                schema = json.loads(model_class.schema_json())
            else:
                rprint(f"\t[yellow]Could not find schema generation method for model {model_name}[/yellow]")
                continue

            schema_file_name = f"{model_name}.json"
            schema_file_path = output_dir / schema_file_name
            with open(schema_file_path, "w") as f:
                json.dump(schema, f, indent=2)
            rprint(f"\t[green]Schema saved to: {schema_file_path}[/green]")

            if model_name == "TokenRegionRequest":
                patch_token_region_request_schema(schema_file_path)

            successfully_generated_schemas[model_name] = schema_file_name
        except PydanticInvalidForJsonSchema as e:
            rprint(f"\t[red]Error: Cannot generate JSON schema for {module_name}.{model_name}. Details: {e}[/red]")
        except Exception as e:
            rprint(f"\t[red]Error generating/saving schema for model {module_name}.{model_name}: {e}[/red]")

    rprint(f"\n[bold green]Successfully generated {len(successfully_generated_schemas)} DTO JSON schema file(s).[/bold green]")
    return successfully_generated_schemas


def parse_author_string(author_str):
    """Parses an author string into name and email."""
    match = re.match(r"^(.*?)\s*<([^>]+)>$", author_str)
    if match:
        return match.group(1).strip(), match.group(2).strip()
    return author_str.strip(), None


def load_project_meta(project_root: Path):
    """Loads project metadata from pyproject.toml."""
    pyproject_file = project_root / "pyproject.toml"
    rprint(f"\n[bold]Loading project metadata from {pyproject_file}...[/bold]")
    meta = {
        "title": "My API",
        "version": "0.1.0",
        "description": "API documentation",
        "contact_name": None,
        "contact_email": None,
    }
    try:
        with open(pyproject_file, "rb") as f:
            data = tomllib.load(f)
        poetry_data = data.get("tool", {}).get("poetry", {})
        name = poetry_data.get("name", "my-api")
        meta["title"] = name.replace("_", " ").replace("-", " ").title() + " API"
        meta["version"] = poetry_data.get("version", "0.1.0")
        meta["description"] = poetry_data.get("description", "API documentation")
        authors = poetry_data.get("authors", [])
        if authors and isinstance(authors, list) and authors[0]:
            meta["contact_name"], meta["contact_email"] = parse_author_string(authors[0])
        rprint(f"  [cyan]API Title:[/] {meta['title']}, [cyan]Version:[/] {meta['version']}, [cyan]Description:[/] {meta['description']}")
        if meta["contact_name"]:
            rprint(f"  [cyan]Contact Name:[/] {meta['contact_name']}, [cyan]Email:[/] {meta['contact_email']}")
    except FileNotFoundError:
        rprint(f"  [red]Error: {pyproject_file} not found. Using default API info.[/red]")
    except Exception as e:
        rprint(f"  [red]Error reading {pyproject_file}: {e}. Using default API info.[/red]")
    return meta


def generate_serverless_config(successfully_generated_schemas, project_meta, project_root: Path):
    """Generates a serverless configuration in memory."""
    rprint("\n[bold]Generating Serverless config for OpenAPI in memory...[/bold]")
    python_runtime = "python3.12"
    try:
        # Look for any serverless.yml or serverless.yaml file in the project root
        sls_files = list(project_root.glob("serverless.y*ml"))
        if sls_files:
            main_sls_file = sls_files[0]
            with open(main_sls_file, "r") as f:
                main_config = yaml.safe_load(f)
            if main_config and "provider" in main_config and "runtime" in main_config["provider"]:
                python_runtime = main_config["provider"]["runtime"]
                rprint(f"  [cyan]Using runtime '{python_runtime}' from {main_sls_file}[/cyan]")
    except Exception as e:
        rprint(f"  [yellow]Could not determine runtime, defaulting to {python_runtime}. Error: {e}[/yellow]")

    model_entries = []
    if successfully_generated_schemas:
        for schema_info in sorted(successfully_generated_schemas, key=lambda x: x['name']):
            model_name = schema_info['name']
            description = schema_info.get('description', f"Schema for {model_name}")
            
            # The schema is already loaded, so we can embed it directly or reference it
            # For this implementation, we'll stick to the file reference model
            schema_file_name = f"{model_name}.json"

            model_entries.append(
                {
                    "name": model_name,
                    "description": description,
                    "contentType": "application/json",
                    "schema": f"${{file(openapi_models/{schema_file_name})}}",
                }
            )

    documentation_block = {
        "version": project_meta["version"],
        "title": project_meta["title"],
        "description": project_meta["description"],
        "models": model_entries,
    }
    if project_meta["contact_name"]:
        documentation_block["contact"] = {"name": project_meta["contact_name"]}
        if project_meta["contact_email"]:
            documentation_block["contact"]["email"] = project_meta["contact_email"]

    functions_file = project_root / "serverless" / "functions.yml"
    functions_content = {}
    if functions_file.exists():
        try:
            with open(functions_file, "r") as f:
                functions_content = yaml.safe_load(f)
            rprint(f"  [green]Successfully loaded functions from {functions_file}[/green]")
        except Exception as e:
            rprint(f"  [yellow]Warning: Could not read or parse functions file {functions_file}: {e}[/yellow]")
    else:
        rprint("  [yellow]Warning: functions.yml not found. No operations will be generated.[/yellow]")


    config_content = {
        "service": project_meta.get("title", "my-api").lower().replace(" ", "-"),
        "frameworkVersion": ">=3.0.0",
        "provider": {"name": "aws", "runtime": python_runtime},
        "plugins": ["serverless-openapi-documenter"],
        "custom": {
            "documentation": documentation_block
        },
        "functions": functions_content,
    }
    
    return config_content
