# OpenAPI Generator for Serverless Configurations

<p>
  <a href="https://www.python.org">
    <img src="https://img.shields.io/badge/python-3.8+-blue.svg">
  </a>
  <a href="https://github.com/JaredCE/serverless-openapi-documenter/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/License-MIT-yellow.svg">
  </a>
</p>

This tool generates an OpenAPI V3 file from your `serverless.yml` file. It is a standalone Python application that parses the `custom.documentation` section of your serverless configuration to produce a complete OpenAPI specification. This currently works for `http` and `httpApi` configurations.

## Install

This tool requires Python 3.8+.

First, ensure you have the necessary Python packaging tools installed:
```bash
pip install build
```

Then, build the package from the root of this repository:
```bash
python -m build
```

This will create a `dist` directory containing the installable package. You can install it using pip:
```bash
pip install dist/serverless_openapi_generator-1.0.0-py3-none-any.whl
```

## Usage

Once installed, you can use the `openapi-gen` command-line tool.

### Running from GitHub

You can also run the tool directly from GitHub using `uvx`:
```bash
uvx --from git+https://github.com/tkfoss/python-serverless-openapi-documentation.git openapi-gen path/to/your/serverless.yml openapi.json
```
For more information on running tools with `uv`, see the [official documentation](https://docs.astral.sh/uv/guides/tools/#running-tools).

**To Run:**
```bash
openapi-gen path/to/your/serverless.yml openapi.json --openApiVersion 3.0.3
```

**Options:**

```
serverless_yml_path      Path to the serverless.yml file. (Required)
output_file_path         Path to the output OpenAPI JSON file. (Required)
--openApiVersion         The OpenAPI version to generate for. Default: 3.0.3
--pre-hook               Path to a Python script to run before generation.
--validate               Validate the generated OpenAPI spec.
```

### Validation

This tool also includes a script to validate an OpenAPI specification file against the OpenAPI 3.0.3 specification.

**To Run:**
```bash
openapi-validate path/to/your/openapi.json
```

You can also use the `--validate` flag with the `openapi-gen` command to automatically validate the generated spec:
```bash
openapi-gen path/to/your/serverless.yml openapi.json --validate
```

### Configuration

To configure this tool to generate a valid OpenAPI Description, there are two places you'll need to modify in your `serverless.yml` file: the `custom.documentation` section and the `documentation` block within the `http`/`httpApi` event for each function.

The `custom` section of your `serverless.yml` can be configured as below:

```yml
custom:
  documentation:
    version: "1.0.0"
    title: "My API"
    description: "This is my API"
    termsOfService: https://google.com
    contact:
      name: API Support
      email: support@example.com
    license:
      name: MIT
      url: https://opensource.org/licenses/MIT
    externalDocumentation:
      url: https://google.com
      description: A link to google
    servers:
      - url: https://example.com:{port}/
        description: The server
        variables:
          port:
            enum:
              - '4000'
              - '3000'
            default: '3000'
            description: The port the server operates on
    tags:
      - name: tag1
        description: this is a tag
        externalDocumentation:
          url: https://npmjs.com
          description: A link to npm
    securitySchemes:
      my_api_key:
        type: apiKey
        name: api_key
        in: header
    security:
      - my_api_key: []
    models:
      - name: "ErrorResponse"
        description: "This is an error"
        contentType: "application/json"
        schema: ${file(models/ErrorResponse.json)}
```

The documentation format for functions, models, security schemes, and other properties remains the same as the original `serverless-openapi-documenter` plugin. Please refer to the extensive examples in the original README for detailed guidance on how to structure your `serverless.yml` file.

### Key Features Supported

*   **Complex Schema Resolution**: Handles nested schemas and resolves internal (`#/definitions/...`), file (`${file(...)}}`), and URL-based references.
*   **OWASP Headers**: Automatically adds OWASP recommended security headers to responses.
*   **CORS Headers**: Automatically adds CORS headers for functions with `cors: true`.
*   **Private Endpoints**: Automatically applies an `x-api-key` security scheme for functions marked with `private: true`.
*   **Inferred Request Bodies**: Generates `requestBody` documentation from a function's `request.schemas` configuration.
*   **Specification Extensions**: Supports custom `x-` fields in most sections of the documentation.
*   **Pre-processing Hooks**: Allows running a custom Python script to generate schemas or configurations before the main tool runs.

### Pre-processing Hooks

You can use the `--pre-hook` argument to specify a Python script that will be executed before the OpenAPI generation begins. This is useful for programmatically generating parts of your `serverless.yml` or the schema files it references.

For example, you could have a script that generates JSON schemas from Pydantic models:

**`generate_schemas.py`:**
```python
# A simplified example to generate schemas from Pydantic models
import json
from pydantic import BaseModel

class MyModel(BaseModel):
    id: int
    name: str

if __name__ == "__main__":
    schema = MyModel.model_json_schema()
    with open("models/MyModel.json", "w") as f:
        json.dump(schema, f, indent=2)
    print("Generated schema for MyModel.")
```

You would then run the tool like this:
```bash
openapi-gen serverless.yml openapi.json --pre-hook generate_schemas.py
```
The `openapi-gen` tool will first execute `generate_schemas.py`, which creates the `models/MyModel.json` file. Then, when the generator processes your `serverless.yml`, it can reference that newly created schema via `${file(models/MyModel.json)}`.

## License

MIT
