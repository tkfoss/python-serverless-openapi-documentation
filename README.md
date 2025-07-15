# OpenAPI Generator for Serverless Configurations

<p>
  <a href="https://www.python.org">
    <img src="https://img.shields.io/badge/python-3.11+-blue.svg">
  </a>
  <a href="https://github.com/tkfoss/python-serverless-openapi-documentation/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/License-MIT-yellow.svg">
  </a>
  <a href="https://github.com/tkfoss/python-serverless-openapi-documentation/actions/workflows/python-ci.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/tkfoss/python-serverless-openapi-documentation/python-ci.yml">
  </a>
  <a href="https://github.com/tkfoss/python-serverless-openapi-documentation/actions/workflows/python-ci.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/tkfoss/python-serverless-openapi-documentation/dependabot%2Fdependabot-updates?label=dependabot">
  </a>
</p>

This tool generates an OpenAPI V3 file from either a `serverless.yml` file or directly from your project's Pydantic models. It is a standalone Python application that can produce a complete OpenAPI specification for your serverless project or any Python application that uses Pydantic for data validation.

## Use

Not yet on PyPi - install from git 

```bash
pip install git+https://github.com/tkfoss/python-serverless-openapi-documentation.git
```

or build and install from source:

```bash
pip install build
python -m build
pip install dist/serverless_openapi_generator-1.0.0-py3-none-any.whl
```

### CLI

The tool now uses a sub-command structure for different stages of the generation process.

#### 1. `generate-schemas`

Generates JSON schemas from your Pydantic models.

```bash
openapi-gen generate-schemas --pydantic-source path/to/your/pydantic/models --output-dir path/to/your/schemas
```

**Arguments:**
*   `--pydantic-source`: (Required) Path to the Pydantic models source directory.
*   `--output-dir`: (Required) Directory to save the generated JSON schemas.

#### 2. `generate-serverless`

Generates a `serverless.yml` file from the JSON schemas and your project's metadata.

```bash
openapi-gen generate-serverless --schema-dir path/to/your/schemas --project-dir path/to/your/project
```

**Arguments:**
*   `--schema-dir`: (Required) Directory containing the JSON schemas generated in the previous step.
*   `--project-dir`: (Optional) Path to the project root directory. This is used to find `pyproject.toml` for project metadata. If not provided, it's inferred from the schema directory.

#### 3. `generate-spec`

Generates the final OpenAPI specification from a `serverless.yml` file.

```bash
openapi-gen generate-spec openapi.json --serverless-yml-path path/to/your/serverless.yml
```

**Arguments:**
*   `output_file_path`: (Required) Path to the output OpenAPI JSON file.
*   `--serverless-yml-path`: (Required) Path to the `serverless.yml` file.
*   `--openApiVersion`: The OpenAPI version to generate for. Default: `3.0.3`.
*   `--validate`: Validate the generated OpenAPI spec.

### Validation

This tool also includes a script to validate an OpenAPI specification file against the OpenAPI 3.0.3 specification.

**To Run:**
```bash
openapi-validate path/to/your/openapi.json
```

You can also use the `--validate` flag with the `generate-spec` command to automatically validate the generated spec.

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
*   **Automatic Tagging**: If no tags are provided for an API operation, a tag is automatically generated from the function's handler path. For example, a handler at `src.api.users.handler` will be tagged with `users`. This helps in organizing the generated documentation.

### Pydantic-based Workflow

This tool can automatically generate JSON schemas from your Pydantic models and create a complete OpenAPI specification. This is particularly useful for projects that do not use the Serverless Framework.

The workflow is as follows:

1.  **Generate Schemas:** Use the `generate-schemas` command to create JSON schemas from your Pydantic models.
2.  **Generate `serverless.yml`:** Use the `generate-serverless` command to create a `serverless.yml` file. This command uses the schemas from the previous step and project metadata from your `pyproject.toml` file.
3.  **Generate OpenAPI Spec:** Use the `generate-spec` command with the newly created `serverless.yml` to generate the final `openapi.json`.

> **Note:** For the Pydantic schema generation to work correctly, the Python environment where you run `openapi-gen` must have all the dependencies of your project installed. This is because the tool needs to import your Pydantic models to generate the schemas.

## License

MIT
