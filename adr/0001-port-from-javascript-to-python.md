# ADR 0001: Port Core Logic from JavaScript to a Standalone Python Tool

## Status

Accepted

## Context

The project was originally a `serverless-openapi-documenter`, a plugin for the Serverless Framework written in Node.js. The primary goal was to generate OpenAPI v3 documentation from `serverless.yml` configurations.

The objective of this task was to port the core functionality to a standalone command-line tool written in Python, removing the direct dependency on the Serverless Framework's plugin architecture while maintaining feature parity.

## Decision

We decided to perform a full port of the logic to Python, creating a new modular structure and a corresponding test suite. The key decisions were:

1.  **Standalone Python CLI**: The new tool is a Python script (`src/openapi_generator.py`) that can be executed from the command line, taking a `serverless.yml` file as input. This decouples it from the Node.js ecosystem and the Serverless Framework's internal workings.

2.  **Dependency Mapping**: Key Node.js libraries were mapped to Python equivalents:
    *   `js-yaml` -> `PyYAML`
    *   `chalk` -> (Not implemented, as it's for colored CLI output)
    *   `@apidevtools/json-schema-ref-parser` -> `referencing`
    *   `openapi-to-postmanv2` -> (De-scoped)
    *   `@redocly/openapi-core` for validation -> (De-scoped)

3.  **Modular Architecture**: The original project's structure was mirrored in Python to maintain a clear separation of concerns. This resulted in:
    *   `src/openapi_generator.py`: The main script and `DefinitionGenerator` class.
    *   `src/owasp.py`: A module to handle the fetching and processing of OWASP-recommended security headers.
    *   `src/schema_handler.py`: A dedicated class for complex schema processing, including standardization of different model formats and schema reference bundling.

4.  **Schema Dereferencing**: After initial attempts with a manual recursive resolver proved difficult, the `referencing` library was chosen as the modern and correct tool for handling JSON schema references. The final implementation explicitly registers sub-schemas found in `definitions` blocks with a `Registry`, allowing the resolver to correctly bundle complex, internally-referenced schemas.

5.  **Test Suite Migration**: The original JavaScript tests (`.spec.js`) could not be run directly. Instead, a new Python test suite was created using the `unittest` framework.
    *   The original test *data* (`serverless.yml` files, JSON schemas) was reused.
    *   An end-to-end test (`test/test_generator.py`) was created to validate the overall output against a known-good baseline.
    *   Unit tests for the `owasp` and `schemaHandler` modules were ported to Python (`test/test_owasp.py`, `test/test_schema_handler.py`) to ensure detailed feature parity.

## Consequences

*   The project now consists of a standalone Python tool that can be run in any environment with Python and its dependencies installed.
*   The direct plugin integration with the Serverless Framework is removed, making the tool more versatile.
*   The core features, including OWASP header generation, complex schema handling, and automatic handling of `private` endpoints and `request.schemas`, have been successfully ported and are verified by a robust test suite.
*   The project's dependencies are now managed via Python tools (e.g., `uv` or `pip`).
*   Generation of Postman collections and validation using Redocly rules were considered out of scope for this initial port, but could be added in the future.
