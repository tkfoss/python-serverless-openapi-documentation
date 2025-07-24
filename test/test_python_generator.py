from pathlib import Path
from src.serverless_openapi_generator.openapi_generator import PythonBasedGenerator

def test_generate_from_python_with_docs():
    generator = PythonBasedGenerator()
    test_project_dir = Path("test/tmp_project")
    spec = generator.generate_from_python(test_project_dir, endpoint_pattern="**/my_endpoint/handler.py", docs_pattern="**/my_endpoint/docs.py")

    assert "openapi" in spec
    assert "info" in spec
    assert "paths" in spec
    assert "/my_endpoint" in spec["paths"]
    assert "post" in spec["paths"]["/my_endpoint"]

    operation = spec["paths"]["/my_endpoint"]["post"]
    assert operation["summary"] == "My Test Endpoint"
    assert operation["description"] == "A more detailed description of my test endpoint."
    assert operation["tags"] == ["tests"]
    assert "200" in operation["responses"]
    assert "400" in operation["responses"]
    assert operation["responses"]["200"]["description"] == "A successful response."
    assert operation["responses"]["400"]["description"] == "A bad request."

def test_generate_html():
    import json
    import subprocess
    from pathlib import Path

    spec = {
        "openapi": "3.0.0",
        "info": {
            "title": "Test API",
            "version": "1.0.0"
        },
        "paths": {}
    }
    spec_file = Path("test/tmp_spec.json")
    with open(spec_file, "w") as f:
        json.dump(spec, f)

    html_file = Path("test/tmp_docs.html")
    
    subprocess.run(
        ["openapi-gen", "generate-html", str(spec_file), str(html_file)],
        check=True
    )

    assert html_file.exists()

    spec_file.unlink()
    html_file.unlink()
