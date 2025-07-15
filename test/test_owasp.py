import requests_mock
import json
import pytest

# It's better to import the module we are testing
from serverless_openapi_generator import owasp

# Load the test data
with open('test/json/newOWASP.json', 'r') as f:
    NEW_OWASP_JSON = json.load(f)


def test_get_latest_fallback(requests_mock):
    # Mock a 404 response
    requests_mock.get("https://owasp.org/www-project-secure-headers/ci/headers_add.json", status_code=404)
    
    owasp.get_latest()
    
    # Check if it fell back to the local data
    assert "Permissions-Policy" in owasp.DEFAULT_OWASP_HEADERS
    assert len(owasp.DEFAULT_OWASP_HEADERS) == 12
    assert owasp.DEFAULT_OWASP_HEADERS["Permissions-Policy"]["schema"]["default"] == "accelerometer=(), autoplay=(), camera=(), cross-origin-isolated=(), display-capture=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), keyboard-map=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), sync-xhr=(self), usb=(), web-share=(), xr-spatial-tracking=(), clipboard-read=(), clipboard-write=(), gamepad=(), hid=(), idle-detection=(), interest-cohort=(), serial=(), unload=()"


def test_get_latest_success(requests_mock):
    # Mock a 200 response with new data
    requests_mock.get("https://owasp.org/www-project-secure-headers/ci/headers_add.json", json=NEW_OWASP_JSON)

    owasp.get_latest()

    assert "Cross-Origin-Embedder-Policy" in owasp.DEFAULT_OWASP_HEADERS
    assert len(owasp.DEFAULT_OWASP_HEADERS) == 12


def test_adds_new_properties_from_release(requests_mock):
    new_owasp_added = json.loads(json.dumps(NEW_OWASP_JSON))
    new_owasp_added["headers"].append({"name": "x-added", "value": "true"})
    requests_mock.get("https://owasp.org/www-project-secure-headers/ci/headers_add.json", json=new_owasp_added)

    owasp.get_latest()

    assert "x-added" in owasp.DEFAULT_OWASP_HEADERS
    assert owasp.DEFAULT_OWASP_HEADERS["x-added"]["schema"]["default"] == "true"
    assert len(owasp.DEFAULT_OWASP_HEADERS) == 13


def test_get_headers_selection():
    header_options = {"cacheControl": True, "xFrameOptions": True}
    headers = owasp.get_headers(header_options)
    assert len(headers) == 2
    assert "Cache-Control" in headers
    assert "X-Frame-Options" in headers


def test_get_headers_value_override():
    header_options = {
        "referrerPolicy": {"value": "strict-origin-when-cross-origin"},
        "crossOriginOpenerPolicy": {"value": "unsafe-none"}
    }
    headers = owasp.get_headers(header_options)
    assert len(headers) == 2
    assert headers["Referrer-Policy"]["schema"]["default"] == "strict-origin-when-cross-origin"
    assert headers["Cross-Origin-Opener-Policy"]["schema"]["default"] == "unsafe-none"


def test_get_headers_deprecated_pragma():
    header_options = {"pragma": {"value": "true"}}
    headers = owasp.get_headers(header_options)
    assert len(headers) == 1
    assert "Pragma" in headers
    assert headers["Pragma"]["schema"]["default"] == "true"
