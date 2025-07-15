import unittest
import requests_mock
import json

# It's better to import the module we are testing
from src import owasp

# Load the test data
with open('test/json/newOWASP.json', 'r') as f:
    NEW_OWASP_JSON = json.load(f)

class TestOwasp(unittest.TestCase):

    @requests_mock.Mocker()
    def test_get_latest_fallback(self, m):
        # Mock a 404 response
        m.get("https://owasp.org/www-project-secure-headers/ci/headers_add.json", status_code=404)
        
        owasp.get_latest()
        
        # Check if it fell back to the local data
        self.assertIn("Permissions-Policy", owasp.DEFAULT_OWASP_HEADERS)
        self.assertEqual(len(owasp.DEFAULT_OWASP_HEADERS), 12)
        self.assertEqual(owasp.DEFAULT_OWASP_HEADERS["Permissions-Policy"]["schema"]["default"], "accelerometer=(), autoplay=(), camera=(), cross-origin-isolated=(), display-capture=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), keyboard-map=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), sync-xhr=(self), usb=(), web-share=(), xr-spatial-tracking=(), clipboard-read=(), clipboard-write=(), gamepad=(), hid=(), idle-detection=(), interest-cohort=(), serial=(), unload=()")

    @requests_mock.Mocker()
    def test_get_latest_success(self, m):
        # Mock a 200 response with new data
        m.get("https://owasp.org/www-project-secure-headers/ci/headers_add.json", json=NEW_OWASP_JSON)

        owasp.get_latest()

        self.assertIn("Cross-Origin-Embedder-Policy", owasp.DEFAULT_OWASP_HEADERS)
        self.assertEqual(len(owasp.DEFAULT_OWASP_HEADERS), 12)

    @requests_mock.Mocker()
    def test_adds_new_properties_from_release(self, m):
        new_owasp_added = json.loads(json.dumps(NEW_OWASP_JSON))
        new_owasp_added["headers"].append({"name": "x-added", "value": "true"})
        m.get("https://owasp.org/www-project-secure-headers/ci/headers_add.json", json=new_owasp_added)

        owasp.get_latest()

        self.assertIn("x-added", owasp.DEFAULT_OWASP_HEADERS)
        self.assertEqual(owasp.DEFAULT_OWASP_HEADERS["x-added"]["schema"]["default"], "true")
        self.assertEqual(len(owasp.DEFAULT_OWASP_HEADERS), 13)

    def test_get_headers_selection(self):
        header_options = {"cacheControl": True, "xFrameOptions": True}
        headers = owasp.get_headers(header_options)
        self.assertEqual(len(headers), 2)
        self.assertIn("Cache-Control", headers)
        self.assertIn("X-Frame-Options", headers)

    def test_get_headers_value_override(self):
        header_options = {
            "referrerPolicy": {"value": "strict-origin-when-cross-origin"},
            "crossOriginOpenerPolicy": {"value": "unsafe-none"}
        }
        headers = owasp.get_headers(header_options)
        self.assertEqual(len(headers), 2)
        self.assertEqual(headers["Referrer-Policy"]["schema"]["default"], "strict-origin-when-cross-origin")
        self.assertEqual(headers["Cross-Origin-Opener-Policy"]["schema"]["default"], "unsafe-none")

    def test_get_headers_deprecated_pragma(self):
        header_options = {"pragma": {"value": "true"}}
        headers = owasp.get_headers(header_options)
        self.assertEqual(len(headers), 1)
        self.assertIn("Pragma", headers)
        self.assertEqual(headers["Pragma"]["schema"]["default"], "true")

if __name__ == '__main__':
    unittest.main()
