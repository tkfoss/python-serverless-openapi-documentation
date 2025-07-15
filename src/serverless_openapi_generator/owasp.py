import requests
import json

# Fallback data from json/owasp.json
FALLBACK_OWASP_JSON = {
  "last_update_utc": "2024-09-19 21:29:28",
  "headers": [
    { "name": "Cache-Control", "value": "no-store, max-age=0" },
    { "name": "Clear-Site-Data", "value": "\"cache\",\"cookies\",\"storage\"" },
    { "name": "Content-Security-Policy", "value": "default-src 'self'; form-action 'self'; object-src 'none'; frame-ancestors 'none'; upgrade-insecure-requests; block-all-mixed-content" },
    { "name": "Cross-Origin-Embedder-Policy", "value": "require-corp" },
    { "name": "Cross-Origin-Opener-Policy", "value": "same-origin" },
    { "name": "Cross-Origin-Resource-Policy", "value": "same-origin" },
    { "name": "Permissions-Policy", "value": "accelerometer=(), autoplay=(), camera=(), cross-origin-isolated=(), display-capture=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), keyboard-map=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), sync-xhr=(self), usb=(), web-share=(), xr-spatial-tracking=(), clipboard-read=(), clipboard-write=(), gamepad=(), hid=(), idle-detection=(), interest-cohort=(), serial=(), unload=()" },
    { "name": "Referrer-Policy", "value": "no-referrer" },
    { "name": "Strict-Transport-Security", "value": "max-age=31536000; includeSubDomains" },
    { "name": "X-Content-Type-Options", "value": "nosniff" },
    { "name": "X-Frame-Options", "value": "deny" },
    { "name": "X-Permitted-Cross-Domain-Policies", "value": "none" }
  ]
}

DEFAULT_OWASP_HEADERS = {}

# Mapping from camelCase to Pascal-Case for header names
HEADER_NAME_MAP = {
    "cacheControl": "Cache-Control",
    "clearSiteData": "Clear-Site-Data",
    "contentSecurityPolicy": "Content-Security-Policy",
    "crossOriginEmbedderPolicy": "Cross-Origin-Embedder-Policy",
    "crossOriginOpenerPolicy": "Cross-Origin-Opener-Policy",
    "crossOriginResourcePolicy": "Cross-Origin-Resource-Policy",
    "permissionsPolicy": "Permissions-Policy",
    "referrerPolicy": "Referrer-Policy",
    "strictTransportSecurity": "Strict-Transport-Security",
    "xContentTypeOptions": "X-Content-Type-Options",
    "xFrameOptions": "X-Frame-Options",
    "xPermittedCrossDomainPolicies": "X-Permitted-Cross-Domain-Policies",
    "pragma": "Pragma" # Special case for deprecated header
}

def _populate_defaults(owasp_data):
    """Helper to populate the DEFAULT_OWASP_HEADERS from a JSON object."""
    DEFAULT_OWASP_HEADERS.clear()
    for header in owasp_data.get("headers", []):
        DEFAULT_OWASP_HEADERS[header["name"]] = {
            "description": f"OWASP recommended value: {header['value']}",
            "schema": {
                "type": "string",
                "default": header["value"]
            }
        }

def get_latest():
    """
    Fetches the latest OWASP headers, falling back to a local copy on failure.
    """
    try:
        response = requests.get("https://owasp.org/www-project-secure-headers/ci/headers_add.json", timeout=5)
        response.raise_for_status()
        _populate_defaults(response.json())
    except (requests.exceptions.RequestException, json.JSONDecodeError):
        _populate_defaults(FALLBACK_OWASP_JSON)

def get_headers(options):
    """
    Returns a dictionary of selected OWASP headers based on the options.
    """
    if not DEFAULT_OWASP_HEADERS:
        get_latest() # Ensure defaults are populated

    selected_headers = {}
    for option_key, option_value in options.items():
        header_name = HEADER_NAME_MAP.get(option_key)
        if header_name and header_name in DEFAULT_OWASP_HEADERS:
            # Deep copy to avoid modifying the default object
            header_obj = json.loads(json.dumps(DEFAULT_OWASP_HEADERS[header_name]))
            
            if isinstance(option_value, dict) and 'value' in option_value:
                header_obj["schema"]["default"] = option_value["value"]
            
            selected_headers[header_name] = header_obj
        elif header_name: # Handle special cases like deprecated 'Pragma'
             selected_headers[header_name] = {
                "description": "OWASP recommended value: no-cache",
                "schema": { "type": "string", "default": "no-cache" }
             }
             if isinstance(option_value, dict) and 'value' in option_value:
                selected_headers[header_name]["schema"]["default"] = option_value["value"]


    return selected_headers
