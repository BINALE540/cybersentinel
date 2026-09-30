import urllib.request
import ssl

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Content-Security-Policy",
    "X-XSS-Protection"
]

def fetch_headers(target_url):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(
        target_url, 
        headers={'User-Agent': 'CyberSentinel-Auditor/1.0'}
    )
    with urllib.request.urlopen(req, context=ctx, timeout=5) as response:
        return dict(response.info())

def audit_http_headers(url):
    """Check target URL for missing security headers (tries HTTPS, falls back to HTTP)."""
    findings = {"missing": [], "present": {}}
    headers = None

    # Strip existing protocol if present
    clean_url = url.replace("https://", "").replace("http://", "")

    # Try HTTPS first, then fallback to HTTP
    for scheme in ["https://", "http://"]:
        try:
            headers = fetch_headers(scheme + clean_url)
            break
        except Exception:
            continue

    if not headers:
        findings["error"] = "Target unresponsive on both HTTP and HTTPS."
        return findings

    for sec_header in SECURITY_HEADERS:
        found = False
        for h_name, h_val in headers.items():
            if h_name.lower() == sec_header.lower():
                findings["present"][sec_header] = h_val
                found = True
                break
        if not found:
            findings["missing"].append(sec_header)

    return findings