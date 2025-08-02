import subprocess
import json
import ipaddress
from urllib.parse import urlparse, urlunparse
import re
from BluHawk.utils import log_exception

def _handle_target_url(target_url):
    """Improved URL validation and normalization for various target types"""
    try:
        # Handle raw IP addresses without scheme
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target_url):
            target_url = f"http://{target_url}"
        elif re.match(r"^[a-fA-F0-9:]+$", target_url):  # IPv6 pattern
            target_url = f"http://[{target_url}]"

        parsed = urlparse(target_url)
        
        # Add scheme if missing
        if not parsed.scheme:
            parsed = parsed._replace(scheme="https")
        
        # Handle netloc/path confusion
        if not parsed.netloc:
            if "/" in parsed.path:
                netloc, *path_parts = parsed.path.split("/", 1)
                parsed = parsed._replace(netloc=netloc, path=path_parts[0] if path_parts else "")
            else:
                parsed = parsed._replace(netloc=parsed.path, path="")

        # Reconstruct normalized URL
        normalized_url = urlunparse((
            parsed.scheme,
            parsed.netloc.lower().strip("[]"),  # Handle IPv6 brackets
            parsed.path,
            parsed.params,
            parsed.query,
            parsed.fragment
        ))

        # Validate network location
        host = parsed.netloc.split(":")[0]
        port = parsed.port
        
        try:
            # Validate IP addresses (both IPv4 and IPv6)
            ipaddress.ip_address(host)
        except ValueError:
            # Validate domain format if not IP
            domain_pattern = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*$"
            if not re.match(domain_pattern, host):
                return {"status": "error", "message": "Invalid domain/IP format"}, None

        # Validate credentials
        if "@" in parsed.netloc:
            return {"status": "error", "message": "URLs with credentials are not supported"}, None

        # Validate port range
        if port and not (1 <= port <= 65535):
            return {"status": "error", "message": "Invalid port number"}, None

        return None, (normalized_url, parsed)

    except ValueError as e:
        return {"status": "error", "message": f"Invalid URL format: {str(e)}"}, None

def get_wapiti_report(target_url, **kwargs):
    """Universal Wapiti scanner supporting IPs, domains, and specific URLs"""
    url_error, normalized_data = _handle_target_url(target_url)
    if url_error:
        return url_error
    
    target_url, parsed = normalized_data
    print(f"Scanning target: {target_url}...")
    
    try:
        # wapiti_args = [
        #     "wapiti",
        #     "-u", target_url,
        #     "-f", "json",
        #     "-o", "/dev/stdout",
        #     "--scope", "folder",
        #     "--max-links", "1000"
        # ]

        wapiti_args = [
            "wapiti",
            "-u", target_url,
            "-f", "json",
            "-o", "/dev/stdout",
            "--scope", "folder",
            "--max-links", "10",
            # "--max-depth", "3",        # Limit crawl depth
            # "--max-links-per-page", "10",
            # "--timeout", "5",          # Stop waiting on slow responses
            # "--delay", "0"             # No delay between requests
        ]

        result = subprocess.run(
            wapiti_args,
            capture_output=True,
            text=True,
            timeout=1500
        )

        # Handle scan errors
        if result.returncode != 0:
            error_msg = result.stderr or "Unknown error occurred during scan"
            error_mapping = {
                "Name or service not known": "DNS resolution failed",
                "Connection refused": "Service unavailable",
                "timed out": "Connection timeout",
                "SSL handshake": "SSL/TLS error"
            }
            for pattern, message in error_mapping.items():
                if pattern in error_msg:
                    error_msg = message
                    break
            print(f"Scan failed: {error_msg}")
            return {'status': 'error', 'message': f"Scan failed: {error_msg}"}

        try:
            json_str = result.stdout[result.stdout.index('{'):result.stdout.rindex('}')+1]
            scan_data = json.loads(json_str)
            
            scan_data['target_info'] = {
                'normalized_url': target_url,
                'host_type': "IP" if parsed.netloc.split(":")[0].replace('.', '').isdigit() else "Domain",
                'port': parsed.port or 443 if parsed.scheme == "https" else 80,
                'scheme': parsed.scheme
            }

            # Deduplicate vulnerabilities
            unique_vulns = {}
            for vuln_type, entries in scan_data.get("vulnerabilities", {}).items():
                unique_entries = {json.dumps(e, sort_keys=True) for e in entries}
                unique_vulns[vuln_type] = [json.loads(e) for e in unique_entries]

            return {
                'status': 'success',
                'data': {
                    'vulnerabilities': unique_vulns,
                    'target_info': scan_data['target_info'],
                    'stats': scan_data.get("scan", {})
                }
            }

        except (ValueError, json.JSONDecodeError) as e:
            log_exception(e)
            return {'status': 'error', 'message': f"Output parsing failed: {str(e)}"}

    except subprocess.TimeoutExpired:
        print("Scan timed out after 10 minutes")
        return {'status': 'error', 'message': "Scan timed out after 10 minutes"}
    except Exception as e:
        print("error ", e)
        log_exception(e)
        return {'status': 'error', 'message': f"Unexpected error: {str(e)}"}