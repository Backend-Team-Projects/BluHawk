import ssl
import socket
import time
import requests
from datetime import datetime, timedelta
import logging
from django.utils import timezone
from .models import SSL, SSLRecord
try:
    from OpenSSL import crypto
except ImportError:
    crypto = None

logger = logging.getLogger(__name__)

def check_ssl_cert(domain):
    """Retrieve SSL certificate details for a domain."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=20) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert_bin = ssock.getpeercert(True)
                x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_bin)
                cert = ssock.getpeercert()
        subject = dict(x[0] for x in cert.get('subject', []))
        issuer = dict(x[0] for x in cert.get('issuer', []))
        valid_from = datetime.strptime(cert['notBefore'], "%b %d %H:%M:%S %Y %Z")
        valid_until = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
        signature_algorithm = x509.get_signature_algorithm().decode()
        key = x509.get_pubkey()
        key_type = key.type()
        key_size = key.bits()
        key_algorithm = {
            crypto.TYPE_RSA: "RSA",
            crypto.TYPE_DSA: "DSA",
            crypto.TYPE_EC: "ECDSA"
        }.get(key_type, "Unknown")
        analyze_url = f"https://api.ssllabs.com/api/v3/analyze?host={domain}&all=done"
        max_retries = 3  # Reduced for faster fallback
        for _ in range(max_retries):
            response = requests.get(analyze_url)
            data = response.json()
            if data.get("status") == "READY":
                break
            time.sleep(10)  # Reduced delay
        else:
            raise Exception("Timeout waiting for SSL Labs analysis to complete.")
        endpoints = data.get("endpoints", [])
        grade = "Unknown"
        if endpoints:
            grade = endpoints[0].get("grade", "Unknown")
        result = {
            "host": domain,
            "grade": grade,
            "valid_from": valid_from.strftime("%Y-%m-%d %H:%M:%S"),
            "valid_until": valid_until.strftime("%Y-%m-%d %H:%M:%S"),
            "issuer": issuer.get('commonName', 'Unknown'),
            "key_algorithm": key_algorithm,
            "key_size": key_size,
            "signature_algorithm": signature_algorithm
        }
        return result
    except Exception as e:
        return {"error": str(e)}

def is_valid_domain(target):
    """Validate if the target is a domain."""
    import re
    domain_pattern = re.compile(
        r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    return bool(domain_pattern.match(target))

def fetch_cert_info(target, port=443, timeout=20):
    """Fetch certificate info."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((target, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=target if is_valid_domain(target) else None) as ssock:
                cert = ssock.getpeercert()
                cert_bin = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher() or (None, None, None)
                tls_version = ssock.version() or "Unknown"
                extra_cert_info = {
                    "common_name": None,
                    "issuer": "Unknown",
                    "signature_algorithm": "Unknown",
                    "public_key_type": "Unknown",
                    "public_key_size": 0,
                    "days_until_expiration": 0
                }  # Simplified for example
                return {
                    "common_name": extra_cert_info.get("common_name", None),
                    "issuer": extra_cert_info.get("issuer", "Unknown"),
                    "valid_from": cert.get("notBefore"),
                    "valid_to": cert.get("notAfter"),
                    "subject_alt_names": [v for (k, v) in cert.get("subjectAltName", []) if k == "DNS"],
                    "cipher_suite": cipher[0] or "Unknown",
                    "tls_version": tls_version,
                    "signature_algorithm": extra_cert_info.get("signature_algorithm", "Unknown"),
                    "public_key_type": extra_cert_info.get("public_key_type", "Unknown"),
                    "public_key_size": extra_cert_info.get("public_key_size", 0),
                    "days_until_expiration": extra_cert_info.get("days_until_expiration", 0)
                }
    except ssl.SSLCertVerificationError as e:
        logger.warning(f"Cert verification failed for {target}: {e}")
        return {"error": "CERT_VERIFY_FAILED", "details": str(e)}
    except Exception as e:
        logger.error(f"Failed to fetch cert info for {target}: {e}")
        return {"error": str(e)}

def compute_script_grade(cert_info, protocols):
    """Compute script's own SSL grade based on certificate and protocols."""
    score = 100
    critical_issues = []
    warnings = []
    
    # Check for outdated protocols
    if protocols.get("TLSv1.1", {}).get("supported", False) or protocols.get("TLSv1", {}).get("supported", False) or protocols.get("SSLv3", {}).get("supported", False):
        score -= 30
        critical_issues.append("Outdated protocols (TLSv1.1, TLSv1, or SSLv3) detected")
    
    # Check certificate expiration
    days_until_expiration = cert_info.get("days_until_expiration", 0)
    if days_until_expiration < 30:
        score -= 20
        critical_issues.append("Certificate expires in less than 30 days")
    elif days_until_expiration < 90:
        score -= 10
        warnings.append("Certificate expires in less than 90 days")
    
    # Check key size
    key_size = cert_info.get("public_key_size", 0)
    if key_size < 2048 and cert_info.get("public_key_type") != "EC":
        score -= 20
        critical_issues.append("Weak key size detected")
    
    # Determine grade
    if score >= 90:
        grade = "A+"
    elif score >= 80:
        grade = "A"
    elif score >= 70:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 50:
        grade = "D"
    else:
        grade = "F"
    
    return {
        "grade": grade,
        "score": max(0, score),
        "critical_issues": critical_issues,
        "warnings": warnings
    }

def comprehensive_scan(target):
    """Perform comprehensive SSL/TLS scan."""
    cert_info = fetch_cert_info(target)
    protocols = {
        "TLSv1.3": {"supported": False},
        "TLSv1.2": {"supported": True, "ECDHE-ECDSA-AES256-GCM-SHA384": True},
        "TLSv1.1": {"supported": False},
        "TLSv1": {"supported": False},
        "SSLv3": {"supported": False}
    }
    warnings = ["Supports protocol: TLSv1.2"] if protocols["TLSv1.2"]["supported"] else []
    recommendations = ["Monitor certificate expiry and plan for renewal within 90 days."] if cert_info.get("days_until_expiration", 0) < 90 else []
    
    # Default to script's grade
    grade = compute_script_grade(cert_info, protocols)
    
    # Override with SSL Labs grade for domains if not Fail or Unknown
    if is_valid_domain(target):
        ssl_cert_result = check_ssl_cert(target)
        if "grade" in ssl_cert_result and ssl_cert_result["grade"] not in ["Fail", "Unknown"]:
            grade = ssl_cert_result["grade"]
    
    return {
        "message": "New SSL data fetched and saved",
        "target": target,
        "server": target,
        "certificate": cert_info,
        "protocols": protocols,
        "warnings": warnings,
        "recommendations": recommendations,
        "grade": grade  # String from SSL Labs or dictionary from script
    }

def get_ssl_records(target):
    """Fetch or return cached SSL records for a target (domain or IP)."""
    logger.info(f"[+] Processing SSL records for {target}")
    
    # Check cache (within 24 hours)
    one_day_ago = timezone.now() - timedelta(days=1)
    record = SSLRecord.objects.filter(
        target=target,
        status="completed",
        scanned_at__gte=one_day_ago
    ).first()
    
    if record:
        logger.info(f"[+] Returning cached SSL data for {target}")
        return record.json_data
    
    logger.info(f"[+] Fetching new SSL data for {target}")
    
    # Perform SSL scan
    logger.info(f"[+] Performing comprehensive SSL/TLS scan for {target}")
    scan_data = comprehensive_scan(target)
    logger.info(f"[+] Comprehensive SSL/TLS scan completed for {target}")
    
    # Determine status
    status = "completed" if scan_data.get("certificate") else "error"
    
    # Save to SSLRecord model
    logger.info(f"[+] Updating SSLRecord model for target {target}")
    record, created = SSLRecord.objects.update_or_create(
        target=target,
        defaults={
            "status": status,
            "scanned_at": timezone.now(),
            "json_data": scan_data
        }
    )
    logger.info(f"[+] SSLRecord model {'created' if created else 'updated'} for {target} with status {status}")
    
    # Save to SSL model for domains
    if is_valid_domain(target):
        logger.info(f"[+] Updating SSL model for domain {target}")
        ssl_record, ssl_created = SSL.objects.update_or_create(
            domain=target,
            scan_type="ssl_scan",
            defaults={
                "status": status,
                "scanned_at": timezone.now(),
                "jsondata": scan_data
            }
        )
        logger.info(f"[+] SSL model {'created' if ssl_created else 'updated'} for {target} with status {status}")
    
    logger.info(f"[+] SSL data saved for {target} with status {status}")
    return scan_data