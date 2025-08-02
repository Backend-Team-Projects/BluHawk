import socket
import ssl
import logging
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, rsa, dsa
# import requests  # Commented out as SSL Labs API is no longer used
# try:
#     from OpenSSL import crypto  # Commented out as pyOpenSSL is no longer used
# except ImportError:
#     crypto = None

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

CIPHERS_BY_PROTOCOL = {
    "TLSv1.3": [
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_128_GCM_SHA256"
    ],
    "TLSv1.2": [
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        "ECDHE-RSA-CHACHA20-POLY1305",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "DHE-RSA-AES256-GCM-SHA384",
        "DHE-RSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES256-SHA384",
        "ECDHE-RSA-AES256-SHA384",
        "ECDHE-ECDSA-AES128-SHA256",
        "ECDHE-RSA-AES128-SHA256",
        "AES256-SHA",
        "AES128-SHA",
        "CAMELLIA256-SHA",
        "CAMELLIA128-SHA",
        "DES-CBC3-SHA",
        "RC4-SHA",
        "NULL-SHA",
        "IDEA-CBC-SHA",
        "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
    ],
    "TLSv1.1": ["AES128-SHA", "RC4-SHA", "DES-CBC3-SHA", "IDEA-CBC-SHA"],
    "TLSv1": ["AES128-SHA", "RC4-SHA", "DES-CBC3-SHA", "IDEA-CBC-SHA"],
    "SSLv3": ["RC4-SHA", "DES-CBC3-SHA"]
}

INSECURE_CIPHERS = ["RC4", "NULL", "ANON", "EXP", "IDEA", "DES", "3DES", "MD5"]
WEAK_CIPHERS = ["CBC", "CAMELLIA", "SEED", "AES128", "SHA1", "SHA224"]
MODERN_CIPHERS = ["AES256-GCM", "CHACHA20", "AES128-GCM"]

# Use modern SSLContext creation
PROTOCOL_TLS_MAP = {
    "TLSv1.3": ssl.PROTOCOL_TLS_CLIENT,
    "TLSv1.2": ssl.PROTOCOL_TLS_CLIENT,
    "TLSv1.1": ssl.PROTOCOL_TLS_CLIENT,
    "TLSv1": ssl.PROTOCOL_TLS_CLIENT,
    "SSLv3": None  # SSLv3 is insecure and disabled
}

def test_protocol_cipher(host, port, protocol, cipher):
    """Test if a specific protocol and cipher combination is supported."""
    proto_const = PROTOCOL_TLS_MAP.get(protocol)
    if not proto_const:
        return False
    try:
        ctx = ssl.SSLContext(proto_const)
        ctx.options |= ssl.OP_NO_COMPRESSION
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        if protocol == "TLSv1.3":
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        elif protocol == "TLSv1.2":
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        elif protocol == "TLSv1.1":
            ctx.minimum_version = ssl.TLSVersion.TLSv1_1
            ctx.maximum_version = ssl.TLSVersion.TLSv1_1
        elif protocol == "TLSv1":
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.maximum_version = ssl.TLSVersion.TLSv1
        ctx.set_ciphers(cipher)
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except Exception:
        return False

def parse_cert_bin(cert_bin):
    """Parse binary certificate for comprehensive SSL scan."""
    try:
        cert = x509.load_der_x509_certificate(cert_bin, backend=default_backend())
        pk = cert.public_key()
        key_type = "Unknown"
        key_size = 0
        if isinstance(pk, rsa.RSAPublicKey):
            key_type = "RSA"
            key_size = pk.key_size
        elif isinstance(pk, ec.EllipticCurvePublicKey):
            key_type = "EC"
            key_size = pk.curve.key_size
        elif isinstance(pk, dsa.DSAPublicKey):
            key_type = "DSA"
            key_size = pk.key_size
        sig_algo = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "Unknown"
        expiry_date = cert.not_valid_after_utc
        valid_from = cert.not_valid_before_utc
        current_date = datetime.now(timezone.utc)
        expiry_days = (expiry_date - current_date).days
        common_name = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        common_name = common_name[0].value if common_name else None
        issuer_common_name = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        issuer_common_name = issuer_common_name[0].value if issuer_common_name else "Unknown"
        return {
            "common_name": common_name,
            "issuer": issuer_common_name,
            "signature_algorithm": sig_algo,
            "public_key_type": key_type,
            "public_key_size": key_size,
            "days_until_expiration": expiry_days,
            "valid_from": valid_from.isoformat(),
            "valid_to": expiry_date.isoformat()
        }
    except Exception as e:
        logger.warning(f"Cert parse failed: {e}")
        return {}

def fetch_cert_info(host, port=443, timeout=20):
    """Fetch certificate info for comprehensive SSL scan."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                cert = ssock.getpeercert()
                cipher = ssock.cipher() or (None, None, None)
                tls_version = ssock.version() or "Unknown"
                extra_cert_info = parse_cert_bin(cert_bin)
                return {
                    "common_name": extra_cert_info.get("common_name"),
                    "issuer": extra_cert_info.get("issuer"),
                    "valid_from": extra_cert_info.get("valid_from"),
                    "valid_to": extra_cert_info.get("valid_to"),
                    "subject_alt_names": [v for (k, v) in cert.get("subjectAltName", []) if k == "DNS"],
                    "cipher_suite": cipher[0] or "Unknown",
                    "tls_version": tls_version,
                    **extra_cert_info
                }
    except Exception as e:
        logger.error(f"Failed to fetch cert info: {e}")
        return {"error": str(e)}

def is_modern_cipher(cipher):
    """Check if a cipher is considered modern."""
    cipher = cipher.upper()
    return any(m in cipher for m in MODERN_CIPHERS)

def count_weak_ciphers(protocols):
    """Count the number of weak ciphers supported."""
    weak_cipher_count = 0
    for proto, ciphers in protocols.items():
        for cipher, supported in ciphers.items():
            if supported and cipher != "supported" and any(w in cipher.upper() for w in WEAK_CIPHERS):
                weak_cipher_count += 1
    return weak_cipher_count

def estimate_ssl_grade(cert, protos):
    """Estimate SSL grade for comprehensive scan."""
    score = 100
    issues = []
    critical_issues = []
    tls_version = cert.get("tls_version", "")
    negotiated_cipher = cert.get("cipher_suite", "").upper()
    key_type = cert.get("public_key_type", "")
    key_size = cert.get("public_key_size", 0)
    days_until_expiration = cert.get("days_until_expiration", 0)
    sig = cert.get("signature_algorithm", "").lower()

    # Penalize non-TLSv1.3 usage
    if tls_version != "TLSv1.3":
        score -= 10
        issues.append("TLS 1.3 recommended")
    else:
        score += 5  # Reward TLSv1.3 usage

    # Penalize non-modern ciphers
    if not is_modern_cipher(negotiated_cipher):
        score -= 10
        issues.append("Non-modern cipher used")

    # Penalize insecure ciphers
    if any(w in negotiated_cipher for w in INSECURE_CIPHERS):
        score -= 30
        critical_issues.append(f"Insecure cipher: {negotiated_cipher}")

    # Penalize weak key sizes
    if key_type == "RSA" and key_size < 2048:
        score -= 40
        critical_issues.append("RSA key too small")
    if key_type == "EC" and key_size < 256:
        score -= 40
        critical_issues.append("EC key too small")

    # Penalize certificate expiration
    if days_until_expiration < 0:
        score = 0
        critical_issues.append("Certificate expired")
    elif days_until_expiration < 30:
        score -= 20
        issues.append(f"Certificate expires in {days_until_expiration} days")

    # Penalize weak signature algorithms
    if "sha1" in sig or "md5" in sig:
        score -= 30
        critical_issues.append("Weak signature algorithm")

    # Penalize based on number of weak ciphers supported
    weak_cipher_count = count_weak_ciphers(protos)
    if weak_cipher_count > 0:
        score -= weak_cipher_count * 5  # Deduct 5 points per weak cipher
        issues.append(f"{weak_cipher_count} weak ciphers supported")

    # Adjust grading thresholds
    if score >= 95:
        grade = "A+"
    elif score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"

    return {
        "grade": grade,
        "score": max(0, min(score, 100)),
        "critical_issues": critical_issues,
        "warnings": issues
    }

def comprehensive_scan(host, port=443):
    """Perform a comprehensive SSL/TLS scan."""
    print(f"[+] Performing comprehensive SSL/TLS scan for {host}")
    logger.debug(f"Performing comprehensive SSL/TLS scan for {host}")
    protocols = {}
    warnings = []
    recommendations = []
    for proto, cipher_list in CIPHERS_BY_PROTOCOL.items():
        protocols[proto] = {}
        any_ok = False
        for c in cipher_list:
            ok = test_protocol_cipher(host, port, proto, c)
            protocols[proto][c] = ok
            if ok:
                c_upper = c.upper()
                if any(w in c_upper for w in INSECURE_CIPHERS):
                    warnings.append(f"Insecure cipher supported: {proto} {c}")
                    recommendations.append(f"Disable insecure cipher: {c}")
                elif any(w in c_upper for w in WEAK_CIPHERS):
                    warnings.append(f"Weak cipher supported: {proto} {c}")
                    recommendations.append(f"Disable weak cipher: {c}")
                any_ok = True
        protocols[proto]["supported"] = any_ok
        if any_ok and proto in ["SSLv3", "TLSv1", "TLSv1.1"]:
            warnings.append(f"Insecure protocol supported: {proto}")
            recommendations.append(f"Disable {proto} in server configuration")
    cert = fetch_cert_info(host, port)
    if "error" in cert:
        print(f"[-] Comprehensive SSL scan failed for {host}: {cert['error']}")
        logger.error(f"Comprehensive SSL scan failed for {host}: {cert['error']}")
        return {"server": host, "error": cert["error"]}
    grade = estimate_ssl_grade(cert, protocols)
    result = {
        "server": host,
        "certificate": cert,
        "protocols": protocols,
        "warnings": warnings,
        "recommendations": list(dict.fromkeys(recommendations)),
        "grade": grade
    }
    print(f"[+] Comprehensive SSL/TLS scan completed for {host}")
    logger.debug(f"Comprehensive SSL/TLS scan completed for {host}")
    return result

# Commented out SSL Labs API function as per senior's instructions
# def check_ssl_cert(domain):
#     """Retrieve SSL certificate details for a domain using SSL Labs API."""
#     print(f"[+] Fetching SSL certificate details for {domain} via SSL Labs API")
#     logger.debug(f"Fetching SSL certificate details for {domain} via SSL Labs API")
#     try:
#         context = ssl.create_default_context()
#         with socket.create_connection((domain, 443), timeout=20) as sock:
#             with context.wrap_socket(sock, server_hostname=domain) as ssock:
#                 cert_bin = ssock.getpeercert(True)
#                 x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_bin)
#                 cert = ssock.getpeercert()
#         subject = dict(x[0] for x in cert.get('subject', []))
#         issuer = dict(x[0] for x in cert.get('issuer', []))
#         valid_from = datetime.strptime(cert['notBefore'], "%b %d %H:%M:%S %Y %Z")
#         valid_until = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
#         signature_algorithm = x509.get_signature_algorithm().decode()
#         key = x509.get_pubkey()
#         key_type = key.type()
#         key_algorithm = {
#             crypto.TYPE_RSA: "RSA",
#             crypto.TYPE_DSA: "DSA",
#             crypto.TYPE_EC: "ECDSA"
#         }.get(key_type, "Unknown")
#         key_size = key.bits()
#         analyze_url = f"https://api.ssllabs.com/api/v3/analyze?host={domain}&all=done"
#         max_retries = 3
#         for attempt in range(max_retries):
#             try:
#                 response = requests.get(analyze_url, timeout=10)
#                 response.raise_for_status()
#                 data = response.json()
#                 if data.get("status") == "READY":
#                     break
#                 logger.debug(f"SSL Labs API not ready for {domain}, attempt {attempt + 1}/{max_retries}")
#                 time.sleep(10)
#             except (requests.Timeout, requests.RequestException) as e:
#                 logger.warning(f"SSL Labs API request failed for {domain}, attempt {attempt + 1}/{max_retries}: {str(e)}")
#                 if attempt == max_retries - 1:
#                     raise Exception(f"SSL Labs API failed after {max_retries} attempts: {str(e)}")
#                 time.sleep(10)
#         else:
#             raise Exception("Timeout waiting for SSL Labs analysis to complete after 30 seconds.")
#         endpoints = data.get("endpoints", [])
#         grade = "Unknown"
#         if endpoints:
#             grade = endpoints[0].get("grade", "Unknown")
#         result = {
#             "host": domain,
#             "grade": grade,
#             "valid_from": valid_from.strftime("%Y-%m-%d %H:%M:%S"),
#             "valid_until": valid_until.strftime("%Y-%m-%d %H:%M:%S"),
#             "issuer": issuer.get('commonName', 'Unknown'),
#             "key_algorithm": key_algorithm,
#             "key_size": key_size,
#             "signature_algorithm": signature_algorithm
#         }
#         print(f"[+] SSL certificate details retrieved for {domain} with grade {grade}")
#         logger.debug(f"SSL certificate details retrieved for {domain} with grade {grade}")
#         return result
#     except Exception as e:
#         logger.error(f"Failed to fetch SSL details for {domain}: {str(e)}")
#         return {"host": domain, "grade": "Unknown", "error": str(e)}

# Removed estimate_ssl_grade and parse_cert_bin for check_ssl_cert as they are redundant
# def estimate_ssl_grade(tls_version, cipher_suite, key_size, signature_algorithm, days_until_expiration):
#     ...
# def parse_cert_bin(cert_bin):
#     ...
# def fetch_cert_info_comprehensive(host, port=443, timeout=20):
#     ...