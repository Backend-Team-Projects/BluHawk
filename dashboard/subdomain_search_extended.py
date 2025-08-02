import logging
import requests
import sublist3r
from BluHawk.load_env import AlienVault_API
import time

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

timeout = 180

def get_subdomains_alienv(domain, threads=1, multi_source=True):
    """
    Fetch subdomains using AlienVault OTX API and optionally sublist3r for multi-source scans.
    Returns a dictionary with status_code and subdomains list for compatibility with attack_surface/views.py.
    """
    try:
        logger.info(f"[+] Starting subdomain enumeration for {domain}")
        # AlienVault OTX API call
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        headers = {"X-OTX-API-KEY": AlienVault_API}
        logger.info(f"[+] Sending AlienVault API request for {domain}")
        start_time = time.time()
        response = requests.get(url, headers=headers, timeout=timeout)
        elapsed = time.time() - start_time
        logger.info(f"[+] AlienVault API request for {domain} completed in {elapsed:.2f} seconds, status: {response.status_code}")
        subdomains = set()

        if response.status_code == 200:
            data = response.json()
            subdomains = {entry["hostname"] for entry in data.get("passive_dns", []) if entry["hostname"].endswith(domain)}
            logger.info(f"[+] Fetched {len(subdomains)} subdomains from AlienVault for {domain}: {subdomains}")
        else:
            logger.warning(f"[!] AlienVault API error for {domain}: {response.status_code} - {response.text}")

        # Optional multi-source scan with sublist3r
        if multi_source:
            logger.info(f"[+] Starting sublist3r scan for {domain}")
            try:
                start_time = time.time()
                engines = ["baidu", "yahoo", "google", "bing", "ask", "netcraft", "threatcrowd", "ssl", "passivedns"]
                subdomains2 = []
                for engine in engines:
                    engine_start = time.time()
                    try:
                        engine_subs = sublist3r.main(
                            domain,
                            threads=threads,
                            savefile=None,
                            ports=None,
                            silent=True,
                            verbose=False,
                            enable_bruteforce=False,
                            engines=engine
                        )
                        logger.info(f"[+] Engine {engine} for {domain} completed in {time.time() - engine_start:.2f} seconds, found {len(engine_subs)} subdomains: {engine_subs}")
                        subdomains2.extend(engine_subs)
                    except Exception as e:
                        logger.warning(f"[!] Engine {engine} for {domain} failed: {str(e)}")
                subdomains2 = list(set(subdomains2))  # Deduplicate
                elapsed = time.time() - start_time
                logger.info(f"[+] Sublist3r scan for {domain} completed in {elapsed:.2f} seconds, found {len(subdomains2)} subdomains: {subdomains2}")
                if subdomains2:
                    subdomains.update([sub for sub in subdomains2 if sub.endswith(domain)])
            except Exception as e:
                logger.error(f"[!] Failed sublist3r scan for {domain}: {str(e)}")

        logger.info(f"[+] Total {len(subdomains)} unique subdomains found for {domain}: {subdomains}")
        return {
            "status_code": "200",
            "subdomains": list(subdomains)
        }
    except Exception as e:
        logger.error(f"[!] Error fetching subdomains for {domain}: {str(e)}")
        return {
            "status_code": "500",
            "error": str(e),
            "subdomains": []
        }

def fetch_subdomains(domain):
    """Wrapper for get_subdomains_alienv with multi_source=False."""
    logger.info(f"[+] fetch_subdomains called for {domain}")
    return get_subdomains_alienv(domain, multi_source=False)

def fetch_subdomains_full(domain):
    """Wrapper for get_subdomains_alienv with multi_source=True."""
    logger.info(f"[+] fetch_subdomains_full called for {domain}")
    return get_subdomains_alienv(domain, multi_source=True)