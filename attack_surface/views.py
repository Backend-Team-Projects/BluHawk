import threading
import logging
import time
import os
import re
import socket
import requests
import dns.resolver
import whois
import traceback
import subprocess
import json
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.utils.timezone import now
from datetime import timedelta, datetime, timezone
from django.db import transaction
from dashboard.views import get_cve_data
from attack_surface.ssl import comprehensive_scan
from .models import AttackSurfaceScan, SSL, SSLRecord, TechnologyDescription, PortDescription
from .thread_control import active_threads
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from rest_framework.permissions import IsAuthenticated
from django.core.mail import send_mail
from BluHawk.load_env import VIRUS_TOTAL
from django.db.models import Q
from dashboard.port_scanning import port_scanner as ps
from dashboard.subdomain_search_extended import fetch_subdomains as sd, fetch_subdomains_full as full_sd
from BluHawk.wapiti_vul_scan import get_wapiti_report
from BluHawk.AsyncDataProcessing import AsyncDataProcessing
from BluHawk.utils import *
from BluHawk import load_env as myenv
from django.http import JsonResponse
from dashboard.models import CveNvd as CVE
from queue import Queue
from .vulnerability_description import fetch_vulnerability_description, fetch_port_description, fetch_technology_description, cpe_to_technology_name
from clatscope.views import get_nrich_data

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def update_task_progress(scan_record, task_name, status, message, jsondata=None):
    """Update the progress field in AttackSurfaceScan for a specific task."""
    try:
        with transaction.atomic():
            scan = AttackSurfaceScan.objects.select_for_update().get(id=scan_record.id)
            progress_entry = {
                "task_name": task_name,
                "status": status,
                "message": message,
                "timestamp": now().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "jsondata": jsondata or {}
            }
            scan.progress = [p for p in scan.progress if p["task_name"] != task_name] + [progress_entry]
            scan.save()
            logger.debug(f"Task progress updated for {scan_record.domain} ({scan_record.scan_type}): {task_name} - {status}")
        return scan.progress
    except Exception as e:
        logger.error(f"Failed to update task progress for {scan_record.domain} ({scan_record.scan_type}): {task_name} - {str(e)}")
        raise

def check_subdomain_activity(subdomain, timeout=3):
    """Check if a subdomain is active by resolving DNS records and checking HTTP/HTTPS connectivity."""
    print(f"[+] Checking subdomain activity for {subdomain}")
    status = {
        "active": False,
        "error": None,
        "http_active": False,
        "https_active": False,
        "http_status": None,
        "https_status": None
    }
    record_types = ["A", "AAAA", "CNAME"]
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(subdomain, rtype, lifetime=timeout)
            if answers:
                status["active"] = True
                break
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
            continue
    if not status["active"]:
        status["error"] = "No A, AAAA, or CNAME records found"
        logger.info(f"Subdomain {subdomain} DNS check: active={status['active']}, error={status['error']}")
        print(f"[+] Subdomain activity check completed for {subdomain}")
        return status

    for protocol in ["http", "https"]:
        try:
            url = f"{protocol}://{subdomain}"
            response = requests.head(url, timeout=timeout, allow_redirects=True)
            status[f"{protocol}_status"] = response.status_code
            if response.status_code is not None and 200 <= response.status_code <= 599:
                status[f"{protocol}_active"] = True
        except requests.RequestException as e:
            status[f"{protocol}_status"] = None
            logger.debug(f"Request failed for {url}: {str(e)}")
    
    logger.info(f"Subdomain {subdomain} check: active={status['active']}, http_active={status['http_active']}, https_active={status['https_active']}, http_status={status['http_status']}, https_status={status['https_status']}")
    print(f"[+] Subdomain activity check completed for {subdomain}")
    return status

def get_all_ipv4s(subdomains):
    """Map subdomains to their IPv4 addresses."""
    print(f"[+] Resolving IPv4 addresses for {len(subdomains)} subdomains")
    ip_map = {}
    for sub in subdomains:
        try:
            ip_info = socket.getaddrinfo(sub, None, socket.AF_INET)
            ip_set = {info[4][0] for info in ip_info}
            ip_map[sub] = list(ip_set)
            logger.debug(f"Resolved IPs for {sub}: {ip_map[sub]}")
        except socket.gaierror as e:
            ip_map[sub] = []
            logger.debug(f"DNS resolution failed for {sub}: {str(e)}")
    if not any(ip_map.values()):
        logger.warning(f"No IPs resolved for any subdomains: {subdomains}")
        print(f"[+] Warning: No IPs resolved for {len(subdomains)} subdomains")
    print(f"[+] IPv4 address resolution completed for {len(subdomains)} subdomains")
    return ip_map

def get_dns_records(subdomain):
    """Resolve DNS records for a subdomain."""
    print(f"[+] Fetching DNS records for {subdomain}")
    record_types = ["A", "AAAA", "CNAME", "MX", "TXT", "NS"]
    records = {}
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(subdomain, rtype, lifetime=3)
            records[rtype] = [str(rdata) for rdata in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
            records[rtype] = []
    print(f"[+] DNS record fetch completed for {subdomain}")
    return records

def get_all_dns_records(subdomain_set):
    """Fetch DNS records for a set of subdomains."""
    print(f"[+] Fetching DNS records for {len(subdomain_set)} subdomains")
    dns_data = {}
    for sub in subdomain_set:
        dns_data[sub] = get_dns_records(sub)
        logger.debug(f"DNS records fetched for {sub}: {dns_data[sub]}")
    print(f"[+] DNS record fetch completed for {len(subdomain_set)} subdomains")
    return dns_data

def fetch_shodan_full_data(ip):
    """Fetch data for a given IP address from external sources."""
    print(f"[+] Fetching Shodan data for IP {ip}")
    SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
    if not SHODAN_API_KEY:
        logger.warning(f"No SHODAN_API key set for IP {ip}")
        print(f"[+] Shodan data fetch failed for IP {ip}: No API key")
        return {"error": "API key for external data source is not set"}
    url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            logger.warning(f"Shodan API returned status {response.status_code} for IP {ip}")
            print(f"[+] Shodan data fetch failed for IP {ip}: Status {response.status_code}")
            return {"error": f"External data source returned status {response.status_code}", "details": response.text[:1000]}
        data = response.json()
        technologies = data.get("data", [{}])[0].get("http", {}).get("components", {}).keys()
        vulns = data.get("vulns", [])
        ports = [str(p) for p in data.get("ports", [])]
        logger.debug(f"Shodan data for IP {ip}: technologies={technologies}, vulns={vulns}, ports={ports}")
        print(f"[+] Shodan data fetch completed for IP {ip}")
        return {"technologies": list(technologies), "vulns": vulns, "ports": ports, "source": "shodan"}
    except Exception as e:
        logger.error(f"Shodan API exception for IP {ip}: {str(e)}")
        print(f"[+] Shodan data fetch failed for IP {ip}: {str(e)}")
        return {"error": f"Exception occurred: {str(e)}"}

def get_whois_info(domain):
    """Fetch WHOIS information for a domain."""
    print(f"[+] Fetching WHOIS information for {domain}")
    logger.debug(f"Fetching WHOIS information for {domain}")
    result = {
        "Registrar": None,
        "Registrant": None,
        "Creation Date": None,
        "Updated Date": None,
        "Expiry Date": None,
    }
    try:
        w = whois.whois(domain)
        result["Registrar"] = w.registrar
        result["Registrant"] = w.name

        def format_date(date_field):
            if date_field is None:
                return None
            if isinstance(date_field, list):
                for dt in date_field:
                    if isinstance(dt, datetime) and dt.tzinfo is not None:
                        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
                for dt in date_field:
                    if isinstance(dt, datetime):
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)
                        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
                return None
            elif isinstance(date_field, datetime):
                if date_field.tzinfo is None:
                    date_field = date_field.replace(tzinfo=timezone.utc)
                return date_field.strftime("%Y-%m-%dT%H:%M:%SZ")
            return None

        result["Creation Date"] = format_date(w.creation_date)
        result["Updated Date"] = format_date(w.updated_date)
        result["Expiry Date"] = format_date(w.expiration_date)
        logger.debug(f"WHOIS information retrieved for {domain}")
        print(f"[+] WHOIS information fetch completed for {domain}")
        return result
    except Exception as e:
        logger.error(f"Error fetching WHOIS for {domain}: {str(e)}")
        print(f"[+] WHOIS information fetch failed for {domain}: {str(e)}")
        return {"error": str(e)}

def check_email_hygiene(domain):
    """Check email hygiene configurations (SPF, DKIM, DMARC, BIMI) for a domain."""
    print(f"[+] Checking email hygiene for {domain}")
    logger.debug(f"Checking email hygiene for {domain}")
    email_hygiene = {
        "spf": {
            "Name": "SPF",
            "Result": "Fail",
            "Description": "No SPF record found.",
            "Records": []
        },
        "dkim": {
            "Name": "DKIM",
            "Result": "Fail",
            "Description": "No DKIM records found.",
            "Records": []
        },
        "dmarc": {
            "Name": "DMARC",
            "Result": "Fail",
            "Description": "No DMARC record found.",
            "Records": []
        },
        "bimi": {
            "Name": "BIMI",
            "Result": "Fail",
            "Description": "No BIMI record found.",
            "Records": []
        }
    }
    try:
        try:
            answers = dns.resolver.resolve(domain, "TXT", lifetime=3)
            spf_records = []
            for rdata in answers:
                txt = str(rdata).strip('"')
                if txt.startswith("v=spf1"):
                    spf_records.append(txt)
            if spf_records:
                email_hygiene["spf"]["Records"] = spf_records
                if any("all" in record for record in spf_records):
                    email_hygiene["spf"]["Result"] = "Pass"
                    email_hygiene["spf"]["Description"] = "Valid SPF record found with 'all' directive."
                else:
                    email_hygiene["spf"]["Result"] = "Partial"
                    email_hygiene["spf"]["Description"] = "SPF record found but lacks 'all' directive."
                logger.debug(f"SPF records for {domain}: {spf_records}")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
            logger.debug(f"No SPF records found for {domain}")
            pass
        selectors = ["default", "selector1", "selector2", "google", "mail"]
        dkim_records = []
        found_selectors = []
        for selector in selectors:
            dkim_domain = f"{selector}._domainkey.{domain}"
            try:
                answers = dns.resolver.resolve(dkim_domain, "TXT", lifetime=3)
                for rdata in answers:
                    txt = str(rdata).strip('"')
                    if txt.startswith("v=DKIM1"):
                        dkim_records.append(txt)
                        found_selectors.append(selector)
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
                continue
        if dkim_records:
            email_hygiene["dkim"]["Records"] = dkim_records
            email_hygiene["dkim"]["Result"] = "Pass"
            email_hygiene["dkim"]["Description"] = f"DKIM records found for selectors: {', '.join(found_selectors)}."
            logger.debug(f"DKIM records for {domain}: {dkim_records}")
        else:
            email_hygiene["dkim"]["Description"] = "No DKIM records found for common selectors."
            logger.debug(f"No DKIM records found for {domain}")
        dmarc_domain = f"_dmarc.{domain}"
        try:
            answers = dns.resolver.resolve(dmarc_domain, "TXT", lifetime=3)
            dmarc_records = []
            for rdata in answers:
                txt = str(rdata).strip('"')
                if txt.startswith("v=DMARC1"):
                    dmarc_records.append(txt)
            if dmarc_records:
                email_hygiene["dmarc"]["Records"] = dmarc_records
                policy = None
                for record in dmarc_records:
                    match = re.search(r"p=([^;]+)", record)
                    if match:
                        policy = match.group(1)
                        break
                if policy in ["quarantine", "reject"]:
                    email_hygiene["dmarc"]["Result"] = "Pass"
                    email_hygiene["dmarc"]["Description"] = f"DMARC policy set to '{policy}'."
                else:
                    email_hygiene["dmarc"]["Result"] = "Partial"
                    email_hygiene["dmarc"]["Description"] = "DMARC record found but policy is 'none' or invalid."
                logger.debug(f"DMARC records for {domain}: {dmarc_records}")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
            logger.debug(f"No DMARC records found for {domain}")
            pass
        bimi_domains = [f"default._bimi.{domain}", f"_bimi.{domain}"]
        bimi_records = []
        logo_url = None
        vmc_url = None
        for bimi_domain in bimi_domains:
            try:
                answers = dns.resolver.resolve(bimi_domain, "TXT", lifetime=3)
                for rdata in answers:
                    txt = str(rdata).strip('"')
                    if txt.startswith("v=BIMI1"):
                        bimi_records.append(txt)
                        logo_match = re.search(r"l=([^;]+)", txt)
                        vmc_match = re.search(r"a=([^;]+)", txt)
                        if logo_match:
                            logo_url = logo_match.group(1).strip()
                        if vmc_match:
                            vmc_url = vmc_match.group(1).strip()
                        break
                if bimi_records:
                    break
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
                continue
        if bimi_records:
            email_hygiene["bimi"]["Records"] = bimi_records
            if logo_url:
                email_hygiene["bimi"]["Result"] = "Pass"
                email_hygiene["bimi"]["Description"] = f"BIMI record found with logo URL: {logo_url}" + (f" and VMC URL: {vmc_url}" if vmc_url else ".")
            else:
                email_hygiene["bimi"]["Result"] = "Partial"
                email_hygiene["bimi"]["Description"] = "BIMI record found but missing logo URL."
            logger.debug(f"BIMI records for {domain}: {bimi_records}")
        logger.debug(f"Email hygiene check completed for {domain}")
        print(f"[+] Email hygiene check completed for {domain}")
        return email_hygiene
    except Exception as e:
        logger.error(f"Error checking email security settings for {domain}: {str(e)}")
        print(f"[+] Email hygiene check failed for {domain}: {str(e)}")
        return {"error": f"Failed to check email security settings: {str(e)}"}

def is_valid_domain(target):
    """Validate if the target is a domain."""
    domain_pattern = re.compile(
        r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    return bool(domain_pattern.match(target))

def wapiti_task(queue, stop_event, domain, scan_record, results, lock):
    """Run Wapiti vulnerability scan with timeout handling."""
    print(f"[+] Performing Wapiti vulnerability scan for {domain}")
    update_task_progress(scan_record, "wapiti", "in_progress", f"Scanning website {domain}")
    try:
        start_time = time.time()
        while time.time() - start_time < 300:
            if stop_event.is_set():
                logger.info(f"Wapiti task for {domain} stopped due to timeout")
                print(f"[+] Wapiti task stopped for {domain} due to timeout")
                with lock:
                    results["wapiti"] = {}
                    update_task_progress(scan_record, "wapiti", "skipped", "Wapiti scan stopped due to timeout")
                queue.put(True)
                return
            wapiti_report_data = get_wapiti_report(domain)
            if wapiti_report_data:
                break
            time.sleep(1)
        with lock:
            # Validate that wapiti_report_data is a dictionary
            if not isinstance(wapiti_report_data, dict):
                logger.error(f"Wapiti scan for {domain} returned invalid data type: {type(wapiti_report_data)}")
                print(f"[+] Wapiti vulnerability scan failed for {domain}: Invalid data type returned")
                results["wapiti"] = {}
                update_task_progress(scan_record, "wapiti", "error", f"Website scan failed: Invalid data type returned ({type(wapiti_report_data)})")
                update_task_progress(scan_record, "vulnerability_description", "skipped", "No Wapiti vulnerabilities to describe due to invalid data")
                queue.put(True)
                return
            
            # Check for 'status' key and handle error cases
            if 'status' not in wapiti_report_data:
                logger.error(f"Wapiti scan for {domain} returned invalid data: Missing 'status' key")
                print(f"[+] Wapiti vulnerability scan failed for {domain}: Missing 'status' key")
                results["wapiti"] = {}
                update_task_progress(scan_record, "wapiti", "error", "Website scan failed: Missing 'status' key in response")
                update_task_progress(scan_record, "vulnerability_description", "skipped", "No Wapiti vulnerabilities to describe due to invalid data")
                queue.put(True)
                return

            # Handle success or error status
            results["wapiti"] = wapiti_report_data.get('data', {}) if wapiti_report_data['status'] == 'success' else {}
            status = "completed" if wapiti_report_data['status'] == 'success' else "error"
            message = "Website scan completed" if status == "completed" else f"Website scan failed: {wapiti_report_data.get('message', 'Unknown error')}"
            update_task_progress(scan_record, "wapiti", status, message, wapiti_report_data)
            logger.debug(f"Wapiti scan for {domain}: {status}")
            print(f"[+] Wapiti vulnerability scan {status} for {domain}")
            
            # Process vulnerabilities only if the scan was successful and data is valid
            if status == "completed" and isinstance(results["wapiti"], dict) and results["wapiti"].get("vulnerabilities"):
                print(f"[+] Fetching descriptions for Wapiti vulnerabilities")
                update_task_progress(scan_record, "vulnerability_description", "in_progress", f"Fetching descriptions for Wapiti vulnerabilities")
                vuln_descriptions = {}
                # Extract non-empty vulnerabilities from the vulnerabilities dictionary
                vulnerabilities = [
                    (vuln_name, finding) for vuln_name, findings in results["wapiti"].get("vulnerabilities", {}).items()
                    if isinstance(findings, list) and len(findings) > 0
                    for finding in findings
                ]
                for vuln_name, finding in vulnerabilities:
                    if vuln_name and finding.get("info"):
                        description_result = fetch_vulnerability_description(vuln_name, wapiti_info=finding["info"])
                        vuln_key = f"{vuln_name}_{finding['info']}"  # Unique key to store multiple findings
                        vuln_descriptions[vuln_key] = description_result
                        update_task_progress(
                            scan_record,
                            f"vuln_description_{vuln_key}",
                            description_result["status"],
                            description_result["message"],
                            description_result["data"]
                        )
                        logger.debug(f"Description fetch for {vuln_name} with info {finding['info']}: {description_result['status']}")
                results["vulnerability_descriptions"] = vuln_descriptions
                update_task_progress(
                    scan_record,
                    "vulnerability_description",
                    "completed",
                    f"Descriptions fetched for {len(vulnerabilities)} vulnerabilities",
                    vuln_descriptions
                )
                print(f"[+] Vulnerability description fetch completed for {len(vulnerabilities)} vulnerabilities")
            else:
                update_task_progress(scan_record, "vulnerability_description", "skipped", "No Wapiti vulnerabilities to describe")
                print(f"[+] Skipped vulnerability description fetch: No Wapiti results")
            
            queue.put(True)
    except Exception as e:
        logger.error(f"Wapiti scan failed for {domain}: {str(e)}")
        print(f"[+] Wapiti vulnerability scan failed for {domain}: {str(e)}")
        with lock:
            results["wapiti"] = {}
            update_task_progress(scan_record, "wapiti", "error", f"Website scan failed: {str(e)}")
            update_task_progress(scan_record, "vulnerability_description", "skipped", "No Wapiti vulnerabilities to describe due to scan failure")
            queue.put(True)

def generate_attack_surface_report(domain, scan_type='complete'):
    """Generate an attack surface report for a domain using multiple threads with timeout."""
    print(f"[+] Starting attack surface report generation for {domain} ({scan_type})")
    logger.info(f"Starting attack surface report for {domain} with scan_type {scan_type}")
    scan_record, _ = AttackSurfaceScan.objects.get_or_create(
        domain=domain,
        scan_type=scan_type,
        defaults={"status": "pending", "jsondata": {}, "progress": []}
    )
    update_task_progress(scan_record, "initialization", "in_progress", f"Starting security scan for {domain}")

    results = {
        "wapiti": {},
        "whois": {},
        "email_hygiene": {},
        "subdomains": [],
        "active_subdomains": [],
        "ip_address_map": {},
        "port_map": {},
        "dns_records": {},
        "shodan_data": {},
        "nrich_data": {},
        "ssl_comprehensive": {},
        "http_status": {},
        "technology_descriptions": {},
        "vulnerability_descriptions": {},
        "port_descriptions": {}
    }
    lock = threading.Lock()
    subsequent_threads = []
    wapiti_queue = Queue()

    def whois_task():
        """Run WHOIS lookup."""
        print(f"[+] Performing WHOIS lookup for {domain}")
        update_task_progress(scan_record, "whois", "in_progress", f"Fetching domain registration details for {domain}")
        try:
            whois_info = get_whois_info(domain)
            with lock:
                results["whois"] = whois_info
                status = "completed" if "error" not in whois_info else "error"
                message = "WHOIS information retrieved" if status == "completed" else f"WHOIS lookup failed: {whois_info['error']}"
                update_task_progress(scan_record, "whois", status, message, whois_info)
                logger.debug(f"WHOIS task for {domain}: {status}")
                print(f"[+] WHOIS lookup completed for {domain}")
        except Exception as e:
            logger.error(f"WHOIS lookup failed for {domain}: {str(e)}")
            print(f"[+] WHOIS lookup failed for {domain}: {str(e)}")
            with lock:
                results["whois"] = {"error": str(e)}
                update_task_progress(scan_record, "whois", "error", f"WHOIS lookup failed: {str(e)}")

    def email_hygiene_task():
        """Run email hygiene checks."""
        print(f"[+] Performing email hygiene check for {domain}")
        update_task_progress(scan_record, "email_hygiene", "in_progress", f"Checking email security settings for {domain}")
        try:
            email_hygiene = check_email_hygiene(domain)
            with lock:
                results["email_hygiene"] = email_hygiene
                status = "completed" if "error" not in email_hygiene else "error"
                message = "Email security settings retrieved" if status == "completed" else f"Email hygiene check failed: {email_hygiene['error']}"
                update_task_progress(scan_record, "email_hygiene", status, message, email_hygiene)
                logger.debug(f"Email hygiene task for {domain}: {status}")
                print(f"[+] Email hygiene check completed for {domain}")
        except Exception as e:
            logger.error(f"Email hygiene check failed for {domain}: {str(e)}")
            print(f"[+] Email hygiene check failed for {domain}: {str(e)}")
            with lock:
                results["email_hygiene"] = {"error": str(e)}
                update_task_progress(scan_record, "email_hygiene", "error", f"Email hygiene check failed: {str(e)}")

    def ssl_task(targets):
        """Run SSL scans for the provided targets."""
        print(f"[+] Performing comprehensive SSL/TLS scan for {len(targets)} targets")
        logger.debug(f"Starting SSL task for targets: {targets}")
        for sub in targets:
            print(f"[+] Performing SSL/TLS scan for {sub}")
            update_task_progress(scan_record, f"ssl_scan_{sub}", "in_progress", f"Checking SSL security for {sub}")
            max_retries = 3
            scan_result = None
            for attempt in range(max_retries):
                try:
                    scan_result = comprehensive_scan(sub)
                    if "error" not in scan_result:
                        break
                    logger.warning(f"SSL scan failed for {sub}, attempt {attempt + 1}/{max_retries}: {scan_result['error']}")
                    print(f"[+] SSL/TLS scan failed for {sub}, retrying")
                    if attempt < max_retries - 1:
                        time.sleep(10)
                except Exception as e:
                    logger.warning(f"SSL scan exception for {sub}, attempt {attempt + 1}/{max_retries}: {str(e)}")
                    print(f"[+] SSL/TLS scan exception for {sub}, retrying")
                    if attempt < max_retries - 1:
                        time.sleep(10)
            with lock:
                if not scan_result or "error" in scan_result:
                    results["ssl_comprehensive"][sub] = {"server": sub, "error": "Failed to fetch SSL details after 3 attempts"}
                    update_task_progress(scan_record, f"ssl_scan_{sub}", "error", f"SSL scan failed for {sub}: Unable to retrieve SSL details")
                    print(f"[+] SSL/TLS scan failed for {sub}: Unable to retrieve SSL details")
                else:
                    results["ssl_comprehensive"][sub] = scan_result
                    update_task_progress(scan_record, f"ssl_scan_{sub}", "completed", f"SSL scan completed for {sub}", scan_result)
                    logger.debug(f"SSL scan completed for {sub}")
                    print(f"[+] Comprehensive SSL/TLS scan completed for {sub}")

                if is_valid_domain(sub):
                    ssl_info_sub = {
                        "host": sub,
                        "grade": scan_result.get("grade", {}).get("grade", "Unknown") if scan_result and "error" not in scan_result else "Unknown",
                        "valid_from": scan_result.get("certificate", {}).get("valid_from", "Unknown") if scan_result and "error" not in scan_result else "Unknown",
                        "valid_to": scan_result.get("certificate", {}).get("valid_to", "Unknown") if scan_result and "error" not in scan_result else "Unknown",
                        "issuer": scan_result.get("certificate", {}).get("issuer", "Unknown") if scan_result and "error" not in scan_result else "Unknown",
                        "key_algorithm": scan_result.get("certificate", {}).get("public_key_type", "Unknown") if scan_result and "error" not in scan_result else "Unknown",
                        "key_size": scan_result.get("certificate", {}).get("public_key_size", 0) if scan_result and "error" not in scan_result else 0,
                        "signature_algorithm": scan_result.get("certificate", {}).get("signature_algorithm", "Unknown") if scan_result and "error" not in scan_result else "Unknown"
                    } if sub != domain else {"host": sub, "grade": "Unknown", "error": "SSL info commented out per request"}
                    logger.debug(f"SSL scan result stored for {sub}")

                    SSL.objects.update_or_create(
                        domain=sub,
                        scan_type="ssl_scan",
                        defaults={
                            "status": "completed" if "error" not in scan_result else "error",
                            "scanned_at": now(),
                            "jsondata": ssl_info_sub
                        }
                    )
                    SSLRecord.objects.update_or_create(
                        target=sub,
                        defaults={
                            "status": "completed" if "error" not in scan_result else "error",
                            "scanned_at": now(),
                            "json_data": scan_result if scan_result else {"error": "Failed to fetch SSL details"}
                        }
                    )
        print(f"[+] Comprehensive SSL/TLS scan completed for {len(targets)} targets")

    def dns_task(targets):
        """Run DNS scans for the provided targets."""
        print(f"[+] Performing DNS scan for {len(targets)} targets")
        logger.debug(f"Starting DNS task for targets: {targets}")
        update_task_progress(scan_record, "dns_records", "in_progress", f"Collecting DNS information for {len(targets)} targets")
        dns_records = get_all_dns_records(targets)
        with lock:
            results["dns_records"] = dns_records
            update_task_progress(scan_record, "dns_records", "completed", f"Collected DNS information for {len(dns_records)} targets", dns_records)
            logger.debug(f"Collected DNS records for {len(dns_records)} targets")
            print(f"[+] DNS scan completed for {len(targets)} targets")

    def http_status_task(targets):
        """Run HTTP/HTTPS status checks for the provided targets."""
        print(f"[+] Performing HTTP/HTTPS status check for {len(targets)} targets")
        logger.debug(f"Starting HTTP/HTTPS status task for targets: {targets}")
        for sub in targets:
            print(f"[+] Checking HTTP/HTTPS status for {sub}")
            update_task_progress(scan_record, f"http_status_{sub}", "in_progress", f"Checking HTTP/HTTPS status for {sub}")
            status = check_subdomain_activity(sub)
            with lock:
                results["http_status"][sub] = {
                    "http_active": status["http_active"],
                    "https_active": status["https_active"],
                    "http_status": status["http_status"],
                    "https_status": status["https_status"]
                }
                update_task_progress(scan_record, f"http_status_{sub}", "completed" if status["active"] else "error",
                                    f"HTTP/HTTPS status check for {sub} {'completed' if status['active'] else 'failed: Unable to connect'}",
                                    {"subdomain": sub, "status": status})
                logger.debug(f"HTTP/HTTPS status check for {sub}: {'completed' if status['active'] else 'failed'}")
                print(f"[+] HTTP/HTTPS status check completed for {sub}")
        print(f"[+] HTTP/HTTPS status check completed for {len(targets)} targets")

    def shodan_nrich_task(targets):
        """Run Shodan and nrich scans for the provided targets, combining CVEs into nrich vulns.

        Modifications:
        - If port scanner returns no ports for an IP, immediately fallback to Shodan ports (if available)
        and store them in results["port_map"][ip] so later steps (port_descriptions, summary) see them.
        - Normalize port values to ints.
        - Use the normalized results["port_map"][ip] when generating port descriptions.
        """
        print(f"[+] Performing Shodan and nrich scans for {len(targets)} targets")
        logger.debug(f"Starting Shodan/nrich task for targets: {targets}")
        ip_address_map = get_all_ipv4s(targets)
        with lock:
            results["ip_address_map"] = ip_address_map
            all_ips = set(ip for ips in ip_address_map.values() for ip in ips)
            update_task_progress(scan_record, "ip_resolution", "completed", f"Identified {len(all_ips)} IP addresses", ip_address_map)
            logger.debug(f"Identified {len(all_ips)} IP addresses")

        if not all_ips:
            logger.warning(f"No valid IPs resolved for targets: {targets}")
            print(f"[+] Warning: No valid IPs resolved for {len(targets)} targets")
            with lock:
                results["port_map"] = {}
                results["port_descriptions"] = {"error": "No valid IPs resolved for port scanning"}
                results["shodan_data"] = {"error": "No valid IPs resolved for Shodan scanning"}
                results["nrich_data"] = {"error": "No valid IPs resolved for nrich scanning"}
                update_task_progress(scan_record, "port_description", "error", "No valid IPs resolved for port scanning")
                update_task_progress(scan_record, "shodan_scan", "error", "No valid IPs resolved for Shodan scanning")
                update_task_progress(scan_record, "nrich_scan", "error", "No valid IPs resolved for nrich scanning")
            return

        for ip in all_ips:
            print(f"[+] Performing port scan for IP {ip}")
            update_task_progress(scan_record, f"port_scan_{ip}", "in_progress", f"Checking network services for IP {ip}")
            max_retries = 2
            port_scan_result = None
            for attempt in range(max_retries):
                try:
                    port_scan_result = ps(ip)
                    if port_scan_result.get('status') == 'success' and port_scan_result.get('data'):
                        break
                    logger.warning(f"Port scan failed for {ip}, attempt {attempt + 1}/{max_retries}: {port_scan_result.get('error', 'No data')}")
                    print(f"[+] Port scan failed for IP {ip}, retrying")
                    if attempt < max_retries - 1:
                        time.sleep(5)
                except Exception as e:
                    logger.warning(f"Port scan exception for {ip}, attempt {attempt + 1}/{max_retries}: {str(e)}")
                    print(f"[+] Port scan exception for {ip}, retrying")
                    if attempt < max_retries - 1:
                        time.sleep(5)

            with lock:
                if port_scan_result and port_scan_result.get('status') == 'success' and port_scan_result.get('data'):
                    # Normalize scanner ports to ints where possible
                    normalized = []
                    for p in port_scan_result.get('data', []):
                        try:
                            normalized.append(int(p))
                        except Exception:
                            try:
                                digits = re.findall(r"\d+", str(p))
                                if digits:
                                    normalized.append(int(digits[0]))
                            except Exception:
                                continue
                    results["port_map"][ip] = list(dict.fromkeys(normalized))  # deduplicate preserving order
                    update_task_progress(scan_record, f"port_scan_{ip}", "completed", f"Network service check completed for IP {ip}", port_scan_result)
                    logger.debug(f"Port scan completed for IP {ip}: {results['port_map'][ip]}")
                    print(f"[+] Port scan completed for IP {ip}: {results['port_map'][ip]}")
                else:
                    results["port_map"][ip] = []
                    error_msg = port_scan_result.get('error', 'Unknown error') if port_scan_result else 'No response from port scanner'
                    update_task_progress(scan_record, f"port_scan_{ip}", "error", f"Port scan failed for IP {ip}: {error_msg}")
                    logger.error(f"Port scan failed for {ip}: {error_msg}")
                    print(f"[+] Port scan failed for IP {ip}: {error_msg}")

            update_task_progress(scan_record, f"shodan_scan_{ip}", "in_progress", f"Collecting Shodan data for IP {ip}")
            shodan_result = fetch_shodan_full_data(ip)
            nrich_result = None

            with lock:
                results["shodan_data"][ip] = shodan_result
                update_task_progress(scan_record, f"shodan_scan_{ip}", "completed", f"Shodan data collected for IP {ip}", shodan_result)
                logger.debug(f"Shodan data collected for IP {ip}")

            # If scanner returned no ports, fallback immediately to Shodan ports (if available)
            try:
                with lock:
                    current_ports = results.get("port_map", {}).get(ip, []) or []
                if not current_ports and isinstance(shodan_result, dict) and shodan_result.get("ports"):
                    fallback_ports = []
                    for p in shodan_result.get("ports", []):
                        try:
                            fallback_ports.append(int(p))
                        except Exception:
                            try:
                                digits = re.findall(r"\d+", str(p))
                                if digits:
                                    fallback_ports.append(int(digits[0]))
                            except Exception:
                                continue
                    fallback_ports = list(dict.fromkeys(fallback_ports))
                    if fallback_ports:
                        with lock:
                            # update results so subsequent steps use the fallback ports
                            results.setdefault("port_map", {})[ip] = fallback_ports
                            logger.info(f"Port scanner empty for {ip}; using Shodan fallback ports: {fallback_ports}")
                            update_task_progress(scan_record, f"port_scan_{ip}", "completed", f"Port scanner returned no ports; used Shodan fallback ports for IP {ip}", {"fallback_ports": fallback_ports})
                            print(f"[+] Used Shodan fallback ports for {ip}: {fallback_ports}")
            except Exception as e:
                logger.warning(f"Failed to apply Shodan fallback ports for {ip}: {str(e)}")
                print(f"[+] Shodan fallback ports application failed for {ip}: {str(e)}")

            # Fetch nrich data
            print(f"[+] Fetching nrich data for IP {ip}")
            update_task_progress(scan_record, f"nrich_scan_{ip}", "in_progress", f"Collecting nrich data for IP {ip}")
            try:
                nrich_result = get_nrich_data(ip)
                if nrich_result.get("status") == "success" and nrich_result.get("data"):
                    with lock:
                        # Combine Shodan and nrich CVEs into nrich_data[ip]["vulns"]
                        nrich_data = nrich_result["data"][0]
                        combined_vulns = set(nrich_data.get("vulns", []))  # Start with nrich vulns
                        combined_vulns.update(nrich_data.get("cve_vulns", {}).keys())  # Add nrich cve_vulns
                        if isinstance(shodan_result, dict) and "vulns" in shodan_result and shodan_result["vulns"]:
                            combined_vulns.update(shodan_result["vulns"])  # Add Shodan vulns
                        nrich_data["vulns"] = list(combined_vulns)  # Update vulns field
                        results["nrich_data"][ip] = nrich_data
                        update_task_progress(scan_record, f"nrich_scan_{ip}", "completed", f"nrich data collected for IP {ip} with {len(combined_vulns)} CVEs", nrich_data)
                        logger.debug(f"nrich data for IP {ip}: {nrich_data}")
                        print(f"[+] nrich data fetch completed for IP {ip} with {len(combined_vulns)} CVEs")
                else:
                    error_msg = nrich_result.get("error", "No data returned from nrich") if nrich_result else "Failed to fetch nrich data"
                    with lock:
                        results["nrich_data"][ip] = {"error": error_msg}
                        update_task_progress(scan_record, f"nrich_scan_{ip}", "error", f"nrich data fetch failed for IP {ip}: {error_msg}")
                        logger.error(f"nrich data fetch failed for IP {ip}: {error_msg}")
                        print(f"[+] nrich data fetch failed for IP {ip}: {error_msg}")
            except Exception as e:
                with lock:
                    results["nrich_data"][ip] = {"error": str(e)}
                    update_task_progress(scan_record, f"nrich_scan_{ip}", "error", f"nrich data fetch failed for IP {ip}: {str(e)}")
                    logger.error(f"nrich data fetch exception for IP {ip}: {str(e)}")
                    print(f"[+] nrich data fetch failed for IP {ip}: {str(e)}")

            # Fetch technology descriptions for Shodan technologies or fallback to nrich CPEs
            technologies = []
            if isinstance(shodan_result, dict) and shodan_result.get("technologies"):
                technologies = shodan_result["technologies"]
                logger.debug(f"Using Shodan technologies for IP {ip}: {technologies}")
                print(f"[+] Using Shodan technologies for IP {ip}: {len(technologies)} found")
            else:
                print(f"[+] No Shodan technologies found for IP {ip}, falling back to nrich CPEs")
                logger.debug(f"No Shodan technologies for IP {ip}, checking nrich CPEs")
                if nrich_result and nrich_result.get("status") == "success" and nrich_result.get("data"):
                    cpes = nrich_result["data"][0].get("cpes", [])
                    technologies = [cpe_to_technology_name(cpe) for cpe in cpes if cpe_to_technology_name(cpe)]
                    technologies = list(set(filter(None, technologies)))  # Remove None and duplicates
                    logger.debug(f"Generated {len(technologies)} technologies from CPEs for IP {ip}: {technologies}")
                    print(f"[+] Generated {len(technologies)} technologies from CPEs for IP {ip}")
                    shodan_result["technologies"] = technologies  # Update shodan_result with CPE-derived technologies
                    with lock:
                        results["shodan_data"][ip] = shodan_result
                        update_task_progress(scan_record, f"shodan_scan_{ip}", "completed", f"Shodan data updated with {len(technologies)} CPE-derived technologies for IP {ip}", shodan_result)
                else:
                    error_msg = nrich_result.get("error", "No data returned from nrich") if nrich_result else "Failed to fetch nrich data"
                    logger.warning(f"No technologies generated for IP {ip}: {error_msg}")
                    print(f"[+] No technologies generated for IP {ip}: {error_msg}")

            # Fetch technology descriptions
            if technologies:
                print(f"[+] Fetching technology descriptions for IP {ip}")
                update_task_progress(scan_record, f"technology_description_{ip}", "in_progress", f"Fetching technology descriptions for IP {ip}")
                tech_descriptions = {}
                for tech in technologies:
                    if tech:
                        description_result = fetch_technology_description(tech)
                        tech_descriptions[tech] = description_result
                        update_task_progress(scan_record, f"tech_description_{tech}_{ip}", description_result["status"], description_result["message"], description_result["data"])
                        logger.debug(f"Description fetch for technology {tech} on IP {ip}: {description_result['status']}")
                        print(f"[+] Description fetch for technology {tech} on IP {ip}: {description_result['status']}")
                        time.sleep(1)  # Rate limit mitigation
                with lock:
                    results["technology_descriptions"][ip] = tech_descriptions
                    update_task_progress(scan_record, f"technology_description_{ip}", "completed", f"Descriptions fetched for {len(tech_descriptions)} technologies on IP {ip}", tech_descriptions)
                    print(f"[+] Technology description fetch completed for {len(tech_descriptions)} technologies on IP {ip}")
            else:
                with lock:
                    results["technology_descriptions"][ip] = {"error": "No technologies found for description"}
                    update_task_progress(scan_record, f"technology_description_{ip}", "skipped", f"No technologies found for IP {ip}")
                    print(f"[+] Technology description fetch skipped for IP {ip}: No technologies found")

            # Fetch port descriptions for up to 5 ports per IP — use results["port_map"][ip] (which may include Shodan fallback)
            with lock:
                ports_for_ip = results.get("port_map", {}).get(ip, []) or []
            if ports_for_ip:
                print(f"[+] Processing port descriptions for {len(ports_for_ip)} ports on IP {ip}")
                update_task_progress(scan_record, f"port_description_{ip}", "in_progress", f"Fetching descriptions for ports on IP {ip}")
                port_descriptions = {}
                # Ensure we work with ints
                normalized_ports = []
                for p in ports_for_ip:
                    try:
                        normalized_ports.append(int(p))
                    except Exception:
                        try:
                            digits = re.findall(r"\d+", str(p))
                            if digits:
                                normalized_ports.append(int(digits[0]))
                        except Exception:
                            continue
                normalized_ports = list(dict.fromkeys(normalized_ports))

                # Check database for existing descriptions
                cached_ports = PortDescription.objects.filter(port__in=normalized_ports)
                cached_port_nums = [p.port for p in cached_ports]
                port_descriptions.update({
                    p.port: {
                        "status": "success",
                        "data": p.description,
                        "message": f"Cached description retrieved for port {p.port}"
                    } for p in cached_ports
                })
                logger.debug(f"Cached descriptions found for ports {cached_port_nums} on IP {ip}")
                print(f"[+] Found cached descriptions for {len(cached_port_nums)} ports on IP {ip}")

                # Select additional ports to fetch, up to a total of 5
                remaining_slots = 5 - len(cached_port_nums)
                ports_to_fetch = [p for p in normalized_ports if p not in cached_port_nums][:remaining_slots]
                logger.debug(f"Fetching descriptions for {len(ports_to_fetch)} additional ports on IP {ip}: {ports_to_fetch}")
                print(f"[+] Fetching descriptions for {len(ports_to_fetch)} additional ports on IP {ip}")

                for port in ports_to_fetch:
                    description_result = fetch_port_description(port)
                    port_descriptions[port] = description_result
                    update_task_progress(scan_record, f"port_description_{port}", description_result["status"], description_result["message"], description_result["data"])
                    logger.debug(f"Description fetch for port {port} on IP {ip}: {description_result['status']}")
                    print(f"[+] Description fetch for port {port} on IP {ip}: {description_result['status']}")
                    time.sleep(1)  # Rate limit mitigation

                with lock:
                    results["port_descriptions"][ip] = port_descriptions
                    update_task_progress(scan_record, f"port_description_{ip}", "completed", f"Descriptions fetched for {len(port_descriptions)} ports on IP {ip}", port_descriptions)
                    print(f"[+] Port description fetch completed for {len(port_descriptions)} ports on IP {ip}")
            else:
                with lock:
                    results["port_descriptions"][ip] = {"error": "No ports found for description"}
                    update_task_progress(scan_record, f"port_description_{ip}", "skipped", f"No ports found for IP {ip}")
                    print(f"[+] Port description fetch skipped for IP {ip}: No ports found")

        print(f"[+] Shodan and nrich scans completed for {len(targets)} targets")


    def subdomain_task():
        """Run subdomain discovery, active subdomain checks, and initiate subsequent tasks."""
        print(f"[+] Performing subdomain discovery for {domain}")
        logger.debug(f"Starting subdomain discovery for {domain}")
        update_task_progress(scan_record, "subdomain_discovery", "in_progress", f"Discovering subdomains for {domain}")
        try:
            subdomains_data = full_sd(domain)
            subdomains = list(set(subdomains_data.get('subdomains', [])))
            total_subdomains = len(subdomains)
            logger.info(f"Discovered {total_subdomains} subdomains for {domain}")
            with lock:
                results["subdomains"] = subdomains + [domain]
                update_task_progress(scan_record, "subdomain_discovery", "completed", f"Discovered {total_subdomains} subdomains", {"subdomains": subdomains})
                print(f"[+] Subdomain discovery completed for {domain}: {total_subdomains} subdomains")

            if total_subdomains > 100:
                logger.info(f"Subdomain count ({total_subdomains}) exceeds 100 for {domain}, checking only {domain}")
                print(f"[+] Checking connectivity for {domain} (subdomain count exceeds 100)")
                update_task_progress(scan_record, "subdomain_activity", "in_progress", f"Found {total_subdomains} subdomains, checking connectivity for {domain}")
                status = check_subdomain_activity(domain)
                with lock:
                    if status["active"]:
                        results["active_subdomains"].append({
                            "active": True,
                            "subdomain": domain,
                            "http_status": status["http_status"],
                            "https_status": status["https_status"],
                            "http_active": status["http_active"],
                            "https_active": status["https_active"]
                        })
                    update_task_progress(scan_record, "subdomain_activity", "completed" if status["active"] else "error",
                                        f"Connectivity check for {domain} {'completed' if status['active'] else 'failed: Unable to connect'}",
                                        {"domain": domain, "status": status})
                    logger.debug(f"Connectivity check for {domain} {'completed' if status['active'] else 'failed: Unable to connect'}")
                    print(f"[+] Connectivity check completed for {domain}")
                targets = [domain]
            else:
                targets = list(set(subdomains + [domain]))
                logger.debug(f"Checking connectivity for {len(targets)} targets: {targets}")
                print(f"[+] Checking connectivity for {len(targets)} subdomains")
                for sub in targets:
                    update_task_progress(scan_record, "subdomain_activity", "in_progress", f"Checking connectivity for {sub}")
                    status = check_subdomain_activity(sub)
                    with lock:
                        if status["active"]:
                            results["active_subdomains"].append({
                                "active": True,
                                "subdomain": sub,
                                "http_status": status["http_status"],
                                "https_status": status["https_status"],
                                "http_active": status["http_active"],
                                "https_active": status["https_active"]
                            })
                        update_task_progress(scan_record, "subdomain_activity", "completed" if status["active"] else "error",
                                            f"Connectivity check for {sub} {'completed' if status['active'] else 'failed: Unable to connect'}",
                                            {"subdomain": sub, "status": status})
                        logger.debug(f"Connectivity check for {sub} {'completed' if status['active'] else 'failed: Unable to connect'}")
                print(f"[+] Connectivity check completed for {len(targets)} subdomains")

            with lock:
                logger.debug(f"Active subdomains found: {len(results['active_subdomains'])}")
                if len(results["active_subdomains"]) > 10:
                    logger.info(f"More than 10 active subdomains found ({len(results['active_subdomains'])}), limiting to {domain}")
                    print(f"[+] Limiting to {domain} due to {len(results['active_subdomains'])} active subdomains")
                    update_task_progress(scan_record, "target_selection", "completed", f"Found {len(results['active_subdomains'])} active subdomains, focusing on {domain}")
                    targets = [domain]
                else:
                    logger.debug(f"Selecting targets for detailed scans from {len(results['active_subdomains'])} active subdomains")
                    targets = [sub["subdomain"] for sub in results["active_subdomains"]]
                    if domain not in targets and any(sub["subdomain"] == domain for sub in results["active_subdomains"]):
                        targets.append(domain)
                    update_task_progress(scan_record, "target_selection", "completed", f"Selected {len(targets)} targets for detailed scans")
                    logger.debug(f"Selected {len(targets)} targets for detailed scans: {targets}")
                    print(f"[+] Selected {len(targets)} targets for detailed scans")

            nonlocal subsequent_threads
            subsequent_threads = [
                threading.Thread(target=ssl_task, args=(targets,)),
                threading.Thread(target=dns_task, args=(targets,)),
                threading.Thread(target=http_status_task, args=(targets,)),
                threading.Thread(target=shodan_nrich_task, args=(targets,))
            ]
            print(f"[+] Starting subsequent scans (SSL, DNS, HTTP/HTTPS, Shodan/nrich) for {len(targets)} targets")
            logger.debug(f"Starting subsequent threads for SSL, DNS, HTTP/HTTPS status, and Shodan/nrich")
            for thread in subsequent_threads:
                thread.start()
        except Exception as e:
            logger.error(f"Subdomain task failed for {domain}: {str(e)}")
            print(f"[+] Subdomain discovery failed for {domain}: {str(e)}")
            with lock:
                update_task_progress(scan_record, "subdomain_discovery", "error", f"Subdomain discovery failed: {str(e)}")

    def compile_report():
        """Compile the final report from thread results.

        Modified port counting:
        - For each IP, prefer ports discovered by the port scanner (results["port_map"][ip]).
        - If port scanner returned an empty list for an IP, fallback to Shodan ports (results["shodan_data"][ip]["ports"]).
        - Normalize port values (strings -> ints) and ignore invalid entries.
        - Summary["ports"] contains the count of UNIQUE ports across all IPs.
        - Also updates results["port_map"] to include Shodan-derived ports where scanner returned empty.
        """
        print(f"[+] Compiling attack surface report for {domain}")
        # Basic counts (unchanged)
        num_subdomains = len(results["subdomains"])
        num_ip_addresses = len(set(ip for ips in results["ip_address_map"].values() for ip in ips))

        # DNS records count
        num_dns_records = 0
        for sub in results["dns_records"]:
            for rtype in results["dns_records"][sub]:
                num_dns_records += len(results["dns_records"][sub].get(rtype, []))

        if "error" not in results.get("email_hygiene", {}):
            if results["email_hygiene"].get("spf", {}).get("Records"):
                num_dns_records += 1
            num_dns_records += len(results["email_hygiene"].get("dkim", {}).get("Records", []))
            if results["email_hygiene"].get("dmarc", {}).get("Records"):
                num_dns_records += 1
            if results["email_hygiene"].get("bimi", {}).get("Records"):
                num_dns_records += 1

        num_technologies = sum(len(results["shodan_data"].get(ip, {}).get("technologies", [])) for ip in results["shodan_data"])
        num_ssl_records = sum(1 for sub in results["ssl_comprehensive"] if "error" not in results["ssl_comprehensive"].get(sub, {}))
        num_whois_records = 1 if "error" not in results.get("whois", {}) else 0

        # Count only non-empty Wapiti vulnerabilities
        num_vulnerabilities = 0
        try:
            if results.get("wapiti"):
                for key, value in results["wapiti"].get("vulnerabilities", {}).items():
                    if isinstance(value, list) and len(value) > 0:
                        num_vulnerabilities += 1
        except Exception:
            num_vulnerabilities = 0

        # --- Port counting: prefer port_map, fallback to shodan ---
        unique_ports = set()
        total_ports_by_ip = {}  # keep a per-ip resolved list for possible debugging/reporting

        # Determine IP list to iterate over: union of keys from port_map and shodan_data
        port_map_ips = set(results.get("port_map", {}).keys())
        shodan_ips = set(results.get("shodan_data", {}).keys())
        all_ips = port_map_ips.union(shodan_ips)

        for ip in all_ips:
            # Prefer scanner data if it exists and is non-empty
            ports_from_scanner = results.get("port_map", {}).get(ip, []) or []
            resolved_ports = []

            if ports_from_scanner:
                # normalize to ints where possible
                for p in ports_from_scanner:
                    try:
                        resolved_ports.append(int(p))
                    except Exception:
                        # try to extract digits if it's a string like "80/udp"
                        try:
                            digits = re.findall(r"\d+", str(p))
                            if digits:
                                resolved_ports.append(int(digits[0]))
                        except Exception:
                            continue
            else:
                # fallback to shodan
                shodan_entry = results.get("shodan_data", {}).get(ip, {})
                shodan_ports = shodan_entry.get("ports", []) if isinstance(shodan_entry, dict) else []
                for p in shodan_ports or []:
                    try:
                        resolved_ports.append(int(p))
                    except Exception:
                        try:
                            digits = re.findall(r"\d+", str(p))
                            if digits:
                                resolved_ports.append(int(digits[0]))
                        except Exception:
                            continue
                # Update results["port_map"] so the report includes the fallback ports (keeps original empty scanner lists replaced)
                if resolved_ports:
                    # store as list of ints for consistency
                    results.setdefault("port_map", {})[ip] = resolved_ports

            # Deduplicate per-IP and add to global unique set
            resolved_ports = list(set(resolved_ports))
            total_ports_by_ip[ip] = resolved_ports
            for p in resolved_ports:
                unique_ports.add(p)

        # Final port metrics
        num_unique_ports = len(unique_ports)

        # Keep backward compatibility: summary["ports"] previously expected a single number.
        # We set it to the number of unique ports across all IPs (this prevents double-counting the same service on multiple IPs).
        num_ports = num_unique_ports

        # Count unique CVEs from Shodan and nrich
        unique_cves = set()
        for ip in results.get("shodan_data", {}):
            if "vulns" in results["shodan_data"][ip]:
                try:
                    unique_cves.update(results["shodan_data"][ip].get("vulns", []))
                except Exception:
                    pass
        for ip in results.get("nrich_data", {}):
            if "error" not in results["nrich_data"].get(ip, {}):
                if "vulns" in results["nrich_data"][ip]:
                    try:
                        unique_cves.update(results["nrich_data"][ip].get("vulns", []))
                    except Exception:
                        pass

        summary = {
            "subdomains": num_subdomains,
            "ip_addresses": num_ip_addresses,
            "dns_records": num_dns_records,
            "technologies": num_technologies,
            "ssl_records": num_ssl_records,
            "whois_records": num_whois_records,
            "vulnerabilities": num_vulnerabilities,
            "ports": num_ports,               # number of unique ports across all IPs (uses shodan fallback)
            "cves": len(unique_cves)
        }

        # Include the (possibly updated) port_map in the report so callers see the shodan-fallback ports
        report = {
            "domain": domain,
            "scan_type": scan_type,
            "subdomains": results["subdomains"],
            "ports": results.get("port_map", {}),
            "ip_addresses": results["ip_address_map"],
            "active_subdomains": results["active_subdomains"],
            "dns_records": results["dns_records"],
            "email_hygiene": results["email_hygiene"],
            "whois": results["whois"],
            "wapiti_report": results["wapiti"],
            "shodan": results["shodan_data"],
            "nrich": results["nrich_data"],
            "technology_descriptions": results["technology_descriptions"],
            "vulnerability_descriptions": results["vulnerability_descriptions"],
            "port_descriptions": results["port_descriptions"],
            "ssl_comprehensive": results["ssl_comprehensive"],
            "http_status": results["http_status"],
            "summary": summary,
            "generated_at": now().strftime("%Y-%m-%d %H:%M:%S")
        }

        with lock:
            scan_record.jsondata = report
            scan_record.status = "completed"
            scan_record.scanned_at = now()
            scan_record.save()
            logger.info(f"Attack surface report compiled for {domain}: {summary}")
            print(f"[+] Attack surface report compilation completed for {domain}")
        return report


    try:
        stop_event = threading.Event()
        wapiti_thread = threading.Thread(target=wapiti_task, args=(wapiti_queue, stop_event, domain, scan_record, results, lock))
        whois_thread = threading.Thread(target=whois_task)
        email_hygiene_thread = threading.Thread(target=email_hygiene_task)
        subdomain_thread = threading.Thread(target=subdomain_task)

        threads = [wapiti_thread, whois_thread, email_hygiene_thread, subdomain_thread]
        for thread in threads:
            thread.start()

        timeout = 300
        start_time = time.time()
        while time.time() - start_time < timeout:
            if wapiti_queue.qsize() > 0:
                wapiti_queue.get()
                break
            time.sleep(1)
        else:
            stop_event.set()
            logger.warning(f"Wapiti scan for {domain} timed out after {timeout} seconds")
            print(f"[+] Wapiti scan timed out for {domain}")

        for thread in threads:
            thread.join(timeout=timeout - (time.time() - start_time))
            if thread.is_alive():
                logger.warning(f"Thread {thread.name} for {domain} did not complete within timeout")
                print(f"[+] Thread {thread.name} did not complete for {domain}")

        for thread in subsequent_threads:
            thread.join(timeout=timeout - (time.time() - start_time))
            if thread.is_alive():
                logger.warning(f"Subsequent thread {thread.name} for {domain} did not complete within timeout")
                print(f"[+] Subsequent thread {thread.name} did not complete for {domain}")

        report = compile_report()
        return report
    except Exception as e:
        logger.error(f"Error generating attack surface report for {domain}: {str(e)}")
        print(f"[+] Attack surface report generation failed for {domain}: {str(e)}")
        with lock:
            update_task_progress(scan_record, "initialization", "error", f"Scan failed: {str(e)}")
            scan_record.status = "error"
            scan_record.jsondata = {"error": str(e)}
            scan_record.save()
        return {"error": str(e)}

def run_scan_in_background(domain, scan_type):
    """Run a scan in a background thread."""
    print(f"[+] Starting background scan for {domain} ({scan_type})")
    def scan_task():
        try:
            logger.info(f"Starting background scan for {domain} ({scan_type})")
            scan_record, _ = AttackSurfaceScan.objects.get_or_create(
                domain=domain,
                scan_type=scan_type,
                defaults={"status": "pending", "jsondata": {}, "progress": []}
            )
            report = generate_attack_surface_report(domain, scan_type)
            scan_record.jsondata = report
            scan_record.status = "completed"
            scan_record.scanned_at = now()
            scan_record.save()
            logger.info(f"Scan completed and saved for {domain} ({scan_type})")
            print(f"[+] Background scan completed for {domain} ({scan_type})")
        except Exception as e:
            scan_record, _ = AttackSurfaceScan.objects.get_or_create(
                domain=domain,
                scan_type=scan_type,
                defaults={"status": "pending", "jsondata": {}, "progress": []}
            )
            scan_record.jsondata = {"error": str(e)}
            scan_record.status = "error"
            scan_record.scanned_at = now()
            scan_record.save()
            logger.error(f"Scan failed for {domain} ({scan_type}): {str(e)}")
            print(f"[+] Background scan failed for {domain} ({scan_type}): {str(e)}")
            traceback.print_exc()
        finally:
            active_threads.pop((domain, scan_type), None)
            logger.info(f"Thread for {domain} ({scan_type}) completed")
            print(f"[+] Thread completed for {domain} ({scan_type})")
    if (domain, scan_type) not in active_threads:
        logger.info(f"Started new scan thread for {domain} ({scan_type})")
        print(f"[+] Starting new scan thread for {domain} ({scan_type})")
        thread = threading.Thread(target=scan_task)
        thread.daemon = True
        thread.start()
        active_threads[(domain, scan_type)] = True
        return True
    print(f"[+] Scan thread already active for {domain} ({scan_type})")
    return False

class AttackSurfaceAPI(APIView):
    # permission_classes = [IsAuthenticated]
    def get(self, request):
        """Handle GET requests for attack surface scans."""
        domain = request.query_params.get("domain", "").strip()
        scan_type = request.query_params.get("scan_type", "complete").strip()
        if not domain:
            print(f"[+] GET request failed: Domain parameter is required")
            return Response({"error": "Domain parameter is required"}, status=status.HTTP_400_BAD_REQUEST)
        if not re.match(r'^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$', domain):
            print(f"[+] GET request failed: Invalid domain format")
            return Response({"error": "Invalid domain format"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            # Check for existing scan (pending or recently completed)
            existing_scan = AttackSurfaceScan.objects.filter(domain=domain, scan_type=scan_type).first()
            if existing_scan:
                existing_scan.refresh_from_db()
                required_tasks = ["wapiti", "whois", "email_hygiene", "subdomain_discovery", "subdomain_activity", "target_selection", "dns_records", "ip_resolution"]
                progress = existing_scan.progress or []
                completed_tasks = {p["task_name"] for p in progress if p["status"] in ["completed", "skipped", "error"]}
                all_tasks_done = all(task in completed_tasks for task in required_tasks)
                
                if existing_scan.status == "pending" or (domain, scan_type) in active_threads:
                    logger.info(f"Scan pending for {domain} ({scan_type}) - Status 202 - Progress: {existing_scan.progress}")
                    print(f"[+] Returning pending scan status for {domain} ({scan_type})")
                    return Response({
                        "message": "Scan in progress",
                        "domain": domain,
                        "scan_type": scan_type,
                        "progress": progress
                    }, status=status.HTTP_202_ACCEPTED)
                
                # Check if the existing scan is recent and completed
                age = now() - existing_scan.scanned_at
                if (age <= timedelta(days=1) and existing_scan.status == "completed" and
                    "error" not in existing_scan.jsondata):
                    logger.info(f"Returning cached scan data for {domain} ({scan_type})")
                    print(f"[+] Returning cached scan data for {domain} ({scan_type})")
                    existing_scan.progress.append({
                        "task_name": "cached_result",
                        "status": "completed",
                        "message": f"Retrieved cached scan results for {domain}",
                        "timestamp": now().strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "jsondata": {}
                    })
                    existing_scan.save()
                    response_data = {
                        "message": "Scan completed",
                        "domain": domain,
                        "scan_type": scan_type,
                        **existing_scan.jsondata
                    }
                    print(f"[+] GET request completed: Cached scan returned for {domain} ({scan_type})")
                    return Response(response_data, status=status.HTTP_200_OK)
                
                # If the existing scan is outdated or failed, delete it to allow a new scan
                logger.info(f"Deleting outdated or failed scan for {domain} ({scan_type})")
                print(f"[+] Deleting outdated or failed scan for {domain} ({scan_type})")
                existing_scan.delete()

            # No active or valid scan exists, initiate a new one
            logger.info(f"Scan initiated for {domain} ({scan_type}) - Status 202")
            print(f"[+] Initiating new scan for {domain} ({scan_type})")
            with transaction.atomic():
                record = AttackSurfaceScan.objects.create(
                    domain=domain,
                    scan_type=scan_type,
                    status="pending",
                    jsondata={},
                    progress=[]
                )
            record.progress.append({
                "task_name": "initialization",
                "status": "in_progress",
                "message": f"Preparing to scan {domain}",
                "timestamp": now().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "jsondata": {}
            })
            record.save()
            run_scan_in_background(domain, scan_type)
            record.refresh_from_db()
            print(f"[+] GET request completed: Scan initiated for {domain} ({scan_type})")
            return Response({
                "message": "Scan initiated",
                "domain": domain,
                "scan_type": scan_type,
                "progress": record.progress or []
            }, status=status.HTTP_202_ACCEPTED)
        except Exception as e:
            logger.error(f"API error for {domain} ({scan_type}): {str(e)}")
            print(f"[+] GET request failed for {domain} ({scan_type}): {str(e)}")
            # Delete the scan record if it exists
            try:
                AttackSurfaceScan.objects.filter(domain=domain, scan_type=scan_type).delete()
                logger.info(f"Deleted scan record for {domain} ({scan_type}) due to exception")
                print(f"[+] Deleted scan record for {domain} ({scan_type}) due to exception")
            except Exception as delete_error:
                logger.error(f"Failed to delete scan record for {domain} ({scan_type}): {str(delete_error)}")
                print(f"[+] Failed to delete scan record for {domain} ({scan_type}): {str(delete_error)}")
            return Response({
                "message": "Scan initiation failed",
                "domain": domain,
                "scan_type": scan_type,
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class CveDetailsAPI(APIView):
    # permission_classes = [IsAuthenticated]
    def get(self, request):
        """Handle GET requests to retrieve CVE details by cve_id."""
        cve_id = request.query_params.get("cve_id", "").strip()
        if not cve_id:
            print(f"[+] GET request failed: cve_id parameter is required")
            return Response({"error": "cve_id parameter is required"}, status=status.HTTP_400_BAD_REQUEST)
        if not re.match(r'^CVE-\d{4}-\d{4,7}$', cve_id):
            print(f"[+] GET request failed: Invalid CVE ID format for {cve_id}")
            return Response({"error": "Invalid CVE ID format. Expected format: CVE-YYYY-NNNN"}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            cve_data = get_cve_data(cve_id)
            if cve_data["status"] == "success":
                logger.info(f"Successfully retrieved CVE data for {cve_id}")
                print(f"[+] GET request completed: CVE data retrieved for {cve_id}")
                return Response({
                    "message": "CVE data retrieved successfully",
                    "cve_id": cve_id,
                    **cve_data
                }, status=status.HTTP_200_OK)
            else:
                logger.warning(f"Failed to retrieve CVE data for {cve_id}: {cve_data.get('message', 'Unknown error')}")
                print(f"[+] GET request failed for {cve_id}: {cve_data.get('message', 'Unknown error')}")
                return Response({
                    "message": "Failed to retrieve CVE data",
                    "cve_id": cve_id,
                    "error": cve_data.get("message", "Unknown error")
                }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Error retrieving CVE data for {cve_id}: {str(e)}")
            print(f"[+] GET request failed for {cve_id}: {str(e)}")
            return Response({
                "message": "Error retrieving CVE data",
                "cve_id": cve_id,
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class AttackSurface(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request, *args, **kwargs):
        """Handle synchronous attack surface scan requests."""
        print(f"[+] Handling synchronous attack surface scan request")
        try:
            domain = request.query_params.get('domain', '').strip()
            scan_type = request.query_params.get('scan_type', 'complete')
            if not domain:
                print(f"[+] Synchronous scan failed: Domain parameter is required")
                return Response({"error": "Domain parameter is required."}, status=status.HTTP_400_BAD_REQUEST)
            if not re.match(r'^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$', domain):
                print(f"[+] Synchronous scan failed: Invalid domain format")
                return Response({"error": "Invalid domain format."}, status=status.HTTP_400_BAD_REQUEST)
            report = generate_attack_surface_report(domain, scan_type)
            print(f"[+] Synchronous attack surface scan completed for {domain} ({scan_type})")
            return Response(report, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"AttackSurface error for {domain}: {str(e)}")
            print(f"[+] Synchronous attack surface scan failed for {domain}: {str(e)}")
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)