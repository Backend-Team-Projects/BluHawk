import http.client
import urllib.parse
from urllib.parse import quote
import requests 
from pystyle import Colors, Write
from phonenumbers import geocoder, carrier
import phonenumbers
import os
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
import dns.resolver
from dns import reversename
from email_validator import validate_email, EmailNotValidError
from urllib.parse import quote
import secrets
import json
from bs4 import BeautifulSoup
import re
from email.parser import Parser
import whois
from tqdm import tqdm
from datetime import datetime
import openai
import magic
import stat
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
import PyPDF2
import openpyxl
import docx
from docx.opc.constants import RELATIONSHIP_TYPE as RT
from pptx import Presentation
from mutagen.easyid3 import EasyID3
from mutagen.mp3 import MP3
from mutagen.mp4 import MP4
from mutagen.id3 import ID3
from mutagen.flac import FLAC
import wave
from mutagen.oggvorbis import OggVorbis
from tinytag import TinyTag

from BluHawk.utils import log_exception

default_color = Colors.red
API_KEY = "INSERT GOOGLE CUSTOM SEARCH API KEY HERE"
CX = "INSERT GOOGLE CX KEY HERE"
CLIENT_ID = "INSERT GOOGLE CLIENT KEY HERE"
HIBP_API_KEY = "INSERT HAVE I BEEN PWNED API KEY HERE"

_global_session = requests.Session()
default_color = Colors.light_red
requests.get = _global_session.get

import multiprocessing
MAX_WORKERS = min(32, (multiprocessing.cpu_count() or 1) * 5)

def validate_domain_input(domain):
    if not domain or len(domain) > 253 or ".." in domain:
        return False
    pattern = r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, domain))

def log_option(output_text):
    print()
    print("[?] Would you like to save this output to a log file? (Y/N): ", end="")
    choice = input().strip().upper()
    if choice == 'Y':
        stamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S] ")
        with open("clatscope_log.txt", "a", encoding="utf-8") as log_file:
            log_file.write(f"{stamp}{output_text}\n\n")
        Write.Print("[!] > Output has been saved to clatscope_log.txt\n", default_color, interval=0)

def export_json(data, filename_prefix="output"):
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{filename_prefix}_{stamp}.json"
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        Write.Print(f"[!] > JSON Export complete: {filename}\n", Colors.green, interval=0)
    except Exception as e:
        Write.Print(f"[!] > Failed to write JSON file: {str(e)}\n", Colors.red, interval=0)

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def restart():
    return
    Write.Input("\nPress Enter to return to the main menu...", default_color, interval=0)
    clear()

def get_ip_details(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=60)
        response.raise_for_status()
        return response.json()
    except:
        return None

def ip_info(ip, **kwargs):
    url = f"https://ipinfo.io/{ip}/json"
    result = {
        "status": "error",
        "message": "Error retrieving IP address info",
        'data': {}
    }
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        loc = data.get('loc', 'None')
        maps_link = f"https://www.google.com/maps?q={loc}" if loc != 'None' else 'None'
        
        # Write.Print(ip_details, Colors.white, interval=0)

        result['status'] = 'success'
        result['message'] = 'IP address info retrieved successfully'
        result['data'] = {
            "ip_address": data.get('ip', 'None'),
            "city": data.get('city', 'None'),
            "region": data.get('region', 'None'),
            "country": data.get('country', 'None'),
            "postal_code": data.get('postal', 'None'),
            "ISP": data.get('org', 'None'),
            "coordinates": loc,
            "timezone": data.get('timezone', 'None'),
            "location": maps_link
        }
        return result

    except:
        return result

def subdomain_enumeration(domain):
    import requests
    from datetime import datetime
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    Write.Print(f"\n[!] Subdomain enumeration for: {domain}\n", Colors.white, interval=0)
    try:
        resp = requests.get(url, timeout=60)
        if resp.status_code == 200:
            try:
                data = resp.json()
            except json.JSONDecodeError:
                msg = "[!] > Error: crt.sh returned non-JSON or empty data.\n"
                Write.Print(msg, Colors.red, interval=0)
                return
            found_subs = set()
            for entry in data:
                if 'name_value' in entry:
                    for subd in entry['name_value'].split('\n'):
                        subd_strip = subd.strip()
                        if subd_strip and subd_strip != domain:
                            found_subs.add(subd_strip)
                elif 'common_name' in entry:
                    c = entry['common_name'].strip()
                    if c and c != domain:
                        found_subs.add(c)
            if found_subs:
                out_text = f"\n[+] Found {len(found_subs)} subdomains for {domain}:\n"
                for s in sorted(found_subs):
                    out_text += f"    {s}\n"
                Write.Print(out_text, Colors.green, interval=0)
                print()
                print("[?] Would you like to save this output to a log file? (Y/N): ", end="")
                choice = input().strip().upper()
                if choice == 'Y':
                    stamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S] ")
                    with open("clatscope_log.txt", "a", encoding="utf-8") as f:
                        f.write(stamp + out_text + "\n")
                    Write.Print("[!] > Subdomains saved to clatscope_log.txt\n", Colors.white, interval=0)

                print("[?] Export subdomains as JSON? (Y/N): ", end="")
                if input().strip().upper() == "Y":
                    export_json(list(found_subs), filename_prefix="subdomains")

            else:
                Write.Print("[!] > No subdomains found.\n", Colors.red, interval=0)
        else:
            err = f"[!] > HTTP {resp.status_code} from crt.sh\n"
            Write.Print(err, Colors.red, interval=0)
    except Exception as exc:
        Write.Print(f"[!] > Subdomain enumeration error: {exc}\n", Colors.red, interval=0)

def person_search(first_name, last_name, city):
    query = f"{first_name} {last_name} {city}"
    payload_person_search = {
        "model": "sonar-reasoning-pro",
        "messages": [
            {
                "role": "system",
                "content": (
                    "When searching for information about [PERSON NAME], please provide a comprehensive analysis that includes:"
                    "their full name including any variations or aliases; date and place of birth (if known); current location or"
                    "place of death if deceased; educational background including institutions and years of attendance; professional"
                    "history with dates and notable achievements; any significant public roles or positions held; major life events"
                    "or controversies; family connections and relationships relevant to their public life; and their current status"
                    "or most recent known activities. For any claims made, include specific citations using [Source X] notation"
                    "within the text, where X corresponds to the numbered source in the reference list. Each piece of information"
                    "should be attributed to at least one credible source, with preference given to primary sources, official records,"
                    "reputable news organizations, and peer-reviewed academic works where applicable. Avoid speculation beyond verifiable"
                    "data. When researching [PERSON NAME], first verify the specific individual by their distinguishing characteristics"
                    "(occupation, time period, location, or notable achievements). If the person has appeared in a news article or public interview, discuss the details of it."
                    "If multiple people share similar names, acknowledge their existence at the beginning of your response like this: Note: There are other notable individuals named"
                    "[Similar Name], including [Brief one-line identifier for each]. This analysis focuses on [Target Person] who is known for [Key Identifier]."
                    "Then proceed with the detailed analysis of only the target individual, including their background, achievements, and current status."
                    "If you cannot confidently distinguish between similarly named individuals based on the available context, state this uncertainty clearly"
                    "and list the potential matches with their key identifiers, requesting additional details to ensure accurate identification. All information"
                    "should be properly cited using numbered references, and only include verified information about the specific target individual. At the end of the analysis,"
                    "provide a numbered list of all sources cited, including full bibliographic information (author, title, publication, date, URL if applicable) in Chicago style format."
                    "If any critical information is missing orunverifiable, explicitly note these gaps in the analysis. Include information about their current job, employment status, and other relevant professional information."
                )
            },
            {
                "role": "user",
                "content": f"Provide detailed background or publicly known information about: {query}"
            }
        ],
        "max_tokens": 8000,
        "temperature": 1.1
    }
    PERPLEXITY_API_URL = "https://api.perplexity.ai/chat/completions"
    PERPLEXITY_API_KEY = "INSERT API KEY HERE"
    perplexity_headers = {
        "Authorization": f"Bearer {PERPLEXITY_API_KEY}",
        "Content-Type": "application/json",
    }
    results_text = ""
    try:
        response = requests.post(PERPLEXITY_API_URL, headers=perplexity_headers, json=payload_person_search)
        if response.status_code == 200:
            data = response.json()
            info_content = data["choices"][0]["message"]["content"]
            results_text = (
                f"\nPERSON SEARCH RESULTS\n"
                f"=====================\n\n"
                f"NAME:\n{first_name} {last_name}\n\n"
                f"LOCATION:\n{city}\n\n"
                f"PUBLIC INFORMATION:\n{info_content}\n"
            )
        else:
            results_text = f"[!] > Error from Perplexity: HTTP {response.status_code}\n{response.text}\n"
    except Exception as e:
        results_text = f"[!] > Error: {str(e)}\n"
    clear()
    Write.Print(results_text, Colors.white, interval=0)
    log_option(results_text)
    print("[?] Export person search as JSON? (Y/N): ", end="")
    if input().strip().upper() == "Y":
        export_json({"search_query": query, "results": results_text}, filename_prefix="person_search")
    restart()

def deep_account_search(nickname, **kwargs):
    sites = [
        "https://youtube.com/@{target}",
        "https://facebook.com/{target}",
        "https://wikipedia.org/wiki/User:{target}",
        "https://instagram.com/{target}",
        "https://reddit.com/user/{target}",
        "https://medium.com/@{target}",
        "https://www.quora.com/profile/{target}",
        "https://bing.com/{target}",
        "https://x.com/{target}",
        "https://yandex.ru/{target}",
        "https://whatsapp.com/{target}",
        "https://yahoo.com/{target}",
        "https://amazon.com/{target}",
        "https://duckduckgo.com/{target}",
        "https://yahoo.co.jp/{target}",
        "https://tiktok.com/@{target}",
        "https://msn.com/{target}",
        "https://netflix.com/{target}",
        "https://weather.com/{target}",
        "https://live.com/{target}",
        "https://naver.com/{target}",
        "https://microsoft.com/{target}",
        "https://twitch.tv/{target}",
        "https://office.com/{target}",
        "https://vk.com/{target}",
        "https://pinterest.com/{target}",
        "https://discord.com/{target}",
        "https://aliexpress.com/{target}",
        "https://github.com/{target}",
        "https://adobe.com/{target}",
        "https://rakuten.co.jp/{target}",
        "https://ikea.com/{target}",
        "https://bbc.co.uk/{target}",
        "https://amazon.co.jp/{target}",
        "https://speedtest.net/{target}",
        "https://samsung.com/{target}",
        "https://healthline.com/{target}",
        "https://medlineplus.gov/{target}",
        "https://roblox.com/users/{target}/profile",
        "https://cookpad.com/{target}",
        "https://indiatimes.com/{target}",
        "https://mercadolivre.com.br/{target}",
        "https://britannica.com/{target}",
        "https://merriam-webster.com/{target}",
        "https://hurriyet.com.tr/{target}",
        "https://steamcommunity.com/user/{target}",
        "https://booking.com/{target}",
        "https://support.google.com/{target}",
        "https://bbc.com/{target}",
        "https://playstation.com/{target}",
        "https://ebay.com/usr/{target}",
        "https://poki.com/{target}",
        "https://walmart.com/{target}",
        "https://medicalnewstoday.com/{target}",
        "https://gov.uk/{target}",
        "https://nhs.uk/{target}",
        "https://detik.com/{target}",
        "https://cricbuzz.com/{target}",
        "https://nih.gov/{target}",
        "https://uol.com.br/{target}",
        "https://ilovepdf.com/{target}",
        "https://clevelandclinic.org/{target}",
        "https://cnn.com/{target}",
        "https://globo.com/{target}",
        "https://nytimes.com/{target}",
        "https://taboola.com/{target}",
        "https://chaturbate.com/{target}",
        "https://redgifs.com/users/{target}",
        "https://tinder.com/{target}",
        "https://pof.com/{target}",
        "https://match.com/{target}",
        "https://eharmony.com/{target}",
        "https://bumble.com/{target}",
        "https://okcupid.com/{target}",
        "https://Badoo.com/{target}",
        "https://dating.com/{target}",
        "https://trello.com/{target}",
        "https://mapquest.com/{target}",
        "https://zoom.com/{target}",
        "https://apple.com/{target}",
        "https://dropbox.com/{target}",
        "https://weibo.com/{target}",
        "https://wordpress.com/{target}",
        "https://cloudflare.com/{target}",
        "https://salesforce.com/{target}",
        "https://fandom.com/{target}",
        "https://paypal.com/{target}",
        "https://soundcloud.com/{target}",
        "https://forbes.com/{target}",
        "https://theguardian.com/{target}",
        "https://hulu.com/{target}",
        "https://stackoverflow.com/users/{target}",
        "https://businessinsider.com/{target}",
        "https://huffpost.com/{target}",
        "https://booking.com/{target}",
        "https://pastebin.com/u/{target}",
        "https://producthunt.com/@{target}",
        "https://pypi.org/user/{target}",
        "https://slideshare.com/{target}",
        "https://strava.com/athletes/{target}",
        "https://tldrlegal.com/{target}",
        "https://t.me/{target}",
        "https://last.fm/user{target}",
        "https://data.typeracer.com/pit/profile?user={target}",
        "https://tryhackme.com/p/{target}",
        "https://trakt.tv/users/{target}",
        "https://scratch.mit.edu/users/{target}",
        "https://replit.com?{target}",
        "https://hackaday.io/{target}",
        "https://freesound.org/people/{target}",
        "https://hub.docker.com/u/{target}",
        "https://disqus.com/{target}",
        "https://www.codecademy.com/profiles/{target}",
        "https://www.chess.com/member/{target}",
        "https://bitbucket.org/{target}",
        "https://www.twitch.tv?{target}",
        "https://wikia.com/wiki/User:{target}",
        "https://steamcommunity.com/groups{target}",
        "https://keybase.io?{target}",
        "http://en.gravatar.com/{target}",
        "https://vk.com/{target}",
        "https://deviantart.com/{target}",
        "https://www.behance.net/{target}",
        "https://vimeo.com/{target}",
        "https://www.youporn.com/user/{target}",
        "https://profiles.wordpress.org/{target}",
        "https://tryhackme.com/p/{target}",
        "https://www.scribd.com/{target}",
        "https://myspace.com/{target}",
        "https://genius.com/{target}",
        "https://genius.com/artists/{target}",
        "https://www.flickr.com/people/{target}",
        "https://www.fandom.com/u/{target}",
        "https://www.chess.com/member/{target}",
        "https://buzzfeed.com/{target}",
        "https://www.buymeacoffee.com/{target}",
        "https://about.me/{target}",
        "https://discussions.apple.com/profile/{target}",
        "https://giphy.com/{target}",
        "https://scholar.harvard.edu/{target}",
        "https://www.instructables.com/member/{target}",
        "http://www.wikidot.com/user:info/{target}",
        "https://erome.com/{target}",
        "https://www.alik.cz/u/{target}",
        "https://rblx.trade/p/{target}",
        "https://www.paypal.com/paypalme/{target}",
        "https://hackaday.io/{target}",
        "https://connect.garmin.com/modern/profile/{target}"
    ]
    
    result_json = {
        'status': "error",
        'message': "Error retrieving social media accounts",
        'data': {}
    }
    try:
        urls = [site_format.format(target=nickname) for site_format in sites]

        def check_url(url):
            try:
                response = requests.get(url, timeout=60)
                status_code = response.status_code
                if status_code == 200:
                    return {"url": url, "status": "found", "code": 200}
                elif status_code == 404:
                    return {"url": url, "status": "not_found", "code": 404}
                else:
                    return {"url": url, "status": "error", "code": status_code}
            except requests.exceptions.Timeout:
                return {"url": url, "status": "timeout", "code": None}
            except requests.exceptions.ConnectionError:
                return {"url": url, "status": "connection_error", "code": None}
            except requests.exceptions.RequestException:
                return {"url": url, "status": "request_exception", "code": None}
            except Exception:
                return {"url": url, "status": "unexpected_error", "code": None}

        def fetch_social_urls(urls, title):
            with ThreadPoolExecutor() as executor:
                executor._max_workers = MAX_WORKERS
                results = list(executor.map(check_url, urls))
            return results

        results = fetch_social_urls(urls, "Deep Account Search")

        result_str = f"""
    ╭─{' '*78}─╮
    |{' '*27}Deep Account Search{' '*27}|
    |{'='*80}|
    """
        for r in results:
            if r["status"] == "found":
                result_str += f"| [+] > {r['url']:<50}|| Found{' '*14}|\n"
            elif r["status"] == "not_found":
                result_str += f"| [-] > {r['url']:<50}|| Not found{' '*9}|\n"
            elif r["status"] == "error":
                result_str += f"| [-] > {r['url']:<50}|| Error: {r['code']}{' '*6}|\n"
        result_str += f"╰─{' '*78}─╯"

        result_json['status'] = 'success'
        result_json['message'] = 'Social media accounts retrieved successfully'
        result_json['data'] = {
            "nickname": nickname,
            "results": results
        }

        return result_json
    except Exception as e:
        result_json['status'] = 'error'
        result_json['message'] = f"Error: {str(e)}"
        return result_json
    
def phone_info(phone_number, **kwargs):
    result = {
        "status": "error",
        "message": "Error retrieving phone number info",
        'data': {}
    }
    try:
        parsed_number = phonenumbers.parse(phone_number)
        country = geocoder.country_name_for_number(parsed_number, "en")
        region = geocoder.description_for_number(parsed_number, "en")
        operator = carrier.name_for_number(parsed_number, "en") if carrier else "" #the fix
        valid = phonenumbers.is_valid_number(parsed_number)
        validity = "Valid" if valid else "Invalid"

        result['status'] = 'success'
        result['message'] = 'Phone number info retrieved successfully'
        result['data'] = {
                "phone_number": phone_number,
                "country": country,
                "region": region,
                "operator": operator,
                "validity": validity
            }
        return result

    except phonenumbers.phonenumberutil.NumberParseException:
        return result
        # clear()
        # Write.Print(f"\n[!] > Error: invalid phone number format (+1-000-000-0000)", default_color, interval=0)
    restart()

def reverse_phone_lookup(phone_number):
    base_prompt = (
        "You are a specialized reverse phone lookup assistant that provides bidirectional search capabilities between phone numbers"
        "and individual/business names across public directories and databases. You search for phone numbers from a name or business name,"
        "or search for a name or business name based on a phone number. You help users find associated contact information. You clarify search"
        "parameters when needed and provide relevant contextual details about found associations."
    )
    payload = {
        "model": "sonar-reasoning-pro",
        "messages": [
            {"role": "system", "content": base_prompt},
            {"role": "user", "content": f"Perform a reverse lookup for: {phone_number}"}
        ],
        "max_tokens": 8000,
        "temperature": 1.1
    }
    PERPLEXITY_API_URL = "https://api.perplexity.ai/chat/completions"
    PERPLEXITY_API_KEY = "INSERT API KEY HERE"
    perplexity_headers = {
        "Authorization": f"Bearer {PERPLEXITY_API_KEY}",
        "Content-Type": "application/json",
    }
    try:
        response = requests.post(PERPLEXITY_API_URL, headers=perplexity_headers, json=payload, timeout=60)
        if response.status_code == 200:
            data = response.json()
            info_content = data["choices"][0]["message"]["content"]
        else:
            info_content = f"[!] > Error from Perplexity: HTTP {response.status_code}\n{response.text}\n"
    except Exception as e:
        info_content = f"[!] > Error: {str(e)}\n"
    clear()
    info_text = f"""
╭─{' '*78}─╮
|{' '*28}Reverse Phone Lookup{' '*28}|
|{'='*80}|
| [+] > Query: {phone_number:<66}|
|{'-'*80}|
{info_content}
╰─{' '*78}─╯
"""
    Write.Print(info_text, Colors.white, interval=0)
    log_option(info_text)
    print("[?] Export reverse phone lookup to JSON? (Y/N): ", end="")
    if input().strip().upper() == "Y":
        export_json({"phone_number": phone_number, "data": info_content}, filename_prefix="reverse_phone_lookup")
    restart()

def dns_lookup(domain, **kwargs):
    record_types = ['A', 'CNAME', 'MX', 'NS']
    result_output = f"""
╭─{' '*78}─╮
|{' '*33} DNS Lookup {' '*33}|
|{'='*80}|
"""
    for rtype in record_types:
        result_output += f"| [+] > {rtype} Records: {' '*62}|\n"
        try:
            answers = dns.resolver.resolve(domain, rtype)
            for ans in answers:
                if rtype == 'MX':
                    result_output += f"|    {ans.preference:<4} {ans.exchange:<70}|\n"
                else:
                    result_output += f"|    {str(ans):<76}|\n"
        except dns.resolver.NoAnswer:
            result_output += "|    No records found.\n"
        except dns.resolver.NXDOMAIN:
            result_output += "|    Domain does not exist.\n"
        except Exception:
            result_output += "|    Error retrieving records.\n"
        result_output += f"|{'='*80}|\n"
    result_output += f"╰─{' '*78}─╯"

    restart()

def email_lookup(email_address, **kwargs):
    try:
        v = validate_email(email_address)
        email_domain = v.domain
    except EmailNotValidError as e:
        Write.Print(f"[!] > Invalid email address format: {str(e)}", default_color, interval=0)
        restart()
        return
    mx_records = []
    try:
        answers = dns.resolver.resolve(email_domain, 'MX')
        for rdata in answers:
            mx_records.append(str(rdata.exchange))
    except:
        mx_records = []
    validity = "Mx Found (Might be valid)" if mx_records else "No MX found (Might be invalid)"
    email_text = f"""
╭─{' '*78}─╮
|{' '*34}Email Info{' '*34}|
|{'='*80}|
| [+] > Email:        || {email_address:<52}|
| [+] > Domain:       || {email_domain:<52}|
| [+] > MX Records:   || {", ".join(mx_records) if mx_records else "None":<52}|
| [+] > Validity:     || {validity:<52}|
╰─{' '*23}─╯╰─{' '*51}─╯
"""
    Write.Print(email_text, Colors.white, interval=0)
    log_option(email_text)

    print("[?] Export email lookup to JSON? (Y/N): ", end="")
    if input().strip().upper() == "Y":
        export_json({
            "email": email_address,
            "domain": email_domain,
            "mx_records": mx_records,
            "validity": validity
        }, filename_prefix="email_lookup")

    restart()

def reverse_dns(ip):
    try:
        rev_name = reversename.from_address(ip)
        answers = dns.resolver.resolve(rev_name, "PTR")
        ptr_record = str(answers[0]).strip('.')
    except:
        ptr_record = "No PTR record found"
    rdns_text = f"""
╭─{' '*78}─╮
|{' '*33}Reverse DNS Lookup{' '*33}|
|{'='*80}|
| [+] > IP:     || {ip:<60}|
| [+] > Host:   || {ptr_record:<60}|
╰─{' '*23}─╯╰─{' '*51}─╯
"""
    Write.Print(rdns_text, Colors.white, interval=0)
    log_option(rdns_text)

    print("[?] Export reverse DNS to JSON? (Y/N): ", end="")
    if input().strip().upper() == "Y":
        export_json({"ip": ip, "ptr_record": ptr_record}, filename_prefix="reverse_dns")

    restart()

def analyze_email_header(raw_headers):
    parser = Parser()
    msg = parser.parsestr(raw_headers)
    from_ = msg.get("From", "")
    to_ = msg.get("To", "")
    subject_ = msg.get("Subject", "")
    date_ = msg.get("Date", "")
    received_lines = msg.get_all("Received", [])
    found_ips = []
    if received_lines:
        for line in received_lines:
            potential_ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', line)
            for ip in potential_ips:
                if ip not in found_ips:
                    found_ips.append(ip)

    header_text = f"""
╭─{' '*78}─╮
|{' '*31}Email Header Analysis{' '*31}|
|{'='*80}|
| [+] > From:      || {from_:<55}|
| [+] > To:        || {to_:<55}|
| [+] > Subject:   || {subject_:<55}|
| [+] > Date:      || {date_:<55}|
|{'-'*80}|
"""
    if found_ips:
        header_text += "| [+] > Received Path (IPs found):\n"
        for ip in found_ips:
            header_text += f"|    {ip:<76}|\n"
    else:
        header_text += "| [+] > No IPs found in Received headers.\n"
    header_text += f"╰─{' '*78}─╯"
    Write.Print(header_text, Colors.white, interval=0)

    ip_details_full = ""
    if found_ips:
        ip_details_header = f"""
╭─{' '*78}─╮
|{' '*30}IP Geolocation Details{' '*30}|
|{'='*80}|
"""
        ip_details_summary = ""
        for ip in found_ips:
            data = get_ip_details(ip)
            if data is not None:
                loc = data.get('loc', 'None')
                ip_details_summary += f"| IP: {ip:<14}|| City: {data.get('city','N/A'):<15} Region: {data.get('region','N/A'):<15} Country: {data.get('country','N/A'):<4}|\n"
                ip_details_summary += f"|    Org: {data.get('org','N/A'):<63}|\n"
                ip_details_summary += f"|    Loc: {loc:<63}|\n"
                ip_details_summary += "|" + "-"*78 + "|\n"
            else:
                ip_details_summary += f"| IP: {ip:<14}|| [!] Could not retrieve details.\n"
                ip_details_summary += "|" + "-"*78 + "|\n"
        ip_details_footer = f"╰─{' '*78}─╯"
        ip_details_full = ip_details_header + ip_details_summary + ip_details_footer
        Write.Print(ip_details_full, Colors.white, interval=0)

    spf_result, dkim_result, dmarc_result = None, None, None
    spf_domain, dkim_domain = None, None
    auth_results = msg.get_all("Authentication-Results", [])
    from_domain = ""
    if "@" in from_:
        from_domain = from_.split("@")[-1].strip(">").strip()
    if auth_results:
        for entry in auth_results:
            spf_match = re.search(r'spf=(pass|fail|softfail|neutral)', entry, re.IGNORECASE)
            if spf_match:
                spf_result = spf_match.group(1)
            spf_domain_match = re.search(r'envelope-from=([^;\s]+)', entry, re.IGNORECASE)
            if spf_domain_match:
                spf_domain = spf_domain_match.group(1)
            dkim_match = re.search(r'dkim=(pass|fail|none|neutral)', entry, re.IGNORECASE)
            if dkim_match:
                dkim_result = dkim_match.group(1)
            dkim_domain_match = re.search(r'd=([^;\s]+)', entry, re.IGNORECASE)
            if dkim_domain_match:
                dkim_domain = dkim_domain_match.group(1)
            dmarc_match = re.search(r'dmarc=(pass|fail|none)', entry, re.IGNORECASE)
            if dmarc_match:
                dmarc_result = dmarc_match.group(1)
    spf_align = False
    dkim_align = False
    if from_domain and spf_domain:
        spf_align = from_domain.lower() == spf_domain.lower()
    if from_domain and dkim_domain:
        dkim_align = from_domain.lower() == dkim_domain.lower()
    alignment_text = f"""
╭─{' '*78}─╮
|{' '*30}SPF / DKIM / DMARC Checks{' '*29}|
|{'='*80}|
| [+] > SPF  Result:   {spf_result if spf_result else 'Not found':<20}   Domain: {spf_domain if spf_domain else 'N/A':<20} Aligned: {spf_align}|
| [+] > DKIM Result:   {dkim_result if dkim_result else 'Not found':<20} Domain: {dkim_domain if dkim_domain else 'N/A':<20} Aligned: {dkim_align}|
| [+] > DMARC Result:  {dmarc_result if dmarc_result else 'Not found':<20}|
╰─{' '*78}─╯
"""
    Write.Print(alignment_text, Colors.white, interval=0)
    full_output = header_text + "\n" + ip_details_full + "\n" + alignment_text
    log_option(full_output)

    print("[?] Export email header analysis to JSON? (Y/N): ", end="")
    if input().strip().upper() == "Y":
        export_json({
            "raw_headers": raw_headers,
            "from": from_,
            "to": to_,
            "subject": subject_,
            "date": date_,
            "found_ips": found_ips,
            "spf_result": spf_result,
            "spf_domain": spf_domain,
            "spf_aligned": spf_align,
            "dkim_result": dkim_result,
            "dkim_domain": dkim_domain,
            "dkim_aligned": dkim_align,
            "dmarc_result": dmarc_result
        }, filename_prefix="email_header_analysis")
    restart()

def haveibeenpwned_check(email):
    headers = {
        "hibp-api-key": HIBP_API_KEY,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36"
    }
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
    try:
        resp = requests.get(url, headers=headers, timeout=60)
        if resp.status_code == 200:
            breaches = resp.json()
            clear()
            results_text = f"""
╭─{' '*78}─╮
|{' '*30}Have I Been Pwned?{' '*30}|
|{'='*80}|
| [!] > Bad news! Your email was found in {len(breaches)} breach(es)                          |
|{'-'*80}|
"""
            for index, breach in enumerate(breaches, start=1):
                breach_name = breach.get('Name', 'Unknown')
                domain = breach.get('Domain', 'Unknown')
                breach_date = breach.get('BreachDate', 'Unknown')
                added_date = breach.get('AddedDate', 'Unknown')
                pwn_count = breach.get('PwnCount', 'Unknown')
                data_classes = ", ".join(breach.get('DataClasses', []))
                results_text += f"| Breach #{index}: {breach_name:<66}|\n"
                results_text += f"|    Domain: {domain:<71}|\n"
                results_text += f"|    Breach Date: {breach_date:<65}|\n"
                results_text += f"|    Added Date:  {added_date:<65}|\n"
                results_text += f"|    PwnCount:    {pwn_count:<65}|\n"
                results_text += f"|    Data Types:  {data_classes:<65}|\n"
                results_text += f"|{'='*80}|\n"
            results_text += f"╰─{' '*78}─╯"
            Write.Print(results_text, Colors.white, interval=0)
            log_option(results_text)

            print("[?] Export breach info to JSON? (Y/N): ", end="")
            if input().strip().upper() == "Y":
                export_json({"email": email, "breaches": breaches}, filename_prefix="breach_info")

        elif resp.status_code == 404:
            clear()
            msg = f"""
╭─{' '*78}─╮
|{' '*30}Have I Been Pwned?{' '*30}|
|{'='*80}|
| [!] > Good news! No breaches found for: {email:<48}|
╰─{' '*78}─╯
"""
            Write.Print(msg, Colors.white, interval=0)
            log_option(msg)
        else:
            clear()
            error_msg = f"[!] > An error occurred: HTTP {resp.status_code}\nResponse: {resp.text}\n"
            Write.Print(error_msg, Colors.red, interval=0)
            log_option(error_msg)
    except requests.exceptions.Timeout:
        clear()
        Write.Print("[!] > Request timed out when contacting Have I Been Pwned.", default_color, interval=0)
    except Exception as e:
        clear()
        Write.Print(f"[!] > An error occurred: {str(e)}", default_color, interval=0)
    restart()

def whois_lookup(domain, **kwargs):
    result = {
        "status": "error",
        "message": "Error retrieving WHOIS information",
        'data': {}
    }
    try:
        w = whois.whois(domain)
        clear()
        domain_name = w.domain_name if w.domain_name else "N/A"
        registrar = w.registrar if w.registrar else "N/A"
        creation_date = w.creation_date if w.creation_date else "N/A"
        expiration_date = w.expiration_date if w.expiration_date else "N/A"
        updated_date = w.updated_date if w.updated_date else "N/A"
        name_servers = ", ".join(w.name_servers) if w.name_servers else "N/A"
        status = ", ".join(w.status) if w.status else "N/A"

        result['status'] = 'success'
        result['message'] = 'WHOIS information retrieved successfully'
        result['data'] = {
                "domain": domain,
                "domain_name": str(domain_name),
                "registrar": str(registrar),
                "creation_date": str(creation_date),
                "expiration_date": str(expiration_date),
                "updated_date": str(updated_date),
                "name_servers": name_servers,
                "status": status
            }
        
        return result
        
    except Exception as e:
        Write.Print(f"[!] > WHOIS lookup error: {str(e)}", default_color, interval=0)
    
    return result

def check_password_strength(password):
    txt_file_path = os.path.join(os.path.dirname(__file__), "passwords.txt")
    if os.path.isfile(txt_file_path):
        try:
            with open(txt_file_path, "r", encoding="utf-8") as f:
                common_words = f.read().splitlines()
            for word in common_words:
                if word and word in password:
                    return "Weak password (may contain common phrase, term, word, sequence, etc, DO NOT use this password)"
        except Exception:
            pass
    score = 0
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    if re.search(r'[A-Z]', password):
        score += 1
    if re.search(r'[a-z]', password):
        score += 1
    if re.search(r'\d', password):
        score += 1
    if re.search(r'[^a-zA-Z0-9]', password):
        score += 1
    if score <= 2:
        return "Weak password (may contain common phrase, term, word, sequence, etc, DO NOT use this password)"
    elif 3 <= score <= 4:
        return "Moderate password (room for improvement)"
    else:
        return "Strong password (suitable for high security apps / credentials)"

def password_strength_tool():
    clear()
    Write.Print("[!] > Enter password to evaluate strength:\n", default_color, interval=0)
    password = Write.Input("[?] >  ", default_color, interval=0)
    if not password:
        clear()
        Write.Print("[!] > Password cannot be empty. Please enter the password.\n", default_color, interval=0)
        restart()
        return
    strength = check_password_strength(password)
    clear()
    output_text = f"Password Strength: {strength}\n"
    Write.Print(output_text, Colors.white, interval=0)
    log_option(output_text)
    restart()



def username_check(username='', **kwargs):
    result = {"status": "error", "message": "", "data": None}

    if not username:
        clear()
        result["message"] = "[!] > No username provided."
        Write.Print(result["message"] + "\n", Colors.red, interval=0)
        return result

    def fetch_wmn_data():
        try:
            response = requests.get("https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json", timeout=60)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            result["message"] = f"[!] > Failed to fetch data from WhatsMyName repository: {str(e)}"
            Write.Print(result["message"] + "\n", Colors.red, interval=0)
            return None

    data = fetch_wmn_data()
    if not data:
        return result

    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36"
    }
    sites = data["sites"]
    total_sites = len(sites)
    found_sites = []
    output_accumulated = ""

    def check_site(site, username, headers):
        site_name = site["name"]
        uri_check = site["uri_check"].format(account=username)
        try:
            res = requests.get(uri_check, headers=headers, timeout=60)
            estring_pos = site["e_string"] in res.text
            estring_neg = site["m_string"] in res.text
            if res.status_code == site["e_code"] and estring_pos and not estring_neg:
                return site_name, uri_check
        except:
            pass
        return None

    try:
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check_site, site, username, headers): site for site in sites}
            with tqdm(total=total_sites, desc="Checking sites") as pbar:
                for future in as_completed(futures):
                    try:
                        result_check = future.result()
                        if result_check:
                            site_name, uri_check = result_check
                            found_sites.append((site_name, uri_check))
                            # found_str = f"[+] Found on: {site_name}\n[+] Profile URL: {uri_check}\n"
                            # output_accumulated += found_str
                            # Write.Print(found_str, Colors.green, interval=0)
                    except Exception:
                        pass
                    finally:
                        pbar.update(1)

        if found_sites:
            result["status"] = "success"
            summary_str = f"\n[!] > Username found on {len(found_sites)} sites!\n"
            output_accumulated += summary_str
            Write.Print(summary_str, Colors.green, interval=0)
            # generate_html_report(username, found_sites)
            # report_msg = f"\n[!] > Report saved: username_check_report_{username}.html\n"
            # output_accumulated += report_msg

            result["data"] = {"username": username, "found_sites": [{"site_name": site, "profile_url": url} for site, url in found_sites]}

        else:
            result["message"] = f"[!] > No results found for {username}."
            result["data"] = {"username": username, "found_sites": []}

    except Exception as e:
        result["message"] = f"[!] > An error occurred: {str(e)}"
    return result

def generate_html_report(username, found_sites):
    html_content = f"""
<html>
<head>
    <title>Username Check Report for {username}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }}
        th {{
            background-color: #f2f2f2;
        }}
    </style>
</head>
<body>
    <h1>Username Check Report for {username}</h1>
    <table>
        <tr>
            <th>Website Name</th>
            <th>Profile URL</th>
        </tr>
"""
    for site_name, uri_check in found_sites:
        html_content += f"""
        <tr>
            <td>{site_name}</td>
            <td><a href="{uri_check}" target="_blank">{uri_check}</a></td>
        </tr>"""
    html_content += """
    </table>
</body>
</html>"""
    with open(f"username_check_report_{username}.html", "w") as report_file:
        report_file.write(html_content)

def log_option(message):
    # Place holder for your log_option function
    pass

def export_json(data, filename_prefix):
    # Place holder for your export_json function
    filename = f"{filename_prefix}_{data['username']}.json"
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)

def check_ssl_cert(domain, **kwargs):

    result = {
        "status": "error",
        "message": "Error retrieving SSL certificate info",
        'data': {}
    }
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=60) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        subject = dict(x[0] for x in cert['subject'])
        issued_to = subject.get('commonName', 'N/A')
        issuer = dict(x[0] for x in cert['issuer'])
        issued_by = issuer.get('commonName', 'N/A')
        not_before = cert['notBefore']
        not_after = cert['notAfter']
        not_before_dt = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
        not_after_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")

        result['status'] = 'success'
        result['message'] = 'SSL certificate info retrieved successfully'
        result['data'] = {
                "domain": domain,
                "issued_to": issued_to,
                "issued_by": issued_by,
                "valid_from": str(not_before_dt),
                "valid_until": str(not_after_dt)
            }
        
        return result
    
    except Exception as e:
        log_exception(e)

def check_robots_and_sitemap(domain):
    urls = [
        f"https://{domain}/robots.txt",
        f"https://{domain}/sitemap.xml"
    ]
    result_text = f"""
╭─{' '*78}─╮
|{' '*32}Site Discovery{' '*32}|
|{'='*80}|
| [+] > Domain:  {domain:<63}|
|{'-'*80}|
"""
    for resource_url in urls:
        try:
            resp = requests.get(resource_url, timeout=60)
            if resp.status_code == 200:
                lines = resp.text.split('\n')
                result_text += f"| Resource: {resource_url:<66}|\n"
                result_text += f"| Status: 200 (OK)\n"
                result_text += f"|{'-'*80}|\n"
                snippet = "\n".join(lines[:10])
                snippet_lines = snippet.split('\n')
                for sline in snippet_lines:
                    trunc = sline[:78]
                    result_text += f"| {trunc:<78}|\n"
                if len(lines) > 10:
                    result_text += "| ... (truncated)\n"
            else:
                result_text += f"| Resource: {resource_url:<66}|\n"
                result_text += f"| Status: {resp.status_code}\n"
            result_text += f"|{'='*80}|\n"
        except requests.exceptions.RequestException as e:
            result_text += f"| Resource: {resource_url}\n"
            result_text += f"| Error: {str(e)}\n"
            result_text += f"|{'='*80}|\n"
    result_text += f"╰─{' '*78}─╯"
    Write.Print(result_text, Colors.white, interval=0)
    log_option(result_text)

    print("[?] Export robots/sitemap to JSON? (Y/N): ", end="")
    if input().strip().upper() == "Y":
        export_json({"domain": domain, "discovery": result_text}, filename_prefix="site_discovery")
    restart()

def check_dnsbl(ip_address):
    dnsbl_list = [
        "zen.spamhaus.org",
        "bl.spamcop.net",
        "dnsbl.sorbs.net",
        "b.barracudacentral.org"
    ]
    reversed_ip = ".".join(ip_address.split(".")[::-1])
    results = []
    for dnsbl in dnsbl_list:
        query_domain = f"{reversed_ip}.{dnsbl}"
        try:
            answers = dns.resolver.resolve(query_domain, 'A')
            for ans in answers:
                results.append((dnsbl, str(ans)))
        except dns.resolver.NXDOMAIN:
            pass
        except dns.resolver.NoAnswer:
            pass
        except Exception as e:
            results.append((dnsbl, f"Error: {str(e)}"))
    report = f"""
╭─{' '*78}─╮
|{' '*33}DNSBL Check{' '*34}|
|{'='*80}|
| [+] > IP: {ip_address:<67}|
|{'-'*80}|
"""
    if results:
        report += "| The IP is listed on the following DNSBL(s):\n"
        for dnsbl, answer in results:
            report += f"|   {dnsbl:<25} -> {answer:<45}|\n"
    else:
        report += "| The IP is NOT listed on the tested DNSBL(s).\n"
    report += f"╰─{' '*78}─╯"
    Write.Print(report, Colors.white, interval=0)
    log_option(report)

    print("[?] Export DNSBL check to JSON? (Y/N): ", end="")
    if input().strip().upper() == "Y":
        export_json({"ip_address": ip_address, "dnsbl_results": results}, filename_prefix="dnsbl_check")
    restart()

def fetch_webpage_metadata(url):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36"
    }
    try:
        resp = requests.get(url, headers=headers, timeout=60)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "lxml")
        title_tag = soup.find("title")
        meta_desc = soup.find("meta", attrs={"name": "description"})
        meta_keyw = soup.find("meta", attrs={"name": "keywords"})
        title = title_tag.get_text(strip=True) if title_tag else "N/A"
        description = meta_desc["content"] if meta_desc and "content" in meta_desc.attrs else "N/A"
        keywords = meta_keyw["content"] if meta_keyw and "content" in meta_keyw.attrs else "N/A"
        result_text = f"""
╭─{' '*78}─╮
|{' '*31}Webpage Metadata{' '*31}|
|{'='*80}|
| [+] > URL:         {url:<58}|
| [+] > Title:       {title:<58}|
| [+] > Description: {description:<58}|
| [+] > Keywords:    {keywords:<58}|
╰─{' '*78}─╯
"""
        Write.Print(result_text, Colors.white, interval=0)
        log_option(result_text)

        print("[?] Export webpage metadata to JSON? (Y/N): ", end="")
        if input().strip().upper() == "Y":
            export_json({
                "url": url,
                "title": title,
                "description": description,
                "keywords": keywords
            }, filename_prefix="webpage_metadata")
    except Exception as e:
        Write.Print(f"[!] > Error fetching metadata: {str(e)}\n", Colors.red, interval=0)
    restart()

PERPLEXITY_API_URL = "https://api.perplexity.ai/chat/completions"
PERPLEXITY_API_KEY = "INSERT API KEY HERE"
perplexity_headers = {
    "Authorization": f"Bearer {PERPLEXITY_API_KEY}",
    "Content-Type": "application/json",
}

def business_search():
    clear()
    Write.Print("[!] > Retrieve information about a business.\n", default_color, interval=0)
    business_name = Write.Input("[?] > Enter the business or persons name to search:", default_color, interval=0).strip()
    if not business_name:
        Write.Print("[!] > No business name was provided.\n", Colors.red, interval=0)
        restart()
        return
    payload_business_info = {
        "model": "sonar-reasoning-pro",
        "messages": [
            {
                "role": "system",
                "content":(
                    "You are a business search assistant specializing in comprehensive market research, competitor analysis, and industry insights."
                    "Your core functions include gathering detailed company information (financials, leadership, employee count, locations), analyzing"
                    "market positioning and competitive landscapes, tracking industry trends and regulations, identifying potential business opportunities"
                    "and risks, and providing actionable strategic recommendations. You have access to public business records, market reports, news archives."
                    "and industry databases. You maintain strict confidentiality, cite sources when available, and clearly distinguish between verified facts"
                    "and analytical insights. When data is incomplete or unavailable, you acknowledge limitations and provide best estimates based on available"
                    "information. Your responses should be structured, data-driven, and tailored to the specific business context while avoiding speculation or"
                    "unsubstantiated claims."
                )
            },
            {
                "role": "user",
                "content": f"Provide me with general information about {business_name}."
            }
        ],
        "max_tokens": 8000,
        "temperature": 1.1,
    }
    out_text = ""
    try:
        response = requests.post(PERPLEXITY_API_URL, headers=perplexity_headers, json=payload_business_info)
        if response.status_code == 200:
            data = response.json()
            out_text = "\nGeneral Business Information:\n" + data["choices"][0]["message"]["content"] + "\n"
            Write.Print(out_text, Colors.white, interval=0)
        else:
            err_msg = f"Error: {response.status_code}, {response.text}\n"
            out_text = err_msg
            Write.Print(err_msg, Colors.red, interval=0)
    except Exception as e:
        out_text = f"[!] > Exception in retrieving business info: {str(e)}\n"
        Write.Print(out_text, Colors.red, interval=0)
    log_option(out_text)
    restart()

def business_reputation_search():
    clear()
    Write.Print("[!] > Business Reputation Search\n", default_color, interval=0)
    company_name = Write.Input("[?] > Enter Company Name: ", default_color, interval=0).strip()
    if not company_name:
        clear()
        Write.Print("[!] > Company name is required.\n", Colors.red, interval=0)
        restart()
        return
    base_prompt_reputation = (
        "Please provide a comprehensive risk assessment for " + company_name +
        "covering the period from + start_date + to present. Include any documented incidents, regulatory violations, compliance issues, legal proceedings, and public controversies. "
        "Focus on areas that could impact business continuity, reputation, or contractual obligations, including but not limited to: data breaches, cybersecurity incidents, environmental violations, labor disputes, financial irregularities, supply chain disruptions, product quality issues, and regulatory non-compliance. "
        "Detail the nature of each incident, its resolution status, any penalties or settlements imposed, and implemented remediation measures. Additionally, highlight any patterns of recurring issues or systemic problems. You must cite all sources in Chicago format."
    )
    payload = {
        "model": "sonar-reasoning-pro",
        "messages": [
            {"role": "system", "content": base_prompt_reputation},
            {"role": "user", "content": f"Conduct a comprehensive business reputation analysis for {company_name}."}
        ],
        "max_tokens": 8000,
        "temperature": 1.1
    }
    result_text = ""
    try:
        response = requests.post(PERPLEXITY_API_URL, headers=perplexity_headers, json=payload, timeout=60)
        if response.status_code == 200:
            data = response.json()
            result_text = "\nBusiness Reputation Analysis:\n" + data["choices"][0]["message"]["content"] + "\n"
            Write.Print(result_text, Colors.white, interval=0)
        else:
            result_text = f"[!] > Error from Perplexity: HTTP {response.status_code}\n{response.text}\n"
            Write.Print(result_text, Colors.red, interval=0)
    except Exception as e:
        result_text = f"[!] > Exception in retrieving business reputation info: {str(e)}\n"
        Write.Print(result_text, Colors.red, interval=0)
    log_option(result_text)
    restart()

def travel_assessment(location):
    clear()
    Write.Print("[!] > Creating a comprehensive travel risk analysis...\n", default_color, interval=0)
    analysis = ""
    prompt = f"""
Provide a comprehensive, highly detailed travel risk analysis for the following location: {location}...
"""
    payload = {
        "model": "sonar-reasoning-pro",
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a travel risk analysis assistant specializing in providing comprehensive, detailed, and practical risk assessments for travel destinations. "
                    "Your responses should cover political stability, crime rates, natural disasters, health risks, local laws, infrastructure, and other relevant factors. "
                    "Ensure that your analysis is thorough, well-structured, and includes practical advice, best practices, and necessary disclaimers with clear citations if applicable."
                )
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        "max_tokens": 8000,
        "temperature": 1.1
    }
    try:
        response = requests.post(PERPLEXITY_API_URL, headers=perplexity_headers, json=payload, timeout=60)
        if response.status_code == 200:
            data = response.json()
            analysis = data["choices"][0]["message"]["content"]
            Write.Print(analysis, Colors.white, interval=0)
        else:
            analysis = f"[!] > Error from Perplexity: HTTP {response.status_code}\n{response.text}\n"
            Write.Print(analysis, Colors.red, interval=0)
    except Exception as e:
        analysis = f"[!] > An error occurred: {str(e)}\n"
        Write.Print(analysis, Colors.red, interval=0)
    log_option(analysis)
    restart()

def botometer_search():
    clear()
    username = Write.Input("[?] > Enter a X/Twitter username (with or without @): ", default_color, interval=0).strip()
    if not username:
        Write.Print("[!] > No username was provided.\n", Colors.red, interval=0)
        restart()
        return
    if not username.startswith("@"):
        username = "@" + username
    Write.Print(f"[!] > Checking Botometer score for {username}...\n", default_color, interval=0)
    output_text = ""
    try:
        url = "https://botometer-pro.p.rapidapi.com/botometer-x/get_botscores_in_batch"
        payload = {
            "user_ids": [],
            "usernames": [username]
        }
        headers = {
            "x-rapidapi-key": "INSERT API KEY HERE",
            "x-rapidapi-host": "botometer-pro.p.rapidapi.com",
            "Content-Type": "application/json"
        }
        response = requests.post(url, json=payload, headers=headers, timeout=60)
        result = response.json()
        output_text = json.dumps(result, indent=2)
        Write.Print(output_text, Colors.white, interval=0)
    except Exception as e:
        output_text = f"[!] > An error occurred: {str(e)}"
        Write.Print(output_text, Colors.red, interval=0)
    log_option(output_text)
    restart()

def hudson_rock_email_infection_check():
    clear()
    email = Write.Input("[?] > Enter an email to check infection status: ", default_color, interval=0).strip()
    if not email:
        clear()
        Write.Print("[!] > No email was provided.\n", Colors.red, interval=0)
        restart()
        return
    output_text = ""
    try:
        url = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email"
        params = {"email": email}
        resp = requests.get(url, params=params, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        clear()
        output_lines = [f"[+] Hudson Rock email infection check results for {email}:\n"]
        if isinstance(data, dict):
            for k, v in data.items():
                output_lines.append(f"{k}: {v}")
        else:
            output_lines.append("No structured data available.")
        output_text = "\n".join(output_lines)
        Write.Print("\n" + output_text, Colors.white, interval=0)
    except requests.exceptions.Timeout:
        output_text = "[!] > Request timed out when contacting Hudson Rock.\n"
        clear()
        Write.Print(output_text, default_color, interval=0)
    except Exception as e:
        output_text = f"[!] > Error: {str(e)}"
        clear()
        Write.Print(output_text, default_color, interval=0)
    log_option(output_text)
    restart()

def hudson_rock_username_infection_check():
    clear()
    username = Write.Input("[?] > Enter a username to check infection status: ", default_color, interval=0).strip()
    if not username:
        clear()
        Write.Print("[!] > No username was provided.\n", Colors.red, interval=0)
        restart()
        return
    output_text = ""
    try:
        url = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-username"
        params = {"username": username}
        resp = requests.get(url, params=params, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        clear()
        output_lines = [f"[+] Hudson Rock username infection check results for {username}:\n"]
        if isinstance(data, dict):
            for k, v in data.items():
                output_lines.append(f"{k}: {v}")
        else:
            output_lines.append("No structured data available.")
        output_text = "\n".join(output_lines)
        Write.Print("\n" + output_text, Colors.white, interval=0)
    except requests.exceptions.Timeout:
        output_text = "[!] > Request timed out when contacting Hudson Rock.\n"
        clear()
        Write.Print(output_text, default_color, interval=0)
    except Exception as e:
        output_text = f"[!] > Error: {str(e)}"
        clear()
        Write.Print(output_text, default_color, interval=0)
    log_option(output_text)
    restart()

def hudson_rock_domain_infection_check():
    clear()
    domain = Write.Input("[?] > Enter a domain / URL to check infection status: ", default_color, interval=0).strip()
    if not domain:
        clear()
        Write.Print("[!] > No domain was provided.\n", Colors.red, interval=0)
        restart()
        return
    output_text = ""
    try:
        url = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain"
        params = {"domain": domain}
        resp = requests.get(url, params=params, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        clear()
        output_lines = [f"[+] Hudson Rock domain infection check results for {domain}:\n"]
        if isinstance(data, dict):
            for k, v in data.items():
                output_lines.append(f"{k}: {v}")
        else:
            output_lines.append("No structured data available.")
        output_text = "\n".join(output_lines)
        Write.Print("\n" + output_text, Colors.white, interval=0)
    except requests.exceptions.Timeout:
        output_text = "[!] > Request timed out when contacting Hudson Rock.\n"
        clear()
        Write.Print(output_text, default_color, interval=0)
    except Exception as e:
        output_text = f"[!] > Error: {str(e)}"
        clear()
        Write.Print(output_text, default_color, interval=0)
    log_option(output_text)
    restart()

def hudson_rock_ip_infection_check():
    clear()
    ip_address = Write.Input("[?] > Enter IP address to check infection status: ", default_color, interval=0).strip()
    if not ip_address:
        clear()
        Write.Print("[!] > No IP provided.\n", Colors.red, interval=0)
        restart()
        return
    output_text = ""
    try:
        url = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-ip"
        params = {"ip": ip_address}
        resp = requests.get(url, params=params, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        clear()
        output_lines = [f"[+] Hudson Rock IP infection check results for {ip_address}:\n"]
        if isinstance(data, dict):
            for k, v in data.items():
                output_lines.append(f"{k}: {v}")
        else:
            output_lines.append("No structured data available.")
        output_text = "\n".join(output_lines)
        Write.Print("\n" + output_text, Colors.white, interval=0)
    except requests.exceptions.Timeout:
        output_text = "[!] > Request timed out when contacting Hudson Rock.\n"
        clear()
        Write.Print(output_text, default_color, interval=0)
    except Exception as e:
        output_text = f"[!] > Error: {str(e)}"
        clear()
        Write.Print(output_text, default_color, interval=0)
    log_option(output_text)
    restart()

def fact_check_text():
    clear()
    Write.Print("[!] > Enter text to fact-check:\n", default_color, interval=0)
    text_to_check = Write.Input("[?] >  ", default_color, interval=0).strip()
    if not text_to_check:
        clear()
        Write.Print("[!] > No text was provided.\n", Colors.red, interval=0)
        restart()
        return
    payload_fact_check = {
        "model": "sonar-reasoning-pro",
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are an advanced AI fact-checking assistant designed to evaluate "
                    "claims and statements with rigorous accuracy and methodical analysis. "
                    "Your primary goal is to help users distinguish truth from misinformation "
                    "through careful, systematic evaluation. You must be able to apply multiple "
                    "verification methods to each claim, cross reference information across reliable "
                    "sources, check for internal consistency within claims, verify dates, numbers, "
                    "and specific details, examine original context when available, identify possible "
                    "cognitive biases, recognize emotional language that may cloud judgement, check "
                    "for cherry picked data or selective presentation, consider alternative perspectives "
                    "and explanations, and flag ideological or commercial influences. You must show and "
                    "cite all sources at the end of the output and make sure they are numbered accurately." 
                    "You must cite all sources in chicago format."
                )
            },
            {"role": "user", "content": f"Fact-check the following text: {text_to_check}"}
        ],
        "max_tokens": 8000,
        "temperature": 1.1
    }
    output_text = ""
    try:
        response = requests.post(PERPLEXITY_API_URL, headers=perplexity_headers, json=payload_fact_check)
        if response.status_code == 200:
            data = response.json()
            output_text = "\nFact Checking Results:\n" + data["choices"][0]["message"]["content"] + "\n"
            Write.Print(output_text, Colors.white, interval=0)
        else:
            err_msg = f"Error: {response.status_code}, {response.text}\n"
            output_text = err_msg
            Write.Print(err_msg, Colors.red, interval=0)
    except Exception as e:
        output_text = f"[!] > Exception in fact-checking: {str(e)}\n"
        Write.Print(output_text, Colors.red, interval=0)
    log_option(output_text)
    restart()

def relationship_search():
    clear()
    Write.Print("[!] > Analyze relationships between people, organizations, or businesses:\n", default_color, interval=0)
    query = Write.Input("[?] > Enter your query: ", default_color, interval=0).strip()
    if not query:
        Write.Print("[!] > No query provided.\n", Colors.red, interval=0)
        restart()
        return
    payload_relationships = {
        "model": "sonar-reasoning-pro",
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are an expert investigative researcher tasked with uncovering and analyzing connections among a diverse array of entities—including individuals," 
                    "organizations, nonprofits, corporations, government bodies, financial institutions, and more. For each inquiry, deliver a comprehensive, objective, and" 
                    "professional analysis of the subject’s background, relationships, business dealings, partnerships, investments, board memberships, charitable activities," 
                    "educational history, and networks, with every claim supported by inline citations. Clearly indicate any speculative or unverified information and" 
                    "consider both direct and indirect connections while explaining their broader significance and flagging potential red flags or conflicts of interest."
                    "Structure your response as follows: 1) Brief subject overview with inline citations for each claim, 2) Categorized key relationships and connections" 
                    "(business, personal, philanthropic, etc.) with citations, 3) Timeline of significant interactions with specific dates and sources, 4) Analysis of the" 
                    "strength and nature of each connection backed by evidence and citations, 5) Identification of potential conflicts of interest or notable patterns with" 
                    "supporting citations, and 6) A detailed representation of the network covering personal, hobbyist, and business ties. Use numbered inline citations" 
                    "(e.g., [1]) and provide a complete source list at the end in Chicago style format—with each citation including the publication name, article title," 
                    "author (if available), date, and URL. When multiple sources support a claim, include multiple citations. Any information without a valid citation" 
                    "should be omitted. END EVERY RESPONSE WITH: Sources: followed by numbered citations in Chicago style format."
                )
            },
            {"role": "user", "content": query}
        ],
        "max_tokens": 8000,
        "temperature": 1.1
    }
    output_text = ""
    try:
        response = requests.post(PERPLEXITY_API_URL, headers=perplexity_headers, json=payload_relationships)
        if response.status_code == 200:
            data = response.json()
            output_text = "\nEntity Relationship Analysis Results:\n" + data["choices"][0]["message"]["content"] + "\n"
            Write.Print(output_text, Colors.white, interval=0)
        else:
            err_msg = f"Error: {response.status_code}, {response.text}\n"
            output_text = err_msg
            Write.Print(err_msg, Colors.red, interval=0)
    except Exception as e:
        output_text = f"[!] > Exception in relationship analysis: {str(e)}\n"
        Write.Print(output_text, Colors.red, interval=0)
    log_option(output_text)
    restart()

def read_file_metadata(file_path):
    clear()
    Write.Print(f"🐢 Checking File Data\n {file_path}", Colors.green, interval=0)

    def timeConvert(atime):
        from datetime import datetime
        dt = atime
        newtime = datetime.fromtimestamp(dt)
        return newtime.date()

    def sizeFormat(size):
        newsize = format(size/1024, ".2f")
        return newsize + " KB"

    try:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File {file_path} does not exist.")
        Dfile = os.stat(file_path)
        file_size = sizeFormat(Dfile.st_size)
        file_name = os.path.basename(file_path)

        max_length = 60
        file_creation_time = datetime.fromtimestamp(getattr(Dfile, 'st_birthtime', Dfile.st_ctime)).date()
        file_modification_time = timeConvert(Dfile.st_mtime)
        file_last_Access_Date = timeConvert(Dfile.st_atime)

        mime = magic.Magic(mime=True)
        file_type = mime.from_file(file_path)

        metaData_extra = []

        def get_permission_string(file_mode):
            permissions = [
                stat.S_IRUSR, stat.S_IWUSR, stat.S_IXUSR,
                stat.S_IRGRP, stat.S_IWGRP, stat.S_IXGRP,
                stat.S_IROTH, stat.S_IWOTH, stat.S_IXOTH
            ]
            labels = ['Owner', 'Group', 'Other']
            permission_descriptions = []
            for i, label in enumerate(labels):
                read = 'Yes' if file_mode & permissions[i * 3] else 'No'
                write = 'Yes' if file_mode & permissions[i * 3 + 1] else 'No'
                execute = 'Yes' if file_mode & permissions[i * 3 + 2] else 'No'
                description = f"{label} {{Read: {read}, Write: {write}, Execute: {execute}}}"
                permission_descriptions.append(description)
            return ', '.join(permission_descriptions)

        def gps_extract(exif_dict):
            gps_metadata = exif_dict['GPSInfo']
            lat_ref_num = 1 if gps_metadata['GPSLatitudeRef'] == 'N' else -1
            long_ref_num = 1 if gps_metadata['GPSLongitudeRef'] == 'E' else -1

            lat_list = [float(num) for num in gps_metadata['GPSLatitude']]
            long_list = [float(num) for num in gps_metadata['GPSLongitude']]

            lat_coordinate = (lat_list[0] + lat_list[1]/60 + lat_list[2]/3600) * lat_ref_num
            long_coordinate = (long_list[0] + long_list[1]/60 + long_list[2]/3600) * long_ref_num
            return (lat_coordinate, long_coordinate)

        permissions = get_permission_string(Dfile.st_mode)

        if file_type.startswith("image"):
            with Image.open(file_path) as img:
                metaData_extra.append(f"|{' '*32}Image MetaData{' '*32}|")
                metaData_extra.append(f"|{'-'*78}|")
                info_dict = {
                    "Filename": img.filename,
                    "Image Size": img.size,
                    "Image Height": img.height,
                    "Image Width": img.width,
                    "Image Format": img.format,
                    "Image Mode": img.mode
                }
                for label,value in info_dict.items():
                    metaData_extra.append(f"|  {str(label):<10}: ||  {str(value)[:max_length]:<60}|")
                if img.format == 'TIFF':
                    for tag_id, value in img.tag_v2.items():
                        tag_name = TAGS.get(tag_id, tag_id)
                        metaData_extra.append(f"|  {str(tag_name):<10}: ||  {str(value)[:max_length]:<60}|")
                elif file_path.endswith('.png'):
                    for key, value in img.info.items():
                        metaData_extra.append(f"|  {str(key):<10}: ||  {str(value)[:max_length]:<60}|")
                else:
                    imdata = img._getexif()
                    if imdata:
                        for tag_id in imdata:
                            tag = TAGS.get(tag_id, tag_id)
                            data = imdata.get(tag_id)
                            if tag == "GPSInfo":
                                gps = gps_extract(imdata)
                                metaData_extra.append(f"|  GPS Coordinates: ||  {gps}  |")
                                continue
                            if isinstance(data, bytes):
                                try:
                                    data = data.decode('utf-8', errors='ignore')
                                except UnicodeDecodeError:
                                    data = '<Unintelligible Data>'
                            metaData_extra.append(f"|  {str(tag):<10}: ||  {str(data)[:max_length]:<60}|")
                    else:
                        metaData_extra.append("No EXIF data found.")
        elif file_type == "application/pdf":
            with open(file_path, "rb") as pdf_file:
                pdf_reader = PyPDF2.PdfReader(pdf_file)
                pdf_data = pdf_reader.metadata
                metaData_extra.append(f"|{' '*32}PDF Metadata{' '*32}|")
                metaData_extra.append(f"|{'-'*78}|")
                if pdf_data:
                    for key, value in pdf_data.items():
                        metaData_extra.append(f"|  {str(key):<10}:  || {str(value)[:max_length]:<60}|")
                    if pdf_reader.is_encrypted:
                        metaData_extra.append(f"|  Encrypted: || Yes      |")
                    else:
                        metaData_extra.append(f"|  Encrypted: || No      |")
                else:
                    metaData_extra.append("No PDF metadata found.")
        elif file_path.endswith(('.doc', '.docx')):
            doc = docx.Document(file_path)
            core_properties = doc.core_properties
            doc_metadata = f"""
|{' '*32}Document Properties{' '*32}
|{'='*78}|
| Title:            || {str(core_properties.title) :<60}           |
| Author:           || {str(core_properties.author) :<60}          |
| Subject:          || {str(core_properties.subject) :<60}         |
| Keywords:         || {str(core_properties.keywords) :<60}        |
| Last Modified By: || {str(core_properties.last_modified_by) :<60}|
| Created:          || {str(core_properties.created) :<60}         |
| Modified:         || {str(core_properties.modified) :<60}        |
| Category:         || {str(core_properties.category) :<60}        |
| Content Status:   || {str(core_properties.content_status) :<60}  |
| Version:          || {str(core_properties.version) :<60}         |
| Revision:         || {str(core_properties.revision) :<60}        |
| Comments:         || {str(core_properties.comments) :<60}        |
            """
            metaData_extra.append(doc_metadata)
        elif file_path.endswith(('.xlsx', '.xlsm')):
            workbook = openpyxl.load_workbook(file_path, data_only=True)
            properties = workbook.properties
            excel_metadata = f"""
|{' '*32}Excel Document Properties{' '*32}|
|{'='*78}|
| Title:            || {str(properties.title) :<60}         |
| Author:           || {str(properties.creator) :<60}       |
| Keywords:         || {str(properties.keywords) :<60}      |
| Last Modified By: || {str(properties.lastModifiedBy) :<60}|
| Created:          || {str(properties.created) :<60}       |
| Modified:         || {str(properties.modified) :<60}      |
| Category:         || {str(properties.category) :<60}      |
| Description:      || {str(properties.description) :<60}   |
            """
            metaData_extra.append(excel_metadata)
        elif file_path.endswith(('.pptx', '.pptm')):
            try:
                presentation = Presentation(file_path)
                core_properties = presentation.core_properties
                pptx_metadata = f"""
|{' '*32}PowerPoint Document Properties{' '*31}|
|{'='*78}|
| Title:            || {str(core_properties.title) :<60}           |
| Author:           || {str(core_properties.author) :<60}          |
| Keywords:         || {str(core_properties.keywords) :<60}        |
| Last Modified By: || {str(core_properties.last_modified_by) :<60}|
| Created:          || {str(core_properties.created) :<60}         |
| Modified:         || {str(core_properties.modified) :<60}        |
| Category:         || {str(core_properties.category) :<60}        |
| Description:      || {str(core_properties.subject) :<60}         |
                """
                metaData_extra.append(pptx_metadata)
            except Exception as e:
                metaData_extra.append(f"[Error] Could not read PowerPoint metadata: {e}")
        elif file_type.startswith("audio"):
            try:
                metaData_extra.append(f"|{' '*32}Audio MetaData{' '*32}|\n|{'-'*78}|")
                tinytim = TinyTag.get(file_path)
                if tinytim:
                    metaData_extra.append(f"|  Title:    || {str(tinytim.title)[:max_length]:<60}      |")
                    metaData_extra.append(f"|  Artist:   || {str(tinytim.artist)[:max_length]:<60}     |")
                    metaData_extra.append(f"|  Genre:    || {str(tinytim.genre)[:max_length]:<60}      |")
                    metaData_extra.append(f"|  Album:    || {str(tinytim.album)[:max_length]:<60}      |")
                    metaData_extra.append(f"|  Year:     || {str(tinytim.year)[:max_length]:<60}       |")
                    metaData_extra.append(f"|  Composer: || {str(tinytim.composer)[:max_length]:<60}   |")
                    metaData_extra.append(f"|  A-Artist: || {str(tinytim.albumartist)[:max_length]:<60}|")
                    metaData_extra.append(f"|  Track     || {str(tinytim.track_total)[:max_length]:<60}|")
                    metaData_extra.append(f"|  Duration: || {f'{tinytim.duration:.2f} seconds':<60}    |")
                    metaData_extra.append(f"|  Bitrate:  || {str(tinytim.bitrate) + ' kbps':<60}       |")
                    metaData_extra.append(f"|  Samplrate:|| {str(tinytim.samplerate) + ' Hz':<60}      |")
                    metaData_extra.append(f"|  Channels: || {str(tinytim.channels):<60}                |")

                if file_path.endswith('.mp3'):
                    audio = MP3(file_path, ID3=ID3)
                elif file_path.endswith('.wav'):
                    audio = wave.open(file_path, 'rb')
                elif file_path.endswith('.flac'):
                    audio = FLAC(file_path)
                elif file_path.endswith('.ogg'):
                    audio = OggVorbis(file_path)
                elif file_path.endswith(('.m4a', '.mp4')):
                    audio = MP4(file_path)
                else:
                    audio = None

                if audio is None:
                    metaData_extra.append(" 🐸 Cant Read Audio File for metadata.\n Unsupported")
                else:
                    if hasattr(audio, 'items') and audio.items():
                        for tag, value in audio.items():
                            metaData_extra.append(f"|  {str(tag):<10}: ||  {str(value)[:max_length]:<60}|")
            except Exception as e:
                metaData_extra.append(f"Error processing file: {str(e)}")

        clear()
        metadata_summary = f"""
|{' '*32}File Metadata{' '*33}|
|{'='*78}|
|  File Path:   || {file_path:<60}                  |
|  File Name:   || {file_name:<60}                  |
|  File Size:   || {file_size:<60}                  |
|  File Type:   || {file_type:<60}                  |
|  Permission:  || {permissions:<60}                |
|  Created:     || {str(file_creation_time):<60}    |
|  Modified:    || {str(file_modification_time):<60}|
|  Last Access: || {str(file_last_Access_Date):60}  |
"""
        metadata_summary += "\n".join(metaData_extra)
        metadata_summary += "\n" + "="*78 + "\n"
        Write.Print(metadata_summary, Colors.white, interval=0)
        log_option(metadata_summary)

        print("[?] Export file metadata to JSON? (Y/N): ", end="")
        if input().strip().upper() == "Y":
            export_json({
                "file_path": file_path,
                "file_name": file_name,
                "file_size": file_size,
                "file_type": file_type,
                "permissions": permissions,
                "created": str(file_creation_time),
                "modified": str(file_modification_time),
                "last_access": str(file_last_Access_Date),
                "additional_metadata": metaData_extra
            }, filename_prefix="file_metadata")

    except Exception as e:
        err_msg = f" ☠️ Error reading file metadata: {str(e)}"
        Write.Print(err_msg, Colors.red, interval=0)
        log_option(err_msg)
    restart()

def hunter_domain_search():
    clear()
    Write.Print("[!] > Hunter.io Domain Search\n", default_color, interval=0)
    domain = Write.Input("[?] > Enter a domain to search via Hunter.io: ", default_color, interval=0).strip()
    if not domain:
        Write.Print("[!] > No domain provided.\n", Colors.red, interval=0)
        restart()
        return
    url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key=INSERT API KEY HERE"
    output_text = ""
    try:
        resp = requests.get(url, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        clear()
        lines = [f"[+] Hunter.io Domain Search results for {domain}:"]
        if isinstance(data, dict):
            for k, v in data.items():
                lines.append(f"{k}: {v}")
        else:
            lines.append("No structured domain data available.")
        output_text = "\n".join(lines)
        Write.Print("\n" + output_text, Colors.white, interval=0)
    except Exception as e:
        output_text = f"[!] > Error: {str(e)}"
        clear()
        Write.Print(output_text, Colors.red, interval=0)
    log_option(output_text)
    restart()

def hunter_email_finder():
    clear()
    Write.Print("[!] > Hunter.io Email Finder\n", default_color, interval=0)
    domain = Write.Input("[?] > Enter a domain (e.g. reddit.com): ", default_color, interval=0).strip()
    first_name = Write.Input("[?] > First Name: ", default_color, interval=0).strip()
    last_name = Write.Input("[?] > Last Name: ", default_color, interval=0).strip()
    if not domain or not first_name or not last_name:
        Write.Print("[!] > Missing domain or names.\n", Colors.red, interval=0)
        restart()
        return
    url = f"https://api.hunter.io/v2/email-finder?domain={domain}&first_name={first_name}&last_name={last_name}&api_key=INSERT API KEY HERE"
    output_text = ""
    try:
        resp = requests.get(url, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        clear()
        lines = [f"[+] Hunter.io Email Finder results for {first_name} {last_name} @ {domain}:"]
        if isinstance(data, dict):
            for k, v in data.items():
                lines.append(f"{k}: {v}")
        else:
            lines.append("No structured email finder data available.")
        output_text = "\n".join(lines)
        Write.Print("\n" + output_text, Colors.white, interval=0)
    except Exception as e:
        output_text = f"[!] > Error: {str(e)}"
        clear()
        Write.Print(output_text, Colors.red, interval=0)
    log_option(output_text)
    restart()

def hunter_email_verifier():
    clear()
    Write.Print("[!] > Hunter.io Email Verification\n", default_color, interval=0)
    email = Write.Input("[?] > Enter an email to verify: ", default_color, interval=0).strip()
    if not email:
        Write.Print("[!] > No email provided.\n", Colors.red, interval=0)
        restart()
        return
    url = f"https://api.hunter.io/v2/email-verifier?email={email}&api_key=INSERT API KEY HERE"
    output_text = ""
    try:
        resp = requests.get(url, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        clear()
        lines = [f"[+] Hunter.io Email Verification results for {email}:"]
        if isinstance(data, dict):
            for k, v in data.items():
                lines.append(f"{k}: {v}")
        else:
            lines.append("No structured verifier data available.")
        output_text = "\n".join(lines)
        Write.Print("\n" + output_text, Colors.white, interval=0)
    except Exception as e:
        output_text = f"[!] > Error: {str(e)}"
        clear()
        Write.Print(output_text, Colors.red, interval=0)
    log_option(output_text)
    restart()

def hunter_company_enrichment():
    clear()
    Write.Print("[!] > Hunter.io Company Enrichment\n", default_color, interval=0)
    domain = Write.Input("[?] > Enter a domain for enrichment (e.g. stripe.com): ", default_color, interval=0).strip()
    if not domain:
        Write.Print("[!] > No domain provided.\n", Colors.red, interval=0)
        restart()
        return
    url = f"https://api.hunter.io/v2/companies/find?domain={domain}&api_key=INSERT API KEY HERE"
    output_text = ""
    try:
        resp = requests.get(url, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        clear()
        lines = [f"[+] Hunter.io Company Enrichment results for {domain}:"]
        if isinstance(data, dict):
            for k, v in data.items():
                lines.append(f"{k}: {v}")
        else:
            lines.append("No structured company data available.")
        output_text = "\n".join(lines)
        Write.Print("\n" + output_text, Colors.white, interval=0)
    except Exception as e:
        output_text = f"[!] > Error: {str(e)}"
        clear()
        Write.Print(output_text, Colors.red, interval=0)
    log_option(output_text)
    restart()

def hunter_person_enrichment():
    clear()
    Write.Print("[!] > Hunter.io Person Enrichment\n", default_color, interval=0)
    email = Write.Input("[?] > Enter an email for person enrichment: ", default_color, interval=0).strip()
    if not email:
        Write.Print("[!] > No email provided.\n", Colors.red, interval=0)
        restart()
        return
    url = f"https://api.hunter.io/v2/people/find?email={email}&api_key=INSERT API KEY HERE"
    output_text = ""
    try:
        resp = requests.get(url, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        clear()
        lines = [f"[+] Hunter.io Person Enrichment results for {email}:"]
        if isinstance(data, dict):
            for k, v in data.items():
                lines.append(f"{k}: {v}")
        else:
            lines.append("No structured person data available.")
        output_text = "\n".join(lines)
        Write.Print("\n" + output_text, Colors.white, interval=0)
    except Exception as e:
        output_text = f"[!] > Error: {str(e)}"
        clear()
        Write.Print(output_text, Colors.red, interval=0)
    log_option(output_text)
    restart()

def hunter_combined_enrichment():
    clear()
    Write.Print("[!] > Hunter.io Combined Enrichment\n", default_color, interval=0)
    email = Write.Input("[?] > Enter an email for combined enrichment: ", default_color, interval=0).strip()
    if not email:
        Write.Print("[!] > No email provided.\n", Colors.red, interval=0)
        restart()
        return
    url = f"https://api.hunter.io/v2/combined/find?email={email}&api_key=INSERT API KEY HERE"
    output_text = ""
    try:
        resp = requests.get(url, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        clear()
        lines = [f"[+] Hunter.io Combined Enrichment results for {email}:"]
        if isinstance(data, dict):
            for k, v in data.items():
                lines.append(f"{k}: {v}")
        else:
            lines.append("No structured combined data available.")
        output_text = "\n".join(lines)
        Write.Print("\n" + output_text, Colors.white, interval=0)
    except Exception as e:
        output_text = f"[!] > Error: {str(e)}"
        clear()
        Write.Print(output_text, Colors.red, interval=0)
    log_option(output_text)
    restart()

def castrick_email_search():
    clear()
    Write.Print("[!] > CastrickClues Email Search\n", default_color, interval=0)
    email = Write.Input("[?] > Enter an email to check via CastrickClues: ", default_color, interval=0).strip()
    if not email:
        Write.Print("[!] > No email provided.\n", Colors.red, interval=0)
        restart()
        return
    type_ = "email"
    query = email
    api_key = "INSERT API KEY HERE"
    headers = {"api-key": api_key}
    url = f"https://api.castrickclues.com/api/v1/search?query={query}&type={type_}"

    def tableify(obj, indent=0):
        lines = []
        prefix = " " * indent
        if isinstance(obj, dict):
            for key, value in obj.items():
                row_title = f"{prefix}{key}:"
                if isinstance(value, (dict, list)):
                    lines.append(f"| {row_title:<76}|")
                    lines.extend(tableify(value, indent + 2))
                else:
                    lines.append(format_table_row(row_title, str(value), indent))
        elif isinstance(obj, list):
            for idx, item in enumerate(obj):
                row_title = f"{prefix}[{idx}]:"
                if isinstance(item, (dict, list)):
                    lines.append(f"| {row_title:<76}|")
                    lines.extend(tableify(item, indent + 2))
                else:
                    lines.append(format_table_row(row_title, str(item), indent))
        else:
            lines.append(format_table_row(prefix.strip(), str(obj), indent))
        return lines

    def format_table_row(label, value, indent):
        row_lines = []
        max_inner_width = 78 - len(label) - 2
        words = value.split()
        current_line = ""
        label_prefix = f"{label} "
        for w in words:
            if len(current_line) + len(w) + 1 <= max_inner_width:
                if current_line:
                    current_line += " " + w
                else:
                    current_line = w
            else:
                row_lines.append(current_line)
                current_line = w
        if current_line:
            row_lines.append(current_line)
        lines_out = []
        if not row_lines:
            lines_out.append(f"| {label_prefix:<78}|")
        else:
            first_line = row_lines[0]
            lines_out.append(f"| {label_prefix + first_line:<78}|")
            for extra_line in row_lines[1:]:
                lines_out.append(f"| {' ' * (len(label_prefix))}{extra_line:<{78-len(label_prefix)}}|")
        return "\n".join(lines_out)

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        clear()
        lines = []
        lines.append(f"╭─{' '*78}─╮")
        lines.append(f"|{' '*30}Castrick Email Search{' '*30}|")
        lines.append(f"|{'='*80}|")
        lines.append(f"| Email Queried: {email:<63}|")
        lines.append(f"|{'-'*80}|")

        if not isinstance(data, (dict, list)):
            data = {"data": data}
        table_lines = tableify(data)
        if not table_lines:
            lines.append("| No structured data returned from Castrick.|")
        else:
            lines.extend(table_lines)
        lines.append(f"╰─{' '*78}─╯")
        output_text = "\n".join(lines)
        Write.Print("\n" + output_text, Colors.white, interval=0)
    except Exception as e:
        output_text = f"[!] > Error: {str(e)}"
        clear()
        Write.Print(output_text, Colors.red, interval=0)
    log_option(output_text)
    restart()

def virustotal_domain_report():
    clear()
    domain = Write.Input("[?] > Enter domain for VirusTotal report: ", default_color, interval=0).strip()
    if not domain:
        clear()
        Write.Print("[!] > No domain provided.\n", default_color, interval=0)
        restart()
        return
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {
        "accept": "application/json",
        "x-apikey": "INSERT API KEY HERE"
    }
    try:
        response = requests.get(url, headers=headers, timeout=60)
        if response.status_code == 200:
            data = response.json()
            formatted_data = json.dumps(data, indent=2)
            output_text = f"[+] VirusTotal Domain Report for {domain}:\n{formatted_data}"
            Write.Print(output_text, Colors.white, interval=0)
        else:
            output_text = f"[!] > Error: HTTP {response.status_code} - {response.text}"
            Write.Print(output_text, Colors.red, interval=0)
    except Exception as e:
        output_text = f"[!] > Exception: {str(e)}"
        Write.Print(output_text, Colors.red, interval=0)
    log_option(output_text)
    restart()

def malice_search():
    clear()
    Write.Print("[!] > Enter text to analyze for potential malicious intent:\n", default_color, interval=0)
    malicious_text = Write.Input("[?] > ", default_color, interval=0).strip()
    if not malicious_text:
        clear()
        Write.Print("[!] > No text provided.\n", Colors.red, interval=0)
        restart()
        return

    base_prompt = (
        "You are a specialized text analysis system designed to evaluate and identify potentially malicious content in user-provided text. "
        "Analyze the input for common indicators of phishing attempts (urgent language, requests for sensitive information, impersonation of legitimate entities), "
        "scam patterns (promises of unrealistic rewards, pressure tactics, unusual payment requests), and other malicious features (social engineering tactics, manipulation attempts, suspicious links or contact information). "
        "Compare the text against known patterns of fraudulent communications, examining factors such as urgency, emotional manipulation, grammatical irregularities, and suspicious requests. "
        "For each analysis, provide a risk assessment categorized as: Low Risk (minimal to no suspicious elements present), Medium Risk (some concerning elements but lacking definitive malicious intent), or High Risk (multiple red flags indicating likely malicious intent). "
        "Include specific reasons for the risk classification and highlight the concerning elements identified. Consider context, tone, linguistic patterns, and requested actions when determining the risk level. "
        "Provide your assessment in a structured format that clearly outlines the risk level, identified suspicious elements, and reasoning behind the classification. "
        "Flag any immediate security concerns that require urgent attention."
    )
    payload = {
        "model": "sonar-reasoning-pro",
        "messages": [
            {"role": "system", "content": base_prompt},
            {"role": "user", "content": f"Analyze the following text for potential malicious intent:\n\n{malicious_text}"}
        ],
        "max_tokens": 8000,
        "temperature": 1.1
    }

    result_text = ""
    try:
        response = requests.post(PERPLEXITY_API_URL, headers=perplexity_headers, json=payload, timeout=60)
        if response.status_code == 200:
            data = response.json()
            result_text = data["choices"][0]["message"]["content"]
        else:
            result_text = f"[!] > Error from Perplexity: HTTP {response.status_code}\n{response.text}\n"
    except Exception as e:
        result_text = f"[!] > Error: {str(e)}\n"

    clear()
    malice_output = f"""
╭─{' '*78}─╮
|{' '*28}Malice Search Analysis{' '*28}|
|{'='*80}|
| [+] > Input Text: {malicious_text[:60]:<60}|
|{'-'*80}|
{result_text}
╰─{' '*78}─╯
"""
    Write.Print(malice_output, Colors.white, interval=0)
    log_option(malice_output)
    restart()

def supply_vendor_search():
    clear()
    Write.Print("[!] > Supply/Vendor Risk Assessment\n", default_color, interval=0)
    company_name = Write.Input("[?] > Enter Company Name: ", default_color, interval=0).strip()
    start_date = Write.Input("[?] > Enter Start Date (YYYY-MM-DD): ", default_color, interval=0).strip()
    if not company_name or not start_date:
        clear()
        Write.Print("[!] > Company name and start date are required.\n", Colors.red, interval=0)
        restart()
        return
    base_prompt = (
        "Please provide a comprehensive risk assessment for " + company_name +
        "covering the period from " + start_date + " to present. Include any documented incidents, regulatory violations, compliance issues, legal proceedings, and public controversies. "
        "Focus on areas that could impact business continuity, reputation, or contractual obligations, including but not limited to: data breaches, cybersecurity incidents, environmental violations, labor disputes, financial irregularities, supply chain disruptions, product quality issues, and regulatory non-compliance. "
        "Detail the nature of each incident, its resolution status, any penalties or settlements imposed, and implemented remediation measures. Additionally, highlight any patterns of recurring issues or systemic problems. You must cite all sources in Chicago format."
    )
    payload = {
        "model": "sonar-reasoning-pro",
        "messages": [
            {"role": "system", "content": base_prompt},
            {"role": "user", "content": f"Supply/Vendor Risk Assessment for {company_name} from {start_date} to present."}
        ],
        "max_tokens": 8000,
        "temperature": 1.1
    }
    result_text = ""
    try:
        response = requests.post(PERPLEXITY_API_URL, headers=perplexity_headers, json=payload, timeout=60)
        if response.status_code == 200:
            data = response.json()
            result_text = data["choices"][0]["message"]["content"]
        else:
            result_text = f"[!] > Error from Perplexity: HTTP {response.status_code}\n{response.text}\n"
    except Exception as e:
        result_text = f"[!] > Error: {str(e)}\n"
    clear()
    output_text = f"""
╭─{' '*78}─╮
|{' '*26}Supply/Vendor Risk Assessment{' '*26}|
|{'='*80}|
| [+] > Company: {company_name:<62}|
| [+] > Period:  {start_date} to present{' '*(62-len(start_date)-len(" to present"))}|
|{'-'*80}|
{result_text}
╰─{' '*78}─╯
"""
    Write.Print(output_text, Colors.white, interval=0)
    log_option(output_text)
    restart()



def wayback_lookup(domain, **kwargs):
    if not domain:
        Write.Print("[!] No domain provided for Wayback lookup.\n", Colors.red, interval=0)
        restart()
        return

    result = {
        "status": "failure",
        "message": "No data found.",
        "data": {}
    }

    base_url = "http://web.archive.org/cdx/search/cdx"
    params = {
        "url": domain,
        "output": "json",
        "fl": "original,timestamp",
        "collapse": "digest",
        "filter": "statuscode:200",
        "limit": 20
    }

    try:
        resp = requests.get(base_url, params=params, timeout=600)
        resp.raise_for_status()
        data = resp.json()

        if len(data) <= 1:
            Write.Print("[!] > No historical snapshots found (or none with status 200).\n", Colors.red, interval=0)
            restart()
            return

        raw_snapshots = data[1:]
        snapshots = []

        output_text = f"\nWayback Machine Snapshots for {domain}:\n"
        for original_url, timestamp in raw_snapshots:
            archive_url = f"https://web.archive.org/web/{timestamp}/{original_url}"
            output_text += f"- {timestamp} -> {archive_url}\n"
            snapshots.append({
                "timestamp": timestamp,
                "original_url": original_url,
                "archive_url": archive_url
            })

        result["status"] = "success"
        result["message"] = "Wayback Machine data retrieved successfully."
        result["data"] = {"domain": domain, "snapshots": snapshots}
        return result

    except Exception as e:
        Write.Print(f"[!] > Error fetching Wayback Machine data: {str(e)}\n", Colors.red, interval=0)
        return result



def basic_port_scan(target, ports=[20, 21, 22, 80, 443, 8080, 23, 25, 53, 67, 68, 69, 88, 110, 123, 137, 138, 139, 143, 162, 162, 389, 427, 445, 465, 500, 636, 993, 995, 1433, 1434, 3306, 5060, 5061]):
    clear()
    Write.Print(f"[!] >Port Scan for {target}\n", default_color, interval=0)
    result_lines = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        try:
            result = sock.connect_ex((target, port))
            if result == 0:
                result_lines.append(f"Port {port} is OPEN.")
            else:
                result_lines.append(f"Port {port} is closed or filtered.")
        except Exception as e:
            result_lines.append(f"Port {port} -> Error: {str(e)}")
        finally:
            sock.close()

    report = f"\nPort Scan Results for {target}:\n" + "\n".join(result_lines)
    Write.Print(report, Colors.white, interval=0)
    log_option(report)

    print("[?] Export port scan results to JSON? (Y/N): ", end="")
    if input().strip().upper() == "Y":
        export_json({"target": target, "scan_results": result_lines}, filename_prefix="port_scan")
    restart()

def bulk_domain_processing(csv_path):
    clear()
    if not os.path.isfile(csv_path):
        Write.Print("[!] CSV file not found or invalid path.\n", Colors.red, interval=0)
        restart()
        return

    try:
        with open(csv_path, "r", encoding="utf-8") as f:
            lines = [x.strip() for x in f if x.strip()]
    except UnicodeDecodeError:
        with open(csv_path, "r", encoding="latin-1") as f:
            lines = [x.strip() for x in f if x.strip()]

    Write.Print(f"[!] Found {len(lines)} entries in {csv_path}.\n", default_color, interval=0)
    Write.Print("Choose the checks you want to run on each domain/IP:\n", Colors.white, interval=0)
    Write.Print("[1] DNS Lookup\n[2] WHOIS Lookup\n[3] Subdomain Enumeration\n[4] IP Info (if IP)\n[5] SSL Cert Info (if domain)\n\n", Colors.white, interval=0)
    chosen = Write.Input("[?] Enter your choices separated by commas (e.g. 1,2,3): ", default_color, interval=0).strip()
    chosen_set = set(x.strip() for x in chosen.split(","))

    results = {}
    for entry in lines:
        out_lines = [f"Results for {entry}:"]
        if "1" in chosen_set:
            try:
                out_lines.append("DNS Lookup:")
                try:
                    answers = dns.resolver.resolve(entry, 'A')
                    out_lines.append(f"A Records: {[str(a) for a in answers]}")
                except:
                    out_lines.append("No A records / Error retrieving.")
            except Exception as e:
                out_lines.append(f"DNS Lookup Error: {str(e)}")
        if "2" in chosen_set:
            try:
                w = whois.whois(entry)
                out_lines.append(f"WHOIS: {w.domain_name}, Registrar: {w.registrar}")
            except Exception as e:
                out_lines.append(f"WHOIS Error: {str(e)}")
        if "3" in chosen_set and validate_domain_input(entry):
            try:
                out_lines.append("Subdomain Enumeration: See script logs for details.")
            except Exception as e:
                out_lines.append(f"Subdomain enumeration error: {str(e)}")
        if "4" in chosen_set:
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', entry):
                details = get_ip_details(entry)
                if details:
                    out_lines.append(f"IP Info: City={details.get('city','N/A')} Region={details.get('region','N/A')} Org={details.get('org','N/A')}")
                else:
                    out_lines.append("IP Info not available.")
            else:
                out_lines.append("Not an IP, skipping IP Info.")
        if "5" in chosen_set and validate_domain_input(entry):
            try:
                context = ssl.create_default_context()
                with socket.create_connection((entry, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=entry) as ssock:
                        cert = ssock.getpeercert()
                subject = dict(x[0] for x in cert['subject'])
                issuer = dict(x[0] for x in cert['issuer'])
                out_lines.append(f"SSL Issued To: {subject.get('commonName','N/A')}, By: {issuer.get('commonName','N/A')}")
            except Exception as e:
                out_lines.append(f"SSL Error: {str(e)}")

        results[entry] = "\n".join(out_lines)

    for entry, data in results.items():
        Write.Print("\n" + data + "\n", Colors.white, interval=0)

    print("[?] Export bulk domain results to JSON? (Y/N): ", end="")
    if input().strip().upper() == "Y":
        export_json(results, filename_prefix="bulk_domain")
    restart()

def known_vulnerability_search():
    clear()
    Write.Print("[!] >Vulnerability Search\n", Colors.black, interval=0)
    keyword = Write.Input("[?] > Enter a keyword to search for known vulnerabilities: ", Colors.black, interval=0).strip()
    if not keyword:
        Write.Print("[!] > No keyword provided.\n", Colors.red, interval=0)
        restart()
        return

    url = "https://known-vulnerability-search.p.rapidapi.com/search"
    payload = { "keyword": keyword }
    headers = {
        "x-rapidapi-key": "INSERT API KEY HERE",
        "x-rapidapi-host": "known-vulnerability-search.p.rapidapi.com",
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(url, json=payload, headers=headers, timeout=60)
        response.raise_for_status()
        data = response.json()
        clear()
        output_text = f"[+] Known Vulnerability Search results for keyword '{keyword}':\n"
        if 'vulnerabilities' in data:
            vulnerabilities = data['vulnerabilities']
            for vuln in vulnerabilities:
                output_text += f"- ID: {vuln.get('id', 'N/A')}\n"
                output_text += f"  Description: {vuln.get('description', 'N/A')}\n"
                output_text += f"  Severity: {vuln.get('severity', 'N/A')}\n"
                output_text += f"  CVSS Score: {vuln.get('cvss_score', 'N/A')}\n"
                output_text += f"  CVSS Vector: {vuln.get('cvss_vector', 'N/A')}\n"
                output_text += f"  Published Date: {vuln.get('published_date', 'N/A')}\n"
                output_text += f"  Last Modified Date: {vuln.get('last_modified_date', 'N/A')}\n"
                output_text += f"  References: {', '.join(vuln.get('references', []))}\n"
                output_text += "-" * 78 + "\n"
        else:
            output_text += "No vulnerabilities found.\n"

        Write.Print(output_text, Colors.white, interval=0)
        log_option(output_text)

        print("[?] Export vulnerability search to JSON? (Y/N): ", end="")
        if input().strip().upper() == "Y":
            export_json({"keyword": keyword, "results": data}, filename_prefix="known_vulnerability_search")

    except requests.exceptions.Timeout:
        Write.Print("[!] > Request timed out when contacting the vulnerability search API.\n", Colors.default_color, interval=0)
    except requests.exceptions.RequestException as e:
        Write.Print(f"[!] > Error: {str(e)}\n", Colors.default_color, interval=0)
    except Exception as e:
        Write.Print(f"[!] > An error occurred: {str(e)}\n", Colors.default_color, interval=0)
    restart()

def phone_leak_search():
    clear()
    Write.Print("[!] > Phone Leak Search\n", Colors.white, interval=0)
    phone_number = Write.Input("[?] > Enter the phone number to search for leaks: ", Colors.white, interval=0).strip()
    if not phone_number:
        Write.Print("[!] > No phone number provided.\n", Colors.red, interval=0)
        restart()
        return

    conn = http.client.HTTPSConnection("phone-leak-search.p.rapidapi.com")
    headers = {
        'x-rapidapi-key': "INSERT API KEY HERE",
        'x-rapidapi-host': "phone-leak-search.p.rapidapi.com"
    }
    conn.request("GET", f"/api/search/origin?phone={phone_number}", headers=headers)

    res = conn.getresponse()
    data = res.read()

    if res.status != 200:
        Write.Print(f"[!] > Error: Received status code {res.status}\n", Colors.red, interval=0)
        restart()
        return

    try:
        response_data = json.loads(data.decode("utf-8"))
        clear()
        output_text = f"[+] Phone Leak Search results for phone number '{phone_number}':\n"
        if 'results' in response_data:
            results = response_data['results']
            for result in results:
                output_text += f"- Source: {result.get('source', 'N/A')}\n"
                output_text += f"  Data: {result.get('data', 'N/A')}\n"
                output_text += "-" * 78 + "\n"
        else:
            output_text += "No leaks found.\n"

        Write.Print(output_text, Colors.white, interval=0)
        log_option(output_text)

        print("[?] Export phone leak search to JSON? (Y/N): ", end="")
        if input().strip().upper() == "Y":
            export_json({"phone_number": phone_number, "results": response_data}, filename_prefix="phone_leak_search")

    except json.JSONDecodeError:
        Write.Print("[!] > Error: Failed to decode JSON response.\n", Colors.red, interval=0)
    except Exception as e:
        Write.Print(f"[!] > An error occurred: {str(e)}\n", Colors.red, interval=0)
    restart()

def aes_encrypt():
    clear()
    Write.Print("[!] > AES Encryption\n", Colors.white, interval=0)
    plaintext = Write.Input("[?] > Enter the plaintext to encrypt: ", Colors.white, interval=0).strip()
    encryption_key = Write.Input("[?] > Enter the encryption key: ", Colors.white, interval=0).strip()

    if not plaintext or not encryption_key:
        Write.Print("[!] > Plaintext and encryption key are required.\n", Colors.red, interval=0)
        restart()
        return

    conn = http.client.HTTPSConnection("encryption-api2.p.rapidapi.com")
    payload = json.dumps({"text": plaintext, "encryption_key": encryption_key})
    headers = {
        'x-rapidapi-key': "INSERT API KEY HERE",
        'x-rapidapi-host': "encryption-api2.p.rapidapi.com",
        'Content-Type': "application/json"
    }
    conn.request("POST", "/enc.php", payload, headers)

    res = conn.getresponse()
    data = res.read()

    if res.status != 200:
        Write.Print(f"[!] > Error: Received status code {res.status}\n", Colors.red, interval=0)
        restart()
        return

    try:
        response_data = json.loads(data.decode("utf-8"))
        clear()
        output_text = "[+] Encryption Results:\n"
        output_text += f"- Ciphertext: {response_data.get('ciphertext', 'N/A')}\n"
        output_text += f"- IV: {response_data.get('iv', 'N/A')}\n"

        Write.Print(output_text, Colors.white, interval=0)
        log_option(output_text)

        print("[?] Export encryption results to JSON? (Y/N): ", end="")
        if input().strip().upper() == "Y":
            export_json({"plaintext": plaintext, "encryption_key": encryption_key, "results": response_data}, filename_prefix="aes_encrypt")

    except json.JSONDecodeError:
        Write.Print("[!] > Error: Failed to decode JSON response.\n", Colors.red, interval=0)
    except Exception as e:
        Write.Print(f"[!] > An error occurred: {str(e)}\n", Colors.red, interval=0)
    restart()

def aes_decrypt():
    clear()
    Write.Print("[!] > AES Decryption\n", Colors.white, interval=0)
    ciphertext = Write.Input("[?] > Enter the ciphertext to decrypt: ", Colors.white, interval=0).strip()
    encryption_key = Write.Input("[?] > Enter the encryption key to decrypt: ", Colors.white, interval=0).strip()
    iv = Write.Input("[?] > Enter the Initialization Vector to decrypt: ", Colors.white, interval=0).strip()

    if not ciphertext or not encryption_key or not iv:
        Write.Print("[!] > Ciphertext, encryption key, and IV are required.\n", Colors.red, interval=0)
        restart()
        return

    conn = http.client.HTTPSConnection("encryption-api2.p.rapidapi.com")
    payload = json.dumps({"ciphertext": ciphertext, "encryption_key": encryption_key, "iv": iv})
    headers = {
        'x-rapidapi-key': "INSERT API KEYS HERE",
        'x-rapidapi-host': "encryption-api2.p.rapidapi.com",
        'Content-Type': "application/json"
    }
    conn.request("POST", "/dec.php", payload, headers)

    res = conn.getresponse()
    data = res.read()

    if res.status != 200:
        Write.Print(f"[!] > Error: Received status code {res.status}\n", Colors.red, interval=0)
        restart()
        return

    try:
        response_data = json.loads(data.decode("utf-8"))
        clear()
        output_text = "[+] Decryption Results:\n"
        output_text += f"- Plaintext: {response_data.get('plaintext', 'N/A')}\n"
        Write.Print(output_text, Colors.white, interval=0)
        log_option(output_text)
        print("[?] Export decryption results to JSON? (Y/N): ", end="")
        if input().strip().upper() == "Y":
            export_json({"ciphertext": ciphertext, "encryption_key": encryption_key, "iv": iv, "results": response_data}, filename_prefix="aes_decrypt")
    except json.JSONDecodeError:
        Write.Print("[!] > Error: Failed to decode JSON response.\n", Colors.red, interval=0)
    except Exception as e:
        Write.Print(f"[!] > An error occurred: {str(e)}\n", Colors.red, interval=0)
    restart()

def malicious_scan():
    clear()
    Write.Print("[!] > Malicious/Scam URL Analysis\n", default_color, interval=0)

    conn = http.client.HTTPSConnection("malicious-scanner.p.rapidapi.com")
    headers = {
        'x-rapidapi-key': "INSERT API KEY HERE",
        'x-rapidapi-host': "malicious-scanner.p.rapidapi.com"
    }
    url = "https%3A%2F%2Fvryjm.page.link%2FjS6a"  
    conn.request("GET", f"/rapid/url?url={url}", headers=headers)

    res = conn.getresponse()
    data = res.read()
    output_text = data.decode("utf-8")

    Write.Print(output_text, Colors.white, interval=0)
    log_option(output_text)
    restart()

def email_intelligence_check():
    clear()
    Write.Print("[!] > Email Intelligence Search\n", default_color, interval=0)
    email = Write.Input("[?] > Enter the email address to search: ", default_color, interval=0).strip()
    if not email:
        Write.Print("[!] > Please enter an email address.\n", default_color, interval=0)
        return
    encoded_email = urllib.parse.quote(email)
    conn = http.client.HTTPSConnection("email-intelligence-api.p.rapidapi.com")
    headers = {
        'x-rapidapi-key': "INSERT API KEY HERE",
        'x-rapidapi-host': "email-intelligence-api.p.rapidapi.com"
    }
    conn.request("GET", f"/v1/check?email={encoded_email}", headers=headers)
    res = conn.getresponse()
    data = res.read()
    output_json = data.decode("utf-8")
    try:
        output_data = json.loads(output_json)
        output_pretty = json.dumps(output_data, indent=4, ensure_ascii=False)
        Write.Print(output_pretty, Colors.white, interval=0)
        log_option(output_pretty)
    except json.JSONDecodeError:
        Write.Print("[!] > Failed to decode JSON response.\n", Colors.red, interval=0)
    restart()

def reddit_user_info():

    clear()
    Write.Print("[!] Reddit User Info\n", default_color, interval=0)

    username = Write.Input("[?] Enter the Reddit username: ", default_color, interval=0).strip()
    if not username:
        Write.Print("[!] Please enter a valid Reddit username.\n", default_color, interval=0)
        return

    encoded_username = quote(username)

    reddit_user_url = f"https://www.reddit.com/user/{encoded_username}/"

    encoded_url = quote(reddit_user_url, safe="%/:=&?~#+!$,;'@()*[]")

    conn = http.client.HTTPSConnection("reddit-scraper2.p.rapidapi.com")
    headers = {
        'x-rapidapi-key': "INSERT API KEY HERE",
        'x-rapidapi-host': "reddit-scraper2.p.rapidapi.com"
    }

    conn.request("GET", f"/user_info?user={encoded_url}", headers=headers)

    res = conn.getresponse()
    data = res.read()
    output_text = data.decode("utf-8")

    Write.Print(output_text, Colors.white, interval=0)
    log_option(output_text)
    restart()

def fetch_tiktok_data():

    conn = http.client.HTTPSConnection("tiktok-private1.p.rapidapi.com")
    headers = {
        'x-rapidapi-key': "INSERT API KEY HERE",
        'x-rapidapi-host': "tiktok-private1.p.rapidapi.com"
    }
    conn.request("GET", "/user", headers=headers)
    res = conn.getresponse()
    if res.status == 200:
        data = res.read()
        output_text = data.decode("utf-8")
        Write.Print(output_text, Colors.white, interval=0)
        log_option(output_text)
    else:
        Write.Print(f"[!] Error: Received status code {res.status}.", Colors.red, interval=0)
    restart()

def scrape_website_contacts():

    clear()
    Write.Print("[!] > Scrape Website Contacts\n", default_color, interval=0)

    domain = Write.Input("[?] > Enter the domain to scrape (e.g., example.com): ", default_color, interval=0).strip()
    if not domain:
        Write.Print("[!] > Please enter a domain.\n", default_color, interval=0)
        return

    encoded_domain = quote(domain)

    conn = http.client.HTTPSConnection("website-social-scraper-api.p.rapidapi.com")
    headers = {
        'x-rapidapi-key': "INSERT API KEY HERE",
        'x-rapidapi-host': "website-social-scraper-api.p.rapidapi.com"
    }

    conn.request("GET", f"/contacts?website={encoded_domain}", headers=headers)
    res = conn.getresponse()
    data = res.read()

    if res.status == 200:
        output_text = data.decode("utf-8")
        Write.Print(output_text, Colors.white, interval=0)
        log_option(output_text)
    else:
        Write.Print(f"[!] > Error: Received status code {res.status}.", Colors.red, interval=0)

    restart()

def validate_whatsapp_number(phone_number):

    conn = http.client.HTTPSConnection("whatsapp-number-validator3.p.rapidapi.com")
    payload = f'{{"phone_number":"{phone_number}"}}'
    headers = {
        'x-rapidapi-key': "INSERT API KEY HERE",
        'x-rapidapi-host': "whatsapp-number-validator3.p.rapidapi.com",
        'Content-Type': "application/json"
    }

    conn.request("POST", "/WhatsappNumberHasItWithToken", payload, headers)
    res = conn.getresponse()

    if res.status == 200:
        data = res.read()
        output_text = data.decode("utf-8")
        Write.Print(output_text, Colors.white, interval=0)  
        log_option(output_text) 
    else:
        Write.Print(f"[!] Error: Received status code {res.status}.", Colors.red, interval=0)
    restart()

def fetch_identity_data():

    conn = http.client.HTTPSConnection("fake-identity-generation.p.rapidapi.com")
    headers = {
        'x-rapidapi-key': "INSERT API KEY HERE",
        'x-rapidapi-host': "fake-identity-generation.p.rapidapi.com"
    }
    conn.request("GET", "/identity/person/address", headers=headers)
    res = conn.getresponse()

    if res.status != 200:
        Write.Print(
            f"[!] > Error: Received status code {res.status}.",
            Colors.red, interval=0
        )
        restart()
        return
    data = res.read().decode("utf-8")
    output = json.dumps(json.loads(data), indent=4, ensure_ascii=False)
    Write.Print(output, Colors.white, interval=0)
    log_option(output)
    restart()
  
import json

def skip_trace_search():
    clear()
    Write.Print("[!] > Skip Trace Search by Name\n", default_color, interval=0)
    name = Write.Input("[?] > Enter the name for the search (e.g., Elon Musk): ", default_color, interval=0).strip()
    if not name:
        Write.Print("[!] > Please enter a valid name.\n", default_color, interval=0)
        return

    encoded_name = quote(name)

    conn = http.client.HTTPSConnection("skip-tracing-working-api.p.rapidapi.com")
    headers = {
        'x-rapidapi-key': "INSERT API KEY HERE",
        'x-rapidapi-host': "skip-tracing-working-api.p.rapidapi.com"
    }
    conn.request("GET", f"/search/byname?name={encoded_name}&page=1", headers=headers)
    res = conn.getresponse()
    if res.status == 200:
        data = res.read()
        try:
            json_data = json.loads(data.decode("utf-8"))
            output_text = json.dumps(json_data, indent=4)  # Pretty-print JSON
            Write.Print(output_text, Colors.white, interval=0)
            log_option(output_text)
        except json.JSONDecodeError:
            Write.Print("[!] Error: Failed to decode JSON response.", Colors.red, interval=0)
            restart()
    else:
        Write.Print(f"[!] Error: Received status code {res.status}.", Colors.red, interval=0)
    restart()

def skip_trace_search_by_id():
    clear()
    Write.Print("[!] Enter the ID for Skip Trace Search:\n", default_color, interval=0)
    peo_id = Write.Input("[?] > Enter the ID: ", default_color, interval=0).strip()
    if not peo_id:
        Write.Print("[!] > No ID provided.\n", Colors.red, interval=0)
        restart()
        return

    conn = http.client.HTTPSConnection("skip-tracing-working-api.p.rapidapi.com")
    headers = {
        'x-rapidapi-key': "INSERT API KEY HERE",
        'x-rapidapi-host': "skip-tracing-working-api.p.rapidapi.com"
    }
    conn.request("GET", f"/search/detailsbyID?peo_id={peo_id}", headers=headers)
    res = conn.getresponse()
    if res.status == 200:
        data = res.read()
        response_data = json.loads(data.decode("utf-8"))
        formatted_output = json.dumps(response_data, indent=2)
        Write.Print(formatted_output, Colors.white, interval=0)
        log_option(formatted_output)
    else:
        Write.Print(f"[!] Error: Received status code {res.status}.", Colors.red, interval=0)
    restart()



def settings():
    while True:
        try:
            clear()
            print("\033[1;31m   ██████╗██╗        █████╗ ████████╗███████╗")
            print("   ██╔════╝██║       ██╔══██╗╚══██╔══╝██╔════╝")
            print("   ██║     ██║       ███████║   ██║   ███████╗")
            print("   ██║     ██║       ██╔══██║   ██║   ╚════██║")
            print("   ██████╗ ███████╗  ██║  ██║   ██║   ███████║")
            print("   ╚═════╝ ╚══════╝  ╚═╝  ╚═╝   ╚═╝   ╚══════╝\033[0m")
            print("\033[1;34mC       L      A       T       S       C       O       P       E\033[0m   \033[1;31m(Version 1.11)\033[0m")
            author = "🛡️ By Josh Clatney - Ethical Pentesting Enthusiast 🛡️"
            Write.Print(author + "\n[C.I.T]\nClatScope Info Tool\n", Colors.white, interval=0)
            settings_menu = """╭─    ─╮╭─                   ─╮╭─                                         ─╮
|  №   ||       Setting       ||                Description                |
|======||=====================||===========================================|
| [1]  || Theme change        || Customize the theme                       |
| [0]  || Back to menu        || Exit the settings                         |
╰─    ─╯╰─                   ─╯╰─                                         ─╯
"""
            Write.Print(settings_menu, Colors.white, interval=0)
            settings_choice = Write.Input("[?] >  ", default_color, interval=0).strip()
            if settings_choice == "1":
                change_color()
            elif settings_choice == "0":
                return
            else:
                clear()
                Write.Print("[!] > Invalid input.\n", Colors.red, interval=0)
        except KeyboardInterrupt:
            clear()
            Write.Print("[!] > Exiting on user request...\n", Colors.white, interval=0)
            exit()

def change_color():
    global default_color
    clear()
    color_menu = """
╭─    ─╮╭─                     ─╮
|  №   ||         Color         |
|======||=======================|
| [1]  || Red                   |
| [2]  || Blue                  |
| [3]  || Green                 |
| [4]  || Yellow                |
| [5]  || Cyan                  |
| [6]  || White                 |
|------||-----------------------|
| [0]  || Back to settings menu |
╰─    ─╯╰─                     ─╯
"""
    Write.Print(color_menu, Colors.white, interval=0)
    color_choice = Write.Input("\n\n[?] >  ", default_color, interval=0).strip()
    color_map = {
        "1": Colors.red,
        "2": Colors.blue,
        "3": Colors.green,
        "4": Colors.yellow,
        "5": Colors.cyan,
        "6": Colors.white
    }
    if color_choice in color_map:
        default_color = color_map[color_choice]
        clear()
        Write.Print("[!] > Colour has been changed.\n", default_color, interval=0)
    elif color_choice == "0":
        settings()
    else:
        clear()
        Write.Print("[!] > Invalid choice.\n", Colors.red, interval=0)
    restart()

def truecaller_search(phone_number):
    conn = http.client.HTTPSConnection("truecaller-data2.p.rapidapi.com")
    headers = {
        'x-rapidapi-key':"INSERT API KEY HERE",
        'x-rapidapi-host':"truecaller-data2.p.rapidapi.com"
    }

    conn.request("GET", f"/search/{phone_number}", headers=headers)
    res = conn.getresponse()

    if res.status == 200:
        data = res.read()
        try:
            output_JSON = json.loads(data.decode("utf-8"))
            formatted_output = json.dumps(output_JSON, indent=4)  # pretty print JSON
            Write.Print(formatted_output, Colors.white, interval=0)
            log_option(formatted_output)
        except json.JSONDecodeError:
            Write.Print("[!] Error: Failed to decode JSON response.", Colors.red, interval=0)
    else:
        Write.Print(f"[!] Error: Received status code {res.status}.", Colors.red, interval=0)

    restart()

def search_sex_offender(first_name="Joseph", last_name="Nigro", zipcode="10465"):

    conn = http.client.HTTPSConnection("sex-offenders.p.rapidapi.com")
    headers = {
        'x-rapidapi-key': "INSERT API KEY HERE",
        'x-rapidapi-host': "sex-offenders.p.rapidapi.com"
    }
    endpoint = f"/sexoffender?firstName={first_name}&lastName={last_name}&zipcode={zipcode}&mode=extensive"
    conn.request("GET", endpoint, headers=headers)

    res = conn.getresponse()
    if res.status == 200:
        data = res.read()
        output_text = data.decode("utf-8")
        Write.Print(output_text, Colors.white, interval=0)
        log_option(output_text)
    else:
        Write.Print(f"[!] Error: Received status code {res.status}.", Colors.red, interval=0)
    restart()

def ship_info(mmsi):
    if not mmsi:
        clear()
        Write.Print("[!] > Please enter a valid MMSI number.\n", default_color, interval=0)
        restart()
        return
    url = f"https://api.facha.dev/v1/ship/{mmsi}"
    try:
        response = requests.get(url, timeout=60)
        response.raise_for_status()
        data = response.json()
        output_text = f"Ship Info for MMSI {mmsi}:\n" + json.dumps(data, indent=2)
        clear()
        Write.Print(output_text, Colors.white, interval=0)
        log_option(output_text)
        print("[?] Export ship info to JSON? (Y/N): ", end="")
        if input().strip().upper() == "Y":
            export_json({"mmsi": mmsi, "data": data}, filename_prefix="ship_info")
    except Exception as e:
        clear()
        Write.Print(f"[!] > Error retrieving ship info: {str(e)}\n", Colors.red, interval=0)
    restart()

def ship_radius(latitude, longitude, radius):

    if not latitude or not longitude or not radius:
        clear()
        Write.Print("[!] > Please enter valid latitude, longitude, and radius values.\n", default_color, interval=0)
        restart()
        return

    url = f"https://api.facha.dev/v1/ship/radius/{latitude}/{longitude}/{radius}"
    try:
        response = requests.get(url, timeout=60)
        response.raise_for_status()
        data = response.json()
        output_text = (
            f"Ships within a radius of {radius} around ({latitude}, {longitude}):\n" 
            + json.dumps(data, indent=2)
        )
        clear()
        Write.Print(output_text, Colors.white, interval=0)
        log_option(output_text)
        print("[?] Export ship radius data to JSON? (Y/N): ", end="")
        if input().strip().upper() == "Y":
            export_json({
                "latitude": latitude,
                "longitude": longitude,
                "radius": radius,
                "data": data
            }, filename_prefix="ship_radius")
    except Exception as e:
        clear()
        Write.Print(f"[!] > Error retrieving ship radius info: {str(e)}\n", Colors.red, interval=0)
    restart()

def aircraft_live_range(lat, lon, range_value):
   
    if not lat or not lon or not range_value:
        clear()
        Write.Print("[!] > Please enter valid latitude, longitude, and range values.\n", default_color, interval=0)
        restart()
        return
    
    url = f"https://api.facha.dev/v1/aircraft/live/range/{lat}/{lon}/{range_value}"
    try:
        response = requests.get(url, timeout=60)
        response.raise_for_status()
        data = response.json()
        output_text = (
            f"Live aircraft within a range of {range_value} around ({lat}, {lon}):\n"
            + json.dumps(data, indent=2)
        )
        clear()
        Write.Print(output_text, Colors.white, interval=0)
        log_option(output_text)
        print("[?] Export aircraft live range data to JSON? (Y/N): ", end="")
        if input().strip().upper() == "Y":
            export_json({
                "latitude": lat,
                "longitude": lon,
                "range": range_value,
                "data": data
            }, filename_prefix="aircraft_live_range")
    except Exception as e:
        clear()
        Write.Print(f"[!] > Error retrieving aircraft live range info: {str(e)}\n", Colors.red, interval=0)
    restart()

def aircraft_live_callsign(callsign):
    if not callsign:
        clear()
        Write.Print("[!] > Please enter a valid callsign.\n", default_color, interval=0)
        restart()
        return
    url = f"https://api.facha.dev/v1/aircraft/live/callsign/{callsign}"
    try:
        response = requests.get(url, timeout=60)
        response.raise_for_status()
        data = response.json()
        output_text = (
            f"Live aircraft info for callsign '{callsign}':\n" +
            json.dumps(data, indent=2)
        )
        clear()
        Write.Print(output_text, Colors.white, interval=0)
        log_option(output_text)
        print("[?] Export aircraft callsign data to JSON? (Y/N): ", end="")
        if input().strip().upper() == "Y":
            export_json({
                "callsign": callsign,
                "data": data
            }, filename_prefix="aircraft_live_callsign")
    except Exception as e:
        clear()
        Write.Print(f"[!] > Error retrieving aircraft info for callsign '{callsign}': {str(e)}\n", Colors.red, interval=0)
    restart()

import requests
import json

def predicta_search():
    clear()
    Write.Print("[!] Predicta Search:\n", default_color, interval=0)

    query = Write.Input("[?] Enter the query (e.g., email or phone number): ", default_color, interval=0).strip()
    if not query:
        Write.Print("[!] Query is required.", Colors.red, interval=0)
        restart()
        return

    query_type = Write.Input("[?] Enter the query type (email/phone): ", default_color, interval=0).strip().lower()
    if query_type not in ["email", "phone"]:
        Write.Print("[!] Invalid query type. Use 'email' or 'phone'.", Colors.red, interval=0)
        restart()
        return

    url = "https://dev.predictasearch.com/api/search"
    api_key = "INSERT API KEY HERE"
    headers = {
        'x-api-key': api_key,
        'Content-Type': 'application/json'
    }

    payload = {
        "query": query,
        "query_type": query_type,
        "networks": ["all"]  # Default networks (do not modify)
    }

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=60)
        if response.status_code == 200:
            data = response.json()
            output_text = json.dumps(data, indent=2)  # Format the response for better readability
            Write.Print(output_text, Colors.white, interval=0)
            log_option(output_text)
        else:
            Write.Print(f"[!] Error: HTTP {response.status_code} - {response.text}", Colors.red, interval=0)
    except Exception as e:
        Write.Print(f"[!] Error: {str(e)}", Colors.red, interval=0)

    restart()

def validate_credit_card():

    card_number = Write.Input("[?] > Enter the credit card number to validate: ", default_color, interval=0).strip()
    if not card_number:
        Write.Print("[!] > No credit card number provided.\n", Colors.red, interval=0)
        restart()
        return

    conn = http.client.HTTPSConnection("credit-card-validator2.p.rapidapi.com")
    payload = f'{{"cardNumber":"{card_number}"}}'
    headers = {
        'x-rapidapi-key': "INSERT API KEY HERE",
        'x-rapidapi-host': "credit-card-validator2.p.rapidapi.com",
        'Content-Type': "application/json"
    }
    conn.request("POST", "/validate-credit-card", payload, headers)
    res = conn.getresponse()
    if res.status == 200:
        data = res.read()
        output_text = data.decode("utf-8")
        Write.Print(output_text, Colors.white, interval=0)
        log_option(output_text)
    else:
        Write.Print(f"[!] Error: Received status code {res.status}.", Colors.red, interval=0)
    restart()

def email_domain_validation(domain):
    conn = http.client.HTTPSConnection("mailcheck.p.rapidapi.com")

    headers = {
        'x-rapidapi-key': "INSERT API KEY HERE",
        'x-rapidapi-host': "mailcheck.p.rapidapi.com"
    }

    conn.request("GET", f"/?domain={domain}", headers=headers)

    res = conn.getresponse()
    data = res.read()

    try:
        response_data = json.loads(data.decode("utf-8"))
        formatted_data = json.dumps(response_data, indent=4, ensure_ascii=False)
        Write.Print(formatted_data, Colors.white, interval=0)
        log_option(formatted_data)
    except json.JSONDecodeError:
        Write.Print("[!] > Error: Failed to decode JSON response.", Colors.red, interval=0)

    restart()

def find_criminal_records():
    conn = http.client.HTTPSConnection("find-criminal-records-api.p.rapidapi.com")

    payload = "{}"
    headers = {
        'x-rapidapi-key': "INSERT API KEY HERE",
        'x-rapidapi-host': "find-criminal-records-api.p.rapidapi.com",
        'Content-Type': "application/json"
    }

    conn.request("POST", "/GetReport", payload, headers)
    res = conn.getresponse()
    data = res.read()
    output = data.decode("utf-8")

    print(output)

def generate_identity():

    conn = http.client.HTTPSConnection("identity-generator.p.rapidapi.com")

    headers = {
        'x-rapidapi-key': "INSERT API KEY HERE",
        'x-rapidapi-host': "identity-generator.p.rapidapi.com"
    }

    conn.request("GET", "/identitygenerator/api/", headers=headers)

    res = conn.getresponse()
    data = res.read()
    output = data.decode("utf-8")

    print(output)

def virtual_phone_numbers_detector():

    conn = http.client.HTTPSConnection("virtual-phone-numbers-detector.p.rapidapi.com")
    payload = json.dumps({
        "phone": "+447497265710"
    })
   
    headers = {
        'x-rapidapi-key': "INSERT API KEY HERE",
        'x-rapidapi-host': "virtual-phone-numbers-detector.p.rapidapi.com",
        'Content-Type': "application/json"
    }

    conn.request("POST", "/check-number", payload, headers)
    
    res = conn.getresponse()
    data = res.read()
    output = data.decode("utf-8")

    print(output)

def exerra_phishing_check():
    conn = http.client.HTTPSConnection("exerra-phishing-check.p.rapidapi.com")
    
    headers = {
        'x-rapidapi-key': "INSERT API KEY HERE",
        'x-rapidapi-host': "exerra-phishing-check.p.rapidapi.com"
    }

    conn.request("GET", "/all/domains", headers=headers)
    res = conn.getresponse()
    data = res.read()
    output = data.decode("utf-8")

    print(output)

def mac_address_lookup():
    conn = http.client.HTTPSConnection("mac-address-lookup-api-apiverve.p.rapidapi.com")
    headers = {
        'x-rapidapi-key': "INSERT API KEY HERE",
        'x-rapidapi-host': "mac-address-lookup-api-apiverve.p.rapidapi.com",
        'Accept': "application/json"
    }
    conn.request("GET", "/v1/macaddresslookup?mac=00-B0-D0-63-C2-26", headers=headers)
    res = conn.getresponse()
    data = res.read()
    output = data.decode("utf-8")

    print(output)


def main():
    while True:
        try:
            clear()
            print("\033[1;31m██████╗    ██╗          █████╗     ████████╗    ███████╗     ██████╗     ██████╗     ██████╗     ███████╗")
            print("██╔════╝    ██║         ██╔══██╗    ╚══██╔══╝    ██╔════╝    ██╔════╝    ██╔═══██╗    ██╔══██╗    ██╔════╝")
            print("██║         ██║         ███████║       ██║       ███████╗    ██║         ██║   ██║    ██████╔╝    █████╗  ")
            print("██║         ██║         ██╔══██║       ██║       ╚════██║    ██║         ██║   ██║    ██╔═══╝     ██╔══╝  ")
            print("╚██████╗    ███████╗    ██║  ██║       ██║       ███████║    ╚██████╗    ╚██████╔╝    ██║         ███████╗")
            print(" ╚═════╝    ╚══════╝    ╚═╝  ╚═╝       ╚═╝       ╚══════╝     ╚═════╝     ╚═════╝     ╚═╝         ╚══════╝\033[0m")
            print("\033[1;34mC L A T S C O P E       I N F O       T O O L\033[0m   \033[1;31m(Version 1.11)\033[0m")
            author = "🛡️ By Joshua M Clatney (Clats97) - Ethical Pentesting Enthusiast 🛡️"
            Write.Print(author + "\n[OSINT]\nOpen Sources. Clear Conclusions\n", Colors.white, interval=0)
            menu = """╭─====─╮╭─===================─╮╭─============================================================─╮
|  №   ||      Function       ||                  Description                                 |
|======||=====================||==============================================================|
| [1]  || IP Address Search   || Retrieves IP address info                                    |
| [2]  || Deep Account Search || Retrieves profiles from various websites                     |
| [3]  || Phone Search        || Retrieves phone number info                                  |
| [4]  || DNS Record Search   || Retrieves DNS records (A, CNAME, MX, NS)                     |
| [5]  || Email MX Search     || Retrieves MX info for an email                               |
| [6]  || Person Name Search  || Retrieves extensive person info                              |
| [7]  || Reverse DNS Search  || Retrieves PTR records for an IP address                      |
| [8]  || Email Header Search || Retrieves info from an email header                          |
| [9]  || Email Breach Search || Retreives email data breach info (HIBP)                      |
| [10] || WHOIS Search        || Retrieves domain registration data                           |
| [11] || Password Analyzer   || Retrieves password strength rating                           |
| [12] || Username Search     || Retrieves usernames from online accounts                     |
| [13] || Reverse Phone Search|| Retrieves references to a phone number                       |
| [14] || SSL Search          || Retrieves basic SSL certificate details from a URL           |
| [15] || Web Crawler Search  || Retrieves Robots.txt & Sitemap.xml URL file info             |
| [16] || DNSBL Search        || Retrieves IP DNS blacklist info                              |
| [17] || Web Metadata Search || Retrieves meta tags and more from a webpage                  |
| [18] || Travel Risk Search  || Retrieves a detailed travel risk assessment                  |
| [19] || Botometer Search    || Retrieves a Botometer score for an X/Twitter user account    |
| [20] || Business Search     || Retrieves general information about a business               |
| [21] || HR Email Search     || Retrieves infostealer email infection data (Hudson Rock)     |
| [22] || HR Username Search  || Retrieves infostealer username infection data (Hudson Rock)  |
| [23] || HR Domain Search    || Retrieves infostealer domain infection data (Hudson Rock)    |
| [24] || HR IP Search        || Retrieves infostealer IP address infection data (Hudson Rock)|
| [25] || Fact Check Search   || Retrieves analysis of input text for truthfulness            |
| [26] || Relationship Search || Retrieves & maps info between entities / people / businesses |
| [27] || File Metadata Search|| Retrieves metadata from various file types                   |
| [28] || Subdomain Search    || Retrieves subdomain info                                     |
| [29] || Domain Search       || Retrieves domain info (Hunter.io)                            |
| [30] || Email Search        || Retrieves email info (Hunter.io)                             |
| [31] || Email Verify Search || Retrieves email verification (Hunter.io)                     |
| [32] || Company Search      || Retrieves company enrichment (Hunter.io)                     |
| [33] || Person Info Search  || Retrieves person enrichment (Hunter.io)                      |
| [34] || Combined Search     || Retrieves combined enrichment (Hunter.io)                    |
| [35] || Email Search        || Retrieves in depth info on someone by email (CastrickClues)  |
| [36] || Virus Search        || Retrieves a VirusTotal report for a domain                   |
| [37] || Malice Search       || Retrieves info related to potential malicious content / scams|
| [38] || Supply/Vendor Search|| Retrieves comprehensive risk assessment for supply/vendors   |
| [39] || Business Rep Search || Retrieves a business reputation overview                     |
| [40] || Wayback Search      || Retrieves historical snapshots from the Wayback Machine      |
| [41] || Port Scan Search    || Retrieves scan results on common ports                       |
| [42] || Bulk CSV Search     || Retrieves multiple checks in bulk from a CSV for domain/IP   |
| [43] || Vulnerability Search|| Retrieves known vulnerabilities related to a keyword         |
| [44] || Phone Leak Search   || Retrieves leaks related to a phone number                    |
| [45] || AES Encryption      || Encrypts plaintext using AES-256-CBC encryption with an IV   |
| [46] || AES Decryption      || Decrypts ciphertext using AES-256-CBC decryption with an IV  |
| [47] || Email Intel Search  || Retrieves an email intelligence check based on user input    |
| [48] || Website Search      || Retrieves contact information from a specified website       |
| [49] || Reddit User Search  || Retrieves Reddit user info based on username input           |
| [50] || TikTok User Search  || Retrieves TikTok user info based on username input           |
| [51] || TrueCaller Search   || Retrieves TrueCaller phone number info                       |
| [52] || Sex Offender Search || Retrieves sex offender records by name and ZIP code          |
| [53] || WhatsApp Search     || Retrieves WhatsApp validation from a phone number            |
| [54] || Skip Trace Search   || Retrieves a skip trace overview by name                      |
| [55] || Skip Trace ID Search|| Retrieves a skip trace overview by ID from Skip Trace Search |
| [56] || Ship Search v1      || Retrieves ship data by searching an MMSI                     |
| [57] || Ship Search v2      || Retrieves ship data by searching a location                  |
| [58] || Aircraft Search v1  || Retrieves aircraft data by searching a location              |
| [59] || Aircraft Search v2  || Retrieves aircraft data by searching a callsign              |
| [60] || Predicta Search     || Retrieves person related data using Predicta                 |
| [61] || Credit Card Search  || Retrieves a credit card validation without storing any data  |
| [62] || Email Domain Search || Retrieves email domain validity report                       |
| [63] || Criminal Rec Search || Retrieves criminal records report (USA Only)                 |
| [64] || Identity Generator  || Generates a random identity for obfuscation or privacy       |
| [65] || Phone Number Check  || Checks if a phone number is virtual                          |
| [66] || Phishing Search     || Retrieves phishing report for a domain / URL                 |
| [67] || MAC Address Search  || Retrieves MAC address details                                |
| [0]  || Exit                || Exit ClatScope Info Tool                                     | 
| [99] || Settings            || Customize ClatScope Info Tool (colour)                       |
╰─    ─╯╰─                   ─╯╰─                                                            ─╯
"""
            Write.Print(menu, Colors.white, interval=0)
            choice = Write.Input("[?] >  ", default_color, interval=0).strip()
            if choice == "1":
                clear()
                ip = Write.Input("[?] > IP-Address: ", default_color, interval=0)
                if not ip:
                    clear()
                    Write.Print("[!] > Enter an IP Address\n", default_color, interval=0)
                    continue
                ip_info(ip)
            elif choice == "2":
                clear()
                nickname = Write.Input("[?] > Username: ", default_color, interval=0)
                if not nickname:
                    clear()
                    Write.Print("[!] > Enter the username\n", default_color, interval=0)
                    continue
                deep_account_search(nickname)
            elif choice == "3":
                clear()
                phone_number = Write.Input("[?] > Phone number: ", default_color, interval=0)
                if not phone_number:
                    clear()
                    Write.Print("[!] > Enter the phone number\n", default_color, interval=0)
                    continue
                phone_info(phone_number)
            elif choice == "4":
                clear()
                domain = Write.Input("[?] > Domain / URL: ", default_color, interval=0)
                if not domain:
                    clear()
                    Write.Print("[!] > Enter a domain / URL\n", default_color, interval=0)
                    continue
                dns_lookup(domain)
            elif choice == "5":
                clear()
                email = Write.Input("[?] > Email: ", default_color, interval=0)
                if not email:
                    clear()
                    Write.Print("[!] > Enter email\n", default_color, interval=0)
                    continue
                email_lookup(email)
            elif choice == "6":
                clear()
                first_name = Write.Input("[?] > First Name: ", default_color, interval=0)
                last_name = Write.Input("[?] > Last Name: ", default_color, interval=0)
                city = Write.Input("[?] > City/Location: ", default_color, interval=0)
                if not first_name or not last_name:
                    clear()
                    Write.Print("[!] > Enter first and last name\n", default_color, interval=0)
                    continue
                person_search(first_name, last_name, city)
            elif choice == "7":
                clear()
                ip = Write.Input("[?] > Enter an IP Address for a Reverse DNS Search: ", default_color, interval=0)
                if not ip:
                    clear()
                    Write.Print("[!] > Enter an IP address\n", default_color, interval=0)
                    continue
                reverse_dns(ip)
            elif choice == "8":
                clear()
                Write.Print("[!] > Paste the raw email headers below as one single string (end with empty line):\n", default_color, interval=0)
                lines = []
                while True:
                    line = input()
                    if not line.strip():
                        break
                    lines.append(line)
                raw_headers = "\n".join(lines)
                if not raw_headers.strip():
                    clear()
                    Write.Print("[!] > No email header was provided.\n", default_color, interval=0)
                    continue
                analyze_email_header(raw_headers)
            elif choice == "9":
                clear()
                email = Write.Input("[?] > Enter an email address for a breach check: ", default_color, interval=0)
                if not email:
                    clear()
                    Write.Print("[!] > Enter an email address\n", default_color, interval=0)
                    continue
                haveibeenpwned_check(email)
            elif choice == "10":
                clear()
                domain = Write.Input("[?] > Enter a domain / URL for WHOIS lookup: ", default_color, interval=0)
                if not domain:
                    clear()
                    Write.Print("[!] > Enter a domain / URL\n", default_color, interval=0)
                    continue
                whois_lookup(domain)
            elif choice == "11":
                password_strength_tool()
            elif choice == "12":
                username_check()
            elif choice == "13":
                clear()
                phone_number = Write.Input("[?] > Enter phone number or name to do a reverse lookup:", default_color, interval=0)
                if not phone_number:
                    clear()
                    Write.Print("[!] > Enter phone number\n", default_color, interval=0)
                    continue
                reverse_phone_lookup(phone_number)
            elif choice == "14":
                clear()
                domain = Write.Input("[?] > Enter a domain / URL for an SSL certificate verification: ", default_color, interval=0)
                if not domain:
                    clear()
                    Write.Print("[!] > Enter a domain name / URL\n", default_color, interval=0)
                    continue
                check_ssl_cert(domain)
            elif choice == "15":
                clear()
                domain = Write.Input("[?] > Enter domain to check for Robots.txt & Sitemap.xml file(s): ", default_color, interval=0)
                if not domain:
                    clear()
                    Write.Print("[!] > Enter a domain name / URL\n", default_color, interval=0)
                    continue
                check_robots_and_sitemap(domain)
            elif choice == "16":
                clear()
                ip_address = Write.Input("[?] > IP address to check DNSBL: ", default_color, interval=0)
                if not ip_address:
                    clear()
                    Write.Print("[!] > Enter an IP address\n", default_color, interval=0)
                    continue
                check_dnsbl(ip_address)
            elif choice == "17":
                clear()
                url = Write.Input("[?] > URL for metadata extraction: ", Colors.white, interval=0)
                if not url:
                    clear()
                    Write.Print("[!] > Enter a URL to get metadata\n", default_color, interval=0)
                    continue
                fetch_webpage_metadata(url)
            elif choice == "18":
                clear()
                location = Write.Input("[?] > Enter location for a travel risk analysis: ", Colors.white, interval=0)
                if not location:
                    clear()
                    Write.Print("[!] > Enter the location\n", default_color, interval=0)
                    continue
                travel_assessment(location)
            elif choice == "19":
                clear()
                botometer_search()
            elif choice == "20":
                clear()
                business_search()
            elif choice == "21":
                clear()
                hudson_rock_email_infection_check()
            elif choice == "22":
                clear()
                hudson_rock_username_infection_check()
            elif choice == "23":
                clear()
                hudson_rock_domain_infection_check()
            elif choice == "24":
                clear()
                hudson_rock_ip_infection_check()
            elif choice == "25":
                clear()
                fact_check_text()
            elif choice == "26":
                clear()
                relationship_search()
            elif choice == "27":
                clear()
                file_path = Write.Input(" 🐸 Enter path to the file you want analyzed: ", default_color, interval=0)
                read_file_metadata(file_path)
            elif choice == "28":
                clear()
                domain = Write.Input("[?] > Enter domain for subdomain enumeration: ", default_color, interval=0)
                subdomain_enumeration(domain)
            elif choice == "29":
                clear()
                hunter_domain_search()
            elif choice == "30":
                clear()
                hunter_email_finder()
            elif choice == "31":
                clear()
                hunter_email_verifier()
            elif choice == "32":
                clear()
                hunter_company_enrichment()
            elif choice == "33":
                clear()
                hunter_person_enrichment()
            elif choice == "34":
                clear()
                hunter_combined_enrichment()
            elif choice == "35":
                clear()
                castrick_email_search()
            elif choice == "36":
                clear()
                virustotal_domain_report()
            elif choice == "37":
                clear()
                malice_search()
            elif choice == "38":
                clear()
                supply_vendor_search()
            elif choice == "39":
                clear()
                business_reputation_search()
            elif choice == "40":
                clear()
                domain = Write.Input("[?] > Enter domain for Wayback lookup: ", default_color, interval=0)
                wayback_lookup(domain)
            elif choice == "41":
                clear()
                target = Write.Input("[?] > Enter IP or domain to do a port scan: ", default_color, interval=0)
                basic_port_scan(target)
            elif choice == "42":
                clear()
                csv_path = Write.Input("[?] > Enter path to CSV file: ", Colors.white, interval=0)
                bulk_domain_processing(csv_path)
            elif choice == "43":
                clear()
                known_vulnerability_search()
            elif choice == "44":
                clear()
                phone_leak_search()
            elif choice == "45":
                clear()
                aes_encrypt()
            elif choice == "46":
                clear()
                aes_decrypt()
            elif choice == "47":
                clear()
                email_intelligence_check()
            elif choice == "48":
                clear()
                scrape_website_contacts()
            elif choice == "49":
                clear()
                reddit_user_info()
            elif choice == "50":
                fetch_tiktok_data()
            elif choice == "51":
                clear()
                phone_number = Write.Input("[?] > Enter the phone number to search: ", default_color, 
            interval=0).strip()
                if not phone_number:
                     Write.Print("[!] > No phone number provided.\n", Colors.red, interval=0)
                else:
                    truecaller_search(phone_number)
            elif choice == "52":
                clear()
                first_name = Write.Input("[?] > Enter first name: ", Colors.white, interval=0).strip()
                last_name = Write.Input("[?] > Enter last name: ", Colors.white, interval=0).strip()
                zipcode = Write.Input("[?] > Enter ZIP code: ", Colors.white, interval=0).strip()
                search_sex_offender(first_name, last_name, zipcode)
            elif choice == "53":
                clear()
                phone_number = Write.Input("[?] > Enter the phone number to validate (1-000-0000): ", Colors.white, 
            interval=0).strip()
                if not phone_number:
                    Write.Print("[!] No phone number provided.", Colors.red, interval=0)
                    restart()
                else:
                    validate_whatsapp_number(phone_number)
            elif choice == "54":
                    skip_trace_search()
            elif choice == "55":
                    skip_trace_search_by_id()
            elif choice == "56":
                clear()
                mmsi = Write.Input("[?] > Enter the MMSI for ship lookup: ", default_color, interval=0).strip()
                if not mmsi:
                    clear()
                    Write.Print("[!] > Please enter an MMSI number.\n", default_color, interval=0)
                    continue
                ship_info(mmsi)
            elif choice == "57":
                clear()
                latitude = Write.Input("[?] > Enter latitude: ", default_color, interval=0).strip()
                longitude = Write.Input("[?] > Enter longitude: ", default_color, interval=0).strip()
                radius = Write.Input("[?] > Enter search radius: ", default_color, interval=0).strip()
                if not latitude or not longitude or not radius:
                    clear()
                    Write.Print("[!] > Please enter all required parameters (latitude, longitude, and radius).\n", default_color, interval=0)
                    continue
                ship_radius(latitude, longitude, radius)
            elif choice == "58":
                clear()
                lat = Write.Input("[?] > Enter latitude: ", default_color, interval=0).strip()
                lon = Write.Input("[?] > Enter longitude: ", default_color, interval=0).strip()
                range_value = Write.Input("[?] > Enter search range: ", default_color, interval=0).strip()
                if not lat or not lon or not range_value:
                    clear()
                    Write.Print("[!] > Please enter all required parameters (latitude, longitude, and range).\n", default_color, interval=0)
                    continue
                aircraft_live_range(lat, lon, range_value)
            elif choice == "59":
                clear()
                callsign = Write.Input("[?] > Enter aircraft callsign: ", default_color, interval=0).strip()
                if not callsign:
                    clear()
                    Write.Print("[!] > Please enter a callsign.\n", default_color, interval=0)
                    continue
                aircraft_live_callsign(callsign)
            elif choice == "60":
                predicta_search()
            elif choice == "61":
                validate_credit_card()
            elif choice == "62":
                clear()
                domain = Write.Input("[?] > Enter the domain to validate: ", default_color, interval=0).strip()
                if not domain:
                    clear()
                    Write.Print("[!] > Enter the domain\n", default_color, interval=0)
                    continue
                email_domain_validation(domain)
            elif choice == "63":
                clear()
                find_criminal_records()
            elif choice == "64":
                clear()
                generate_identity()
            elif choice == "65":
                clear()
                virtual_phone_numbers_detector()
            elif choice == "66":
                clear()
                exerra_phishing_check()
            elif choice == "67":
                clear()
                mac_address_lookup()
            elif choice == "99":
                clear()
                settings()
            elif choice == "0":
                clear()
                Write.Print("[!] > Exiting ClatScope Info Tool.\n", Colors.white, interval=0)
                break
            else:
                clear()
                Write.Print("[!] > Invalid input. Please try again.\n", Colors.white, interval=0)
        except KeyboardInterrupt:
            clear()
            Write.Print("[!] > Exiting on user request...\n", Colors.white, interval=0)
            break

if __name__ == "__main__":
    main()