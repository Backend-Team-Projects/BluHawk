import requests
import random
from BluHawk.load_env import *
import sublist3r 

timeout = 180

API_KEY = AlienVault_API

def get_subdomains_alienv(domain, multi_source = False):
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    headers = {"X-OTX-API-KEY": API_KEY}

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        subdomains = {entry["hostname"] for entry in data.get("passive_dns", [])}
        
        if multi_source:
            subdomains2 = []
            try:
                subdomains2 = sublist3r.main(domain, 8, f"{domain}.txt", ports=None, silent= False, verbose=False, enable_bruteforce=False, engines=None) 
            except Exception as e:
                print(f"Error fetching subdomains with Sublist3r: {str(e)}")
                
            subdomains.update(subdomains2)

        domains = set({})

        for i in subdomains:
            if i.find(domain) != -1:
                domains.add(i)
        subdomains = domains
        return {"subdomains":subdomains, "status_code": "200"}
    else:
        print(f"Error: {response.status_code} - {response.text}")
        return {"subdomains":set(), "status_code": response.status_code}

def fetch_rapiddns(domain, mode = 'short'):

    status = 'error'
    
    try:
        # response = requests.get(url, headers=headers, timeout=timeout)
        response = get_subdomains_alienv(domain)
        subdomains = set()
        if response.get('status_code') == '200':
            status = 'success'
            subdomains = response['subdomains']
            # print(f"[+] Found {len(subdomains)} subdomains", '\n\n')
        else:
            # print(f"[-] Received unexpected status code {response.get('status_code')}")
            pass

        return {"data":sorted(subdomains), 'status': status}
    
    except Exception as e:
        # print(f"[-] Error fetching RapidDNS: {str(e)}")
        return {'data':{}, 'status': 'error'}

def fetch_subdomains_full(domain):
    return fetch_subdomains(domain, mode='full')

def fetch_subdomains(domain, **kwargs ):
    mode = 'short'
    subdomains = set()
    data = fetch_rapiddns(domain, mode)
    status = data.get('status', 'error')
    data = data.get('data', [])
    
    for i in data:
        subdomains.update(i.split("\n"))
    
    return {'data':list(subdomains), 'status': status}