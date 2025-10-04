allowed_roles = [
    'admin',
    'analyst',
    'viewer'
]

TRACKED_ENDPOINTS = {
    "find_intel", 
    # "my_intel_search", 
    "wapiti_scan", 
    "port_scan", 
    "subdomain_search", 
    "company_profile",
    "wallet",
    # "wallet-history",
    # "nftwallet-history",
    "upload-file",
    "get_who_is",
    "get_username",
    "get_deep_account",
    "get_ip_info",
    "get_wayback",
    "get_ssl_info",
    "get_phone_info",
    "get_nrich",
    # "cpe_search",
}


TRACKED_ENDPOINTS_NAMES = {
    "cpe_search": {"name":"CPE Search", "page":"Vulnerability Intel"},
    "find_intel": {"name":"Target Analysis",
                   "page":"Threat Intel"
                },
    "my_intel_search":{"name": "Malware Search", "page":"Vulnerability Intel"}, 
    "wapiti_scan": {"name":"Web Application Vulnerability", "page": "Threat Intel"},
    "port_scan": {"name":"Port Scan", "page":"Threat Intel"},
    "subdomain_search":{"name":"Subdomain Search", "page":"Threat Intel"},
    "company_profile": {"name":"Generate Organization Profile", "page": "Threat Intel"},
    "wallet": {"name":"Web3 Wallet", "page":"Web3"},
    "wallet-history":{"name":"Wallet History", "page":"Web3"},
    "nftwallet-history":{"name":"Nft History", "page":"Web3"},
    "upload-file":{"name":"Scan File", "page":"Malware Analysis"},
    "get_who_is":{"name":"Who Is", "page":"WildCard Intel"},
    "get_username":{"name":"Username Search", "page":"WildCard Intel"},
    "get_deep_account":{"name":"Account Search", "page":"WildCard Intel"},
    "get_ip_info":{"name":"IP Info", "page":"WildCard Intel"},
    "get_wayback":{"name":"Domain Wayback", "page":"WildCard Intel"},
    "get_ssl_info":{"name":"SSL Info", "page":"WildCard Intel"},
    "get_phone_info": {"name":"Phone Info", "page":"WildCard Intel"},
    "get_nrich":{"name":"Scan For CVE", "page":"WildCard Intel"},
}


view_display_pairs = {
    'attack-surface-scan': 'Attack Surface Scan',
    'get_username': 'Username Scan',
    # 'get_ip_info': 'IP Intelligence Lookup',
    'get_deep_account': 'Deep Account Finder',
    'get_wayback': 'Wayback Machine Lookup',
    'get_ssl_info': 'SSL Certificate Info',
    'get_nrich': 'CVE Vulnerability Scan',
    'wallet': 'ETH Wallet Intelligence',
    # 'wallet-chain': 'Wallet Chain Viewer',
    'wallet-history': 'ETH Wallet History Lookup',
    'nftswallet-history': 'Wallet NFT History',
    # 'blockchain_details': 'Blockchain Details',
    # 'upload-file': 'Malware File Upload',
    # 'virusTotal_file': 'VirusTotal File Scan',
    # 'find_intel': 'Threat Intel Discovery',
    # 'my_intel_search': 'Saved Threat Searches',
    'wapiti_scan': 'Web App Vulnerability Scan',
    'port_scan': 'Port Scanner',
    'subdomain_search': 'Subdomain Finder',
    # 'full_subdomain_search': 'Full Subdomain Enumeration',
    'get_report': 'File Analysis',
    'find_intel_full_scan':'Full Threat Intel Scan'
}

COMMON_TCP_PORTS = [
    # Internet-facing services
    20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445, 465,
    512, 513, 514, 515, 993, 995, 1080, 1433, 1521, 1720, 1723, 2049, 2082, 2083,
    2086, 2087, 2222, 2375, 2376, 2480, 3306, 3389, 3690, 4000, 4369, 5000, 5432,
    5555, 5800, 5900, 5984, 5985, 5986, 6000, 6379, 6660, 6661, 6662, 6666, 7001,
    7070, 7474, 7777, 8000, 8008, 8080, 8081, 8222, 8443, 8500, 8600, 8888, 9000,
    9001, 9042, 9090, 9200, 9300, 9418, 9999, 10000, 11211, 27017,

    # Exploit/malware/backdoor ports
    31, 69, 1352, 1434, 2745, 3127, 4444, 5001, 5010, 5190, 5431, 5800, 5901,
    6001, 6667, 7000, 7212, 7877, 8880, 9898, 12345, 31337, 32764,

    # SCADA, ICS, IoT - often poorly secured
    102, 502, 1911, 1962, 20000, 47808,

    # Common web admin / webmail ports
    2095, 2096, 8181, 8282, 9091, 10050, 10051, 15672, 28017,

    # VoIP/SIP, SMB, RPC-related
    5060, 5061, 135, 139, 445, 2049, 135, 593, 1024, 1025, 1026, 1027,

    # Remote access / management
    3389, 5800, 5900, 22, 23, 3128, 50000, 49152, 49153, 49154, 49155,

    # Misc (HTTP variants, reverse shells, proxy ports)
    81, 88, 99, 8001, 8082, 8083, 8444, 8501, 8666, 8765, 9002, 9080, 9091,
    9100, 9111, 9998, 10001, 1234, 1337, 3000, 3001, 3128, 3131, 4001, 4443,
    4445, 4555, 4567, 5002, 5050, 5062, 5100, 5200, 5400, 5601, 5801, 5902,
    6001, 6100, 6200, 6400, 6500, 7002, 7200, 7400, 7600, 8009, 8085, 8180,
    8200, 8300, 8502, 8601, 8700, 8800, 8889, 8890, 9009, 9101, 9201, 9301,
    9400, 9500, 9600, 9700, 9800, 9900, 10010, 10020, 10100, 10200, 10300
]


role_based_views = {
    "admin": [
        "attack-surface-scan",
        "get_username",
        "get_deep_account",
        "get_wayback",
        "get_ssl_info",
        "get_nrich",
        "wallet",
        "wallet-history",
        "nftswallet-history",
        "wapiti_scan",
        "port_scan",
        "subdomain_search",
        "get_report",
        "find_intel_full_scan",
    ],
    "analyst": [
        "find_intel_full_scan",
        "get_username",
        "get_deep_account",
        "get_wayback",
        "get_ssl_info",
        "get_nrich",
        "wallet",
        "wallet-history",
        "nftswallet-history",
        "wapiti_scan",
        "port_scan",
        "subdomain_search",
        "get_report",
    ],
    "viewer": [
        "get_username",
        "get_deep_account",
        "get_wayback",
        "get_ssl_info",
        "wallet",
        "wallet-history",
        "nftswallet-history",
        "get_report",
    ]
}

COMPLIANCE_RULES = {
    "phone_number": ["GDPR Article 5", "India PDPB - Personal data handling"],
    "email": ["GDPR Article 5", "ISO27001 A.9.2"],
    "name": ["GDPR Article 5"],
    "region": ["GDPR Article 5"],
    "country": ["GDPR Article 5"],
    "ip_address": ["GDPR Article 5", "ISO27001 A.12.4.1"],
    "os_version": ["ISO27001 A.12.4.1", "NIST 800-53 AU-2"],
    "installed_packages": ["ISO27001 A.12.4.1"],
    "config_files": ["ISO27001 A.12.4.1"],
    "credit_card": ["PCI-DSS 3.2.1", "PCI-DSS 8.2.3"],
    "bank_account": ["PCI-DSS 3.2.1"],
    "json_data": ["ISO27001 A.12.4.1", "NIST 800-53 AU-2"]
}