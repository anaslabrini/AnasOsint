# tools/ip_lookup.py

import os
import socket
import requests
from utils import output_manager

def lookup(ip_address, save=False):
    """
    Master lookup for an IP address.
    - save: if True, writes all output to a per-IP report file.
    """
    # Prepare report file
    safe_ip = ip_address.replace(".", "_")
    report_dir = "reports"
    os.makedirs(report_dir, exist_ok=True)
    report_path = os.path.join(report_dir, f"{safe_ip}_ip_report.txt")
    output_manager.set_report(save=save, path=report_path)

    output_manager.info(f"Starting lookup for IP address: {ip_address}")

    # Ask for advanced scan
    advanced = input("[?] Do you want to perform an advanced lookup? (y/n): ").strip().lower() == "y"
    if advanced:
        # Collect API keys for many sources (>20)
        ipinfo_token      = input("[?] Enter your ipinfo.io API Token: ").strip()
        shodan_key        = input("[?] Enter your Shodan API Key: ").strip()
        abuseipdb_key     = input("[?] Enter your AbuseIPDB API Key: ").strip()
        virustotal_key    = input("[?] Enter your VirusTotal API Key: ").strip()
        censys_id         = input("[?] Enter your Censys API ID: ").strip()
        censys_secret     = input("[?] Enter your Censys API Secret: ").strip()
        greynoise_key     = input("[?] Enter your GreyNoise API Key: ").strip()
        threatcrowd_key   = input("[?] Enter your ThreatCrowd API Key: ").strip()
        urlscan_key       = input("[?] Enter your URLScan.io API Key: ").strip()
        passivetotal_user = input("[?] Enter PassiveTotal Username: ").strip()
        passivetotal_key  = input("[?] Enter PassiveTotal API Key: ").strip()
        securitytrails_key= input("[?] Enter SecurityTrails API Key: ").strip()
        dnsdb_key         = input("[?] Enter DNSDB API Key: ").strip()
        viewdns_key       = input("[?] Enter ViewDNS.info API Key: ").strip()
        alienvault_key    = input("[?] Enter AlienVault OTX API Key: ").strip()
        binaryedge_key    = input("[?] Enter BinaryEdge API Key: ").strip()
        ipquality_key     = input("[?] Enter IPQualityScore API Key: ").strip()
        phishing_key      = input("[?] Enter PhishTank API Key: ").strip()
        spamhaus_email    = input("[?] Enter Spamhaus Email (for DNSBL): ").strip()
        # …add more keys as needed…
    else:
        output_manager.warning("Skipping advanced lookup. Only basic checks will run.")

    # --- BASIC CHECKS ---
    basic_reverse_dns(ip_address)
    basic_icmp_ping(ip_address)
    basic_ipinfo(ip_address)

    # --- ADVANCED CHECKS ---
    if advanced:
        check_ipinfo(ip_address, ipinfo_token)
        check_shodan(ip_address, shodan_key)
        check_abuseipdb(ip_address, abuseipdb_key)
        check_virustotal(ip_address, virustotal_key)
        check_censys(ip_address, censys_id, censys_secret)
        check_greynoise(ip_address, greynoise_key)
        check_threatcrowd(ip_address, threatcrowd_key)
        check_urlscan(ip_address, urlscan_key)
        check_passivetotal(ip_address, passivetotal_user, passivetotal_key)
        check_securitytrails(ip_address, securitytrails_key)
        check_dnsdb(ip_address, dnsdb_key)
        check_viewdns(ip_address, viewdns_key)
        check_alienvault(ip_address, alienvault_key)
        check_binaryedge(ip_address, binaryedge_key)
        check_ipquality(ip_address, ipquality_key)
        check_phishtank(ip_address, phishing_key)
        check_spamhaus(ip_address, spamhaus_email)
        # …call additional check_*() as needed…

    output_manager.success(
        f"IP lookup completed. {'Report saved to '+report_path if save else 'Not saved.'}"
    )


# --- BASIC FUNCTIONS ---

def basic_reverse_dns(ip):
    output_manager.info("Performing reverse DNS lookup...")
    try:
        host = socket.gethostbyaddr(ip)[0]
        output_manager.success(f"Reverse DNS: {host}")
    except Exception:
        output_manager.warning("Reverse DNS lookup failed or no PTR record.")

def basic_icmp_ping(ip):
    output_manager.info("Pinging IP (ICMP)…")
    # Note: actual ICMP might require raw socket privileges; simulate via requests to http://ip/
    try:
        r = requests.get(f"http://{ip}", timeout=3)
        output_manager.success(f"Ping HTTP status: {r.status_code}")
    except Exception:
        output_manager.warning("HTTP ping failed (ICMP may require root privileges).")

def basic_ipinfo(ip):
    output_manager.info("Fetching basic ipinfo.io data (no token)…")
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json")
        data = r.json()
        output_manager.success("ipinfo.io Basic Info:")
        for k in ("ip","city","region","country","org"):
            output_manager.info(f"{k.title()}: {data.get(k)}")
    except Exception as e:
        output_manager.error(f"Basic ipinfo.io failed: {e}")


# --- ADVANCED FUNCTIONS ---

def check_ipinfo(ip, token):
    output_manager.info("Querying ipinfo.io (advanced)…")
    try:
        url = f"https://ipinfo.io/{ip}/json" + (f"?token={token}" if token else "")
        data = requests.get(url).json()
        output_manager.success("ipinfo.io Detailed Info:")
        for k in ("ip","hostname","city","region","country","loc","org","postal","timezone"):
            output_manager.info(f"{k.title()}: {data.get(k)}")
    except Exception as e:
        output_manager.error(f"Advanced ipinfo.io failed: {e}")

def check_shodan(ip, key):
    output_manager.info("Querying Shodan for host info…")
    try:
        r = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={key}")
        data = r.json()
        output_manager.success("Shodan Host Data:")
        output_manager.info(f"OS: {data.get('os')}")
        output_manager.info(f"Open Ports: {data.get('ports')}")
    except Exception as e:
        output_manager.error(f"Shodan lookup failed: {e}")

def check_abuseipdb(ip, key):
    output_manager.info("Querying AbuseIPDB for malicious reports…")
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": key, "Accept": "application/json"}
        )
        d = r.json()["data"]
        output_manager.success(f"AbuseIPDB Confidence: {d.get('abuseConfidenceScore')}")
    except Exception as e:
        output_manager.error(f"AbuseIPDB failed: {e}")

def check_virustotal(ip, key):
    output_manager.info("Querying VirusTotal for IP reputation…")
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                         headers={"x-apikey": key})
        stats = r.json().get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
        output_manager.success(f"VirusTotal analysis stats: {stats}")
    except Exception as e:
        output_manager.error(f"VirusTotal lookup failed: {e}")

def check_censys(ip, cid, secret):
    output_manager.info("Querying Censys for IP…")
    try:
        r = requests.post("https://search.censys.io/api/v2/hosts/search",
                          auth=(cid, secret),
                          json={"q": ip, "per_page": 5})
        hits = r.json().get("result",{}).get("total",0)
        output_manager.success(f"Censys found {hits} result(s)")
    except Exception as e:
        output_manager.error(f"Censys lookup failed: {e}")

def check_greynoise(ip, key):
    output_manager.info("Querying GreyNoise…")
    try:
        r = requests.get(f"https://api.greynoise.io/v3/community/{ip}",
                         headers={"key": key})
        output_manager.success(f"GreyNoise classification: {r.json().get('classification')}")
    except Exception as e:
        output_manager.error(f"GreyNoise lookup failed: {e}")

def check_threatcrowd(ip, key):
    output_manager.info("Querying ThreatCrowd…")
    try:
        r = requests.get(f"https://www.threatcrowd.org/searchApi/v2/ip/report/?ip={ip}")
        subs = r.json().get("resolutions", [])
        output_manager.success(f"ThreatCrowd found {len(subs)} resolution(s)")
    except Exception as e:
        output_manager.error(f"ThreatCrowd lookup failed: {e}")

def check_urlscan(ip, key):
    output_manager.info("Querying URLScan.io…")
    try:
        r = requests.get("https://urlscan.io/api/v1/search/",
                         params={"q": ip}, headers={"API-Key": key})
        hits = r.json().get("results", [])
        output_manager.success(f"URLScan results: {len(hits)}")
    except Exception as e:
        output_manager.error(f"URLScan lookup failed: {e}")

def check_passivetotal(ip, user, key):
    output_manager.info("Querying PassiveTotal…")
    try:
        r = requests.get("https://api.passivetotal.org/v2/host/report",
                         auth=(user, key), params={"query": ip})
        subs = r.json().get("subdomains", [])
        output_manager.success(f"PassiveTotal found {len(subs)} subdomain(s)")
    except Exception as e:
        output_manager.error(f"PassiveTotal lookup failed: {e}")

def check_securitytrails(ip, key):
    output_manager.info("Querying SecurityTrails…")
    try:
        r = requests.get(f"https://api.securitytrails.com/v1/host/{ip}/whois",
                         headers={"APIKEY": key})
        data = r.json()
        output_manager.success(f"SecurityTrails WHOIS parsed")
    except Exception as e:
        output_manager.error(f"SecurityTrails lookup failed: {e}")

def check_dnsdb(ip, key):
    output_manager.info("Querying DNSDB…")
    try:
        r = requests.get(f"https://api.dnsdb.info/lookup/rrset/ip/{ip}",
                         headers={"X-API-Key": key})
        records = r.json()
        output_manager.success(f"DNSDB returned {len(records)} RRsets")
    except Exception as e:
        output_manager.error(f"DNSDB lookup failed: {e}")

def check_viewdns(ip, key):
    output_manager.info("Querying ViewDNS.info…")
    try:
        r = requests.get("https://api.viewdns.info/reverseip/",
                         params={"apikey": key, "host": ip, "output": "json"})
        recs = r.json().get("response",{}).get("records",[])
        output_manager.success(f"ViewDNS returned {len(recs)} record(s)")
    except Exception as e:
        output_manager.error(f"ViewDNS lookup failed: {e}")

def check_alienvault(ip, key):
    output_manager.info("Querying AlienVault OTX…")
    try:
        r = requests.get(f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                         headers={"X-OTX-API-KEY": key})
        data = r.json()
        output_manager.success(f"OTX pulse count: {len(data.get('pulse_info',{}).get('pulses',[]))}")
    except Exception as e:
        output_manager.error(f"AlienVault lookup failed: {e}")

def check_binaryedge(ip, key):
    output_manager.info("Querying BinaryEdge…")
    try:
        r = requests.get(f"https://api.binaryedge.io/v2/query/ip/{ip}",
                         headers={"X-Key": key})
        output_manager.success(f"BinaryEdge data keys: {list(r.json().keys())}")
    except Exception as e:
        output_manager.error(f"BinaryEdge lookup failed: {e}")

def check_ipquality(ip, key):
    output_manager.info("Querying IPQualityScore…")
    try:
        r = requests.get(f"https://ipqualityscore.com/api/json/ip/{key}/{ip}")
        output_manager.success(f"IPQualityScore fraud score: {r.json().get('fraud_score')}")
    except Exception as e:
        output_manager.error(f"IPQualityScore lookup failed: {e}")

def check_phishtank(ip, key):
    output_manager.info("Querying PhishTank…")
    try:
        r = requests.get("https://checkurl.phishtank.com/checkurl/",
                         params={"url": ip, "format": "json", "app_key": key})
        output_manager.success(f"PhishTank valid: {r.json().get('valid')}")
    except Exception as e:
        output_manager.error(f"PhishTank lookup failed: {e}")

def check_spamhaus(ip, email):
    output_manager.info("Querying Spamhaus DNSBL…")
    try:
        rev = ".".join(reversed(ip.split(".")))
        for zone in ["zen.spamhaus.org", "dbl.spamhaus.org"]:
            resp = socket.gethostbyname_ex(f"{rev}.{zone}")
            output_manager.success(f"Listed in {zone}: {resp[2]}")
    except Exception:
        output_manager.warning("Not listed in Spamhaus DNSBL.")

# Add more check functions as needed…
