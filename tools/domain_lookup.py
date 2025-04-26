# tools/domain_lookup.py

import os
import json
import requests
import whois
import dns.resolver
from utils import output_manager

def lookup(domain, save=False):
    """
    Master lookup for a domain.
    - save: if True, writes all output to a per-domain report file.
    """
    # Prepare report file
    safe_dom = domain.replace(".", "_")
    report_dir = "reports"
    os.makedirs(report_dir, exist_ok=True)
    report_path = os.path.join(report_dir, f"{safe_dom}_domain_report.txt")
    output_manager.set_report(save=save, path=report_path)

    output_manager.info(f"Starting lookup for domain: {domain}")

    # Ask advanced
    advanced = input("[?] Do you want to perform an advanced lookup? (y/n): ").strip().lower() == "y"
    if advanced:
        # Gather API keys for 20+ services
        st_key    = input("[?] Enter SecurityTrails API Key: ").strip()
        vt_key    = input("[?] Enter VirusTotal API Key: ").strip()
        cz_id     = input("[?] Enter Censys API ID: ").strip()
        cz_secret = input("[?] Enter Censys API Secret: ").strip()
        sh_key    = input("[?] Enter Shodan API Key: ").strip()
        tc_key    = input("[?] Enter ThreatCrowd API Key: ").strip()
        us_key    = input("[?] Enter URLScan.io API Key: ").strip()
        pt_user   = input("[?] Enter PassiveTotal Username: ").strip()
        pt_key    = input("[?] Enter PassiveTotal API Key: ").strip()
        db_token  = input("[?] Enter DNSDB API Token: ").strip()
        vt_user   = input("[?] Enter ViewDNS.info API Key: ").strip()
        bv_key    = input("[?] Enter BuiltWith API Key: ").strip()
        dt_key    = input("[?] Enter DomainTools API Key: ").strip()
        av_key    = input("[?] Enter AlienVault OTX API Key: ").strip()
        sp_key    = input("[?] Enter Spyse API Key: ").strip()
        nc_key    = input("[?] Enter Netcraft API Key: ").strip()
        bf_key    = input("[?] Enter Brandfetch API Key: ").strip()
        rh_key    = input("[?] Enter RiskIQ PassiveTotal Key: ").strip()
        ih_location = input("[?] Enter IntelligenceX API Key: ").strip()
        ahd_key   = input("[?] Enter Hacked-Emails DB API Key: ").strip()
        # add more as needed…
    else:
        output_manager.warning("Skipping advanced lookup. Only basic checks will run.")

    # Basic checks
    basic_whois(domain)
    basic_dns(domain)
    basic_crt_sh(domain)

    # Advanced checks
    if advanced:
        check_securitytrails(domain, st_key)
        check_virustotal(domain, vt_key)
        check_censys(domain, cz_id, cz_secret)
        check_shodan_domain(domain, sh_key)
        check_threatcrowd(domain, tc_key)
        check_urlscan(domain, us_key)
        check_passivetotal(domain, pt_user, pt_key)
        check_dnsdb(domain, db_token)
        check_viewdns(domain, vt_user)
        check_builtwith(domain, bv_key)
        check_domaintools(domain, dt_key)
        check_alienvault(domain, av_key)
        check_spyse(domain, sp_key)
        check_netcraft(domain, nc_key)
        check_brandfetch(domain, bf_key)
        check_riskiq(domain, rh_key)
        check_intelx(domain, ih_location)
        check_hacked_emails_db(domain, ahd_key)

    output_manager.success(f"Domain lookup completed. {'Report saved to '+report_path if save else 'Not saved.'}")


# --- BASIC FUNCTIONS ---

def basic_whois(domain):
    output_manager.info("Performing WHOIS lookup...")
    try:
        info = whois.whois(domain)
        fields = ["registrar", "creation_date", "expiration_date", "name_servers", "emails"]
        output_manager.success("WHOIS Data:")
        for f in fields:
            output_manager.info(f"{f.title().replace('_',' ')}: {info.get(f)}")
    except Exception as e:
        output_manager.error(f"WHOIS lookup failed: {e}")

def basic_dns(domain):
    output_manager.info("Fetching DNS records...")
    try:
        for rt in ["A","AAAA","MX","TXT","NS","CNAME"]:
            try:
                answers = dns.resolver.resolve(domain, rt)
                output_manager.success(f"{rt} Records:")
                for a in answers:
                    output_manager.info(str(a))
            except Exception:
                output_manager.warning(f"No {rt} records found.")
    except Exception as e:
        output_manager.error(f"DNS enumeration failed: {e}")

def basic_crt_sh(domain):
    output_manager.info("Enumerating subdomains via crt.sh...")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        r = requests.get(url, timeout=15)
        subs = {s for entry in r.json() if (name:=entry.get("name_value")) for s in name.split("\n") if domain in s}
        if subs:
            output_manager.success(f"Found {len(subs)} subdomain(s):")
            for s in sorted(subs):
                output_manager.info(s)
        else:
            output_manager.warning("No subdomains found.")
    except Exception as e:
        output_manager.error(f"crt.sh enumeration failed: {e}")


# --- ADVANCED FUNCTIONS ---

def check_securitytrails(domain, key):
    output_manager.info("Checking SecurityTrails...")
    try:
        r = requests.get(f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
                         headers={"APIKEY": key})
        subs = r.json().get("subdomains", [])
        output_manager.success(f"SecurityTrails found {len(subs)} subdomain(s)")
    except Exception as e:
        output_manager.error(f"SecurityTrails lookup failed: {e}")

def check_virustotal(domain, key):
    output_manager.info("Querying VirusTotal domain info...")
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}",
                         headers={"x-apikey": key})
        data = r.json().get("data", {})
        stats = data.get("attributes", {}).get("last_analysis_stats", {})
        output_manager.success(f"VT Analysis stats: {stats}")
    except Exception as e:
        output_manager.error(f"VirusTotal lookup failed: {e}")

def check_censys(domain, cid, secret):
    output_manager.info("Querying Censys for TLS certificates...")
    try:
        r = requests.post("https://search.censys.io/api/v2/certificates/search",
                          auth=(cid, secret),
                          json={"q": domain, "per_page": 5})
        hits = r.json().get("result", {}).get("total", 0)
        output_manager.success(f"Censys found {hits} cert(s)")
    except Exception as e:
        output_manager.error(f"Censys lookup failed: {e}")

def check_shodan_domain(domain, key):
    output_manager.info("Checking Shodan for domain data...")
    try:
        r = requests.get(f"https://api.shodan.io/dns/domain/{domain}?key={key}")
        ips = r.json().get("data", [])
        output_manager.success(f"Shodan returned {len(ips)} DNS entries")
    except Exception as e:
        output_manager.error(f"Shodan domain lookup failed: {e}")

def check_threatcrowd(domain, key):
    output_manager.info("Querying ThreatCrowd...")
    try:
        r = requests.get(f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}")
        occ = r.json().get("subdomains", [])
        output_manager.success(f"ThreatCrowd found {len(occ)} subdomain(s)")
    except Exception as e:
        output_manager.error(f"ThreatCrowd lookup failed: {e}")

def check_urlscan(domain, key):
    output_manager.info("Checking URLScan.io...")
    try:
        r = requests.get("https://urlscan.io/api/v1/search/",
                         params={"q": f"domain:{domain}"}, headers={"API-Key": key})
        results = r.json().get("results", [])
        output_manager.success(f"URLScan returned {len(results)} result(s)")
    except Exception as e:
        output_manager.error(f"URLScan lookup failed: {e}")

def check_passivetotal(domain, user, key):
    output_manager.info("Querying PassiveTotal...")
    try:
        r = requests.get("https://api.passivetotal.org/v2/dns/passive",
                         auth=(user, key), params={"query": domain})
        subs = r.json().get("subdomains", [])
        output_manager.success(f"PassiveTotal found {len(subs)} subdomain(s)")
    except Exception as e:
        output_manager.error(f"PassiveTotal lookup failed: {e}")

def check_dnsdb(domain, token):
    output_manager.info("Checking DNSDB...")
    try:
        r = requests.get(f"https://api.dnsdb.info/lookup/rrset/name/{domain}",
                         headers={"X-API-Key": token})
        records = r.json()
        output_manager.success(f"DNSDB returned {len(records)} RRsets")
    except Exception as e:
        output_manager.error(f"DNSDB lookup failed: {e}")

def check_viewdns(domain, key):
    output_manager.info("Querying ViewDNS.info...")
    try:
        r = requests.get("https://api.viewdns.info/reversedns/",
                         params={"apikey": key, "domain": domain, "output": "json"})
        rev = r.json().get("response", {}).get("records", [])
        output_manager.success(f"ViewDNS returned {len(rev)} record(s)")
    except Exception as e:
        output_manager.error(f"ViewDNS lookup failed: {e}")

def check_builtwith(domain, key):
    output_manager.info("Checking BuiltWith...")
    try:
        r = requests.get(f"https://api.builtwith.com/v19/api.json?KEY={key}&LOOKUP={domain}")
        data = r.json()
        output_manager.success(f"BuiltWith categories: {list(data.keys())[:5]}")
    except Exception as e:
        output_manager.error(f"BuiltWith lookup failed: {e}")

def check_domaintools(domain, key):
    output_manager.info("Querying DomainTools...")
    try:
        r = requests.get(f"https://api.domaintools.com/v1/{domain}/whois.json?api_username={key}")
        info = r.json().get("response", {})
        output_manager.success(f"DomainTools registrar: {info.get('registrar_name')}")
    except Exception as e:
        output_manager.error(f"DomainTools lookup failed: {e}")

def check_alienvault(domain, key):
    output_manager.info("Checking AlienVault OTX...")
    try:
        r = requests.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
                         headers={"X-OTX-API-KEY": key})
        pdns = r.json().get("passive_dns", [])
        output_manager.success(f"AlienVault returned {len(pdns)} passive DNS records")
    except Exception as e:
        output_manager.error(f"AlienVault lookup failed: {e}")

def check_spyse(domain, key):
    output_manager.info("Checking Spyse...")
    try:
        r = requests.get(f"https://api.spyse.com/v4/data/domain/subdomains?domain={domain}",
                         headers={"Authorization": f"Bearer {key}"})
        subs = r.json().get("data", {}).get("subdomains", [])
        output_manager.success(f"Spyse found {len(subs)} subdomain(s)")
    except Exception as e:
        output_manager.error(f"Spyse lookup failed: {e}")

def check_netcraft(domain, key):
    output_manager.info("Querying Netcraft...")
    try:
        r = requests.get(f"https://api.netcraft.com/api/v1/sites/{domain}",
                         headers={"API-Key": key})
        data = r.json()
        output_manager.success(f"Netcraft status: {data.get('risk_rating')}")
    except Exception as e:
        output_manager.error(f"Netcraft lookup failed: {e}")

def check_brandfetch(domain, key):
    output_manager.info("Checking Brandfetch...")
    try:
        r = requests.get(f"https://api.brandfetch.io/v2/brands/{domain}",
                         headers={"Authorization": f"Bearer {key}"})
        data = r.json()
        output_manager.success(f"Brandfetch found {len(data.get('links', []))} brand assets")
    except Exception as e:
        output_manager.error(f"Brandfetch lookup failed: {e}")

def check_riskiq(domain, key):
    output_manager.info("Checking RiskIQ PassiveTotal...")
    try:
        r = requests.get(f"https://api.riskiq.net/passthrough/domain/{domain}",
                         headers={"x-api-key": key})
        data = r.json()
        output_manager.success(f"RiskIQ data: {data.get('status')}")
    except Exception as e:
        output_manager.error(f"RiskIQ lookup failed: {e}")

def check_intelx(domain, key):
    output_manager.info("Querying IntelligenceX...")
    try:
        r = requests.get(f"https://api.intelx.io/intelx/search?query={domain}",
                         headers={"x-api-key": key})
        hits = r.json().get("hits", 0)
        output_manager.success(f"IntelligenceX hits: {hits}")
    except Exception as e:
        output_manager.error(f"IntelligenceX lookup failed: {e}")

def check_hacked_emails_db(domain, key):
    output_manager.info("Checking Hacked-Emails DB for domain leaks...")
    try:
        r = requests.get(f"https://hacked-emails.com/api?domain={domain}&key={key}")
        count = r.json().get("count", 0)
        output_manager.success(f"Hacked-Emails DB leaks: {count}")
    except Exception as e:
        output_manager.error(f"Hacked-Emails lookup failed: {e}")
