# tools/email_lookup.py

import os
import requests
import hashlib
import dns.resolver
from utils import output_manager

def lookup(email, save=False):
    """
    Master lookup for an email address.
    - save: if True, writes all output to a per-email report file.
    """
    # Prepare report file
    safe_email = email.replace("@", "_at_").replace(".", "_")
    report_dir = "reports"
    os.makedirs(report_dir, exist_ok=True)
    report_path = os.path.join(report_dir, f"{safe_email}_email_report.txt")
    output_manager.set_report(save=save, path=report_path)

    output_manager.info(f"Starting lookup for email: {email}")

    # Ask for advanced scan
    advanced = input("[?] Do you want to perform an advanced lookup? (y/n): ").strip().lower() == "y"
    if advanced:
        # Gather all required API keys
        hibp_key         = input("[?] Enter your HaveIBeenPwned API Key: ").strip()
        hunter_key       = input("[?] Enter your Hunter.io API Key: ").strip()
        emailrep_key     = input("[?] Enter your EmailRep.io API Key: ").strip()
        leakcheck_key    = input("[?] Enter your LeakCheck API Key: ").strip()
        mailboxlayer_key = input("[?] Enter your MailboxLayer API Key: ").strip()
        emailhippo_key   = input("[?] Enter your EmailHippo API Key: ").strip()
        intelx_key       = input("[?] Enter your IntelligenceX API Key: ").strip()
        hacked_key       = input("[?] Enter your Hacked-Emails DB API Key: ").strip()
        pgp_key          = input("[?] Enter your PGP Keyserver API Key: ").strip()
        # Add more as needed to exceed 20 sources...
    else:
        output_manager.warning("Skipping advanced lookup. Only basic checks will run.")

    # --- BASIC CHECKS ---
    check_gravatar(email)
    search_google_dorks(email)
    check_mx_records(email)

    # --- ADVANCED CHECKS ---
    if advanced:
        check_hibp(email, hibp_key)
        check_hunter(hunter_key, email)
        check_emailrep(email, emailrep_key)
        check_leakcheck(email, leakcheck_key)
        check_mailboxlayer(email, mailboxlayer_key)
        check_emailhippo(email, emailhippo_key)
        check_intelx(email, intelx_key, email)
        check_hacked_emails(email, hacked_key)
        check_pgp_keys(email, pgp_key)
        check_social_media_mentions(email)
        check_linkedin_dork(email)
        check_pastebin_dork(email)
        # …add additional 5+ API or OSINT sources here…
    
    output_manager.success(f"Email lookup completed. Report {'saved to '+report_path if save else 'not saved'}.")

# --- BASIC FUNCTIONS ---

def check_gravatar(email):
    output_manager.info("Checking Gravatar profile...")
    try:
        h = hashlib.md5(email.lower().encode()).hexdigest()
        url = f"https://www.gravatar.com/avatar/{h}?d=404"
        r = requests.get(url)
        if r.status_code == 200:
            output_manager.success(f"Gravatar profile exists: {url}")
        else:
            output_manager.warning("No Gravatar profile found.")
    except Exception as e:
        output_manager.error(f"Gravatar check failed: {e}")

def search_google_dorks(email):
    output_manager.info("Generating Google Dorks...")
    try:
        dorks = [
            f'"{email}"',
            f'"{email}" filetype:pdf',
            f'"{email}" site:linkedin.com',
            f'"{email}" site:pastebin.com',
            f'"{email}" site:github.com',
            f'"{email}" site:twitter.com',
        ]
        for d in dorks:
            output_manager.info(f"Google Dork: https://www.google.com/search?q={d.replace(' ', '+')}")
    except Exception as e:
        output_manager.error(f"Google Dorks generation failed: {e}")

def check_mx_records(email):
    domain = email.split("@")[-1]
    output_manager.info(f"Looking up MX records for {domain}...")
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        output_manager.success("MX Records:")
        for r in answers:
            output_manager.info(f" - {r.exchange} (priority {r.preference})")
    except Exception:
        output_manager.warning("No MX records found or DNS error.")

# --- ADVANCED FUNCTIONS ---

def check_hibp(email, api_key):
    output_manager.info("Checking HaveIBeenPwned for breaches...")
    headers = {"hibp-api-key": api_key, "user-agent": "anas-osint-tool"}
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
    try:
        r = requests.get(url, headers=headers)
        if r.status_code == 200:
            breaches = r.json()
            output_manager.success(f"{len(breaches)} breach(es) found:")
            for b in breaches:
                output_manager.info(f" - {b['Name']} on {b['BreachDate']}")
        elif r.status_code == 404:
            output_manager.success("No breaches found.")
        else:
            output_manager.error(f"HIBP API error: {r.status_code}")
    except Exception as e:
        output_manager.error(f"HIBP lookup failed: {e}")

def check_hunter(api_key, email):
    output_manager.info("Checking Hunter.io for email sources...")
    url = f"https://api.hunter.io/v2/email-finder?api_key={api_key}&email={email}"
    try:
        r = requests.get(url)
        data = r.json().get("data", {})
        sources = data.get("sources", [])
        output_manager.success(f"Hunter.io found {len(sources)} source(s)")
        for s in sources:
            output_manager.info(f" - {s['domain']} via {s['uri']}")
    except Exception as e:
        output_manager.error(f"Hunter.io lookup failed: {e}")

def check_emailrep(email, api_key):
    output_manager.info("Checking EmailRep.io for reputation...")
    url = f"https://emailrep.io/{email}"
    headers = {"Key": api_key}
    try:
        r = requests.get(url, headers=headers).json()
        rep = r.get("reputation", "unknown")
        cats = r.get("details", {}).get("categories", [])
        output_manager.success(f"EmailRep reputation: {rep}")
        output_manager.info(f"Categories: {', '.join(cats)}")
    except Exception as e:
        output_manager.error(f"EmailRep.io lookup failed: {e}")

def check_leakcheck(email, api_key):
    output_manager.info("Checking LeakCheck for password leaks...")
    url = f"https://api.leakcheck.net/?email={email}&key={api_key}"
    try:
        r = requests.get(url).json()
        count = r.get("leaks_count", 0)
        output_manager.success(f"LeakCheck found {count} leak(s)")
    except Exception as e:
        output_manager.error(f"LeakCheck lookup failed: {e}")

def check_mailboxlayer(email, api_key):
    output_manager.info("Verifying email with MailboxLayer...")
    url = f"http://apilayer.net/api/check?access_key={api_key}&email={email}"
    try:
        r = requests.get(url).json()
        valid = r.get("format_valid", False) and r.get("smtp_check", False)
        output_manager.success(f"MailboxLayer valid: {valid}")
    except Exception as e:
        output_manager.error(f"MailboxLayer lookup failed: {e}")

def check_emailhippo(email, api_key):
    output_manager.info("Checking EmailHippo for advanced verification...")
    url = f"https://emailhippo.example.com/verify?key={api_key}&email={email}"
    try:
        r = requests.get(url).json()
        output_manager.success(f"EmailHippo status: {r.get('status', 'unknown')}")
    except Exception as e:
        output_manager.error(f"EmailHippo lookup failed: {e}")

def check_intelx(email, api_key, query):
    output_manager.info("Searching IntelligenceX for mentions...")
    url = f"https://api.intelx.io/intelx/search?key={api_key}&q={query}"
    try:
        r = requests.get(url).json()
        hits = r.get("hits", 0)
        output_manager.success(f"IntelligenceX hits: {hits}")
    except Exception as e:
        output_manager.error(f"IntelligenceX lookup failed: {e}")

def check_hacked_emails(email, api_key):
    output_manager.info("Checking Hacked-Emails DB...")
    url = f"https://hacked-emails.com/api?q={email}&key={api_key}"
    try:
        r = requests.get(url).json()
        found = r.get("found", False)
        output_manager.success(f"Hacked-Emails found: {found}")
    except Exception as e:
        output_manager.error(f"Hacked-Emails lookup failed: {e}")

def check_pgp_keys(email, api_key):
    output_manager.info("Searching PGP Keyservers...")
    url = f"https://api.keyserver.ubuntu.com/pks/lookup?op=vindex&options=mr&search={email}"
    try:
        r = requests.get(url)
        count = r.text.count("pub")
        output_manager.success(f"PGP keys found: {count}")
    except Exception as e:
        output_manager.error(f"PGP lookup failed: {e}")

def check_social_media_mentions(email):
    output_manager.info("Searching for social media mentions...")
    platforms = ["facebook.com", "twitter.com", "instagram.com", "linkedin.com"]
    for site in platforms:
        d = f'"{email}" site:{site}'
        output_manager.info(f"Social Dork: https://www.google.com/search?q={d.replace(' ', '+')}")

def check_linkedin_dork(email):
    output_manager.info("Generating LinkedIn Dork...")
    d = f'"{email}" site:linkedin.com/in'
    output_manager.info(f"LinkedIn Dork: https://www.google.com/search?q={d.replace(' ', '+')}")

def check_pastebin_dork(email):
    output_manager.info("Generating Pastebin Dork...")
    d = f'"{email}" site:pastebin.com'
    output_manager.info(f"Pastebin Dork: https://www.google.com/search?q={d.replace(' ', '+')}")
