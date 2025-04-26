# tools/phone_lookup.py

import os
import requests
from utils import output_manager

def lookup(phone_number, save=False):
    """
    Master lookup for a phone number.
    - save: if True, writes all output to a per-number report file.
    """
    # Prepare report file
    safe_phone = phone_number.replace("+", "").replace(" ", "").replace("-", "")
    report_dir = "reports"
    os.makedirs(report_dir, exist_ok=True)
    report_path = os.path.join(report_dir, f"{safe_phone}_phone_report.txt")
    output_manager.set_report(save=save, path=report_path)

    output_manager.info(f"Starting lookup for phone number: {phone_number}")

    # Ask for advanced scan
    advanced = input("[?] Do you want to perform an advanced lookup? (y/n): ").strip().lower() == "y"
    if advanced:
        # Gather API keys for multiple OSINT sources
        numverify_key    = input("[?] Enter your NumVerify API Key: ").strip()
        twilio_sid       = input("[?] Enter your Twilio Account SID: ").strip()
        twilio_token     = input("[?] Enter your Twilio Auth Token: ").strip()
        nexmo_key        = input("[?] Enter your Nexmo API Key: ").strip()
        nexmo_secret     = input("[?] Enter your Nexmo API Secret: ").strip()
        opencnam_key     = input("[?] Enter your OpenCNAM API Key: ").strip()
        truecaller_token = input("[?] Enter your Truecaller API Token: ").strip()
        pipl_key         = input("[?] Enter your Pipl API Key: ").strip()
        whitepages_key   = input("[?] Enter your Whitepages Pro API Key: ").strip()
        fullcontact_key  = input("[?] Enter your FullContact API Key: ").strip()
        numlookup_key    = input("[?] Enter your NumberAPI (numlookupapi.com) Key: ").strip()
        phoneformat_key  = input("[?] Enter your PhoneFormat.io API Key: ").strip()
        hlrlookup_key    = input("[?] Enter your HLR Lookup API Key: ").strip()
        infobel_key      = input("[?] Enter your Infobel API Key: ").strip()
        fraudcheck_key   = input("[?] Enter your FraudCheck API Key: ").strip()
        callerid_key     = input("[?] Enter your CallerID API Key: ").strip()
        # ...add more keys to exceed 20 sources as needed
    else:
        output_manager.warning("Skipping advanced lookup. Only basic checks will run.")

    # --- BASIC CHECKS ---
    check_numverify_basic(phone_number)
    search_social_media(phone_number)

    # --- ADVANCED CHECKS ---
    if advanced:
        check_numverify(phone_number, numverify_key)
        check_twilio(phone_number, twilio_sid, twilio_token)
        check_nexmo(phone_number, nexmo_key, nexmo_secret)
        check_opencnam(phone_number, opencnam_key)
        check_truecaller(phone_number, truecaller_token)
        check_pipl(phone_number, pipl_key)
        check_whitepages(phone_number, whitepages_key)
        check_fullcontact(phone_number, fullcontact_key)
        check_numlookup(phone_number, numlookup_key)
        check_phoneformat(phone_number, phoneformat_key)
        check_hlrlookup(phone_number, hlrlookup_key)
        check_infobel(phone_number, infobel_key)
        check_fraudcheck(phone_number, fraudcheck_key)
        check_callerid(phone_number, callerid_key)
        # ...call additional check_*() for other services

    output_manager.success(f"Phone lookup completed. {'Report saved to '+report_path if save else 'Not saved.'}")


# --- BASIC FUNCTIONS ---

def check_numverify_basic(phone_number):
    output_manager.info("Basic NumVerify lookup (no API key)...")
    output_manager.warning("No API key provided, skipping detailed NumVerify data.")

def search_social_media(phone_number):
    output_manager.info("Generating social media dorks...")
    platforms = ["facebook.com", "twitter.com", "instagram.com", "linkedin.com", "pastebin.com", "github.com"]
    output_manager.warning("Automated social search limited. Use these URLs manually:")
    for site in platforms:
        dork = f'"{phone_number}" site:{site}'
        output_manager.info(f" - https://www.google.com/search?q={dork.replace(' ', '+')}")


# --- ADVANCED FUNCTIONS ---

def check_numverify(phone_number, api_key):
    output_manager.info("Checking NumVerify API for phone details...")
    try:
        url = f"http://apilayer.net/api/validate?access_key={api_key}&number={phone_number}&format=1"
        r = requests.get(url)
        data = r.json()
        if data.get("valid"):
            output_manager.success(f"NumVerify: Valid number")
            output_manager.info(f"International Format: {data.get('international_format')}")
            output_manager.info(f"Local Format: {data.get('local_format')}")
            output_manager.info(f"Country: {data.get('country_name')} ({data.get('country_code')})")
            carrier = data.get("carrier") or "Unknown"
            output_manager.info(f"Carrier: {carrier}")
            output_manager.info(f"Line Type: {data.get('line_type')}")
        else:
            output_manager.warning("NumVerify: Number invalid or not found.")
    except Exception as e:
        output_manager.error(f"NumVerify lookup failed: {e}")

def check_twilio(phone_number, sid, token):
    output_manager.info("Checking Twilio Lookup API...")
    try:
        url = f"https://lookups.twilio.com/v1/PhoneNumbers/{phone_number}?Type=carrier"
        r = requests.get(url, auth=(sid, token))
        data = r.json()
        carrier = data.get("carrier", {})
        output_manager.success("Twilio carrier lookup:")
        output_manager.info(f" Name: {carrier.get('name')}")
        output_manager.info(f" Type: {carrier.get('type')}")
    except Exception as e:
        output_manager.error(f"Twilio lookup failed: {e}")

def check_nexmo(phone_number, key, secret):
    output_manager.info("Checking Nexmo Number Insight API...")
    try:
        url = f"https://api.nexmo.com/ni/basic/json?api_key={key}&api_secret={secret}&number={phone_number}"
        data = requests.get(url).json()
        output_manager.success("Nexmo insight:")
        output_manager.info(f" Status: {data.get('status')}")
        output_manager.info(f" Country: {data.get('country_name')}")
        output_manager.info(f" Network: {data.get('network')}")
    except Exception as e:
        output_manager.error(f"Nexmo lookup failed: {e}")

def check_opencnam(phone_number, api_key):
    output_manager.info("Checking OpenCNAM caller ID...")
    try:
        url = f"https://api.opencnam.com/v3/phone/{phone_number}?format=json&account_sid={api_key}"
        data = requests.get(url).json()
        output_manager.success(f"OpenCNAM: Caller Name: {data.get('name')}")
    except Exception as e:
        output_manager.error(f"OpenCNAM lookup failed: {e}")

def check_truecaller(phone_number, token):
    output_manager.info("Checking Truecaller (unofficial)...")
    try:
        url = f"https://api5.truecaller.com/v1/search?phone={phone_number}"
        r = requests.get(url, headers={"Authorization": f"Bearer {token}"})
        data = r.json().get("data", {})
        output_manager.success(f"Truecaller name: {data.get('name')}")
    except Exception as e:
        output_manager.error(f"Truecaller lookup failed: {e}")

def check_pipl(phone_number, api_key):
    output_manager.info("Checking Pipl for identity resolution...")
    try:
        url = f"https://api.pipl.com/search/?key={api_key}&phone={phone_number}"
        data = requests.get(url).json()
        person = data.get("person", {})
        output_manager.success(f"Pipl: Found person?: {'Yes' if person else 'No'}")
    except Exception as e:
        output_manager.error(f"Pipl lookup failed: {e}")

def check_whitepages(phone_number, api_key):
    output_manager.info("Checking Whitepages Pro...")
    try:
        url = f"https://proapi.whitepages.com/3.0/phone.json?api_key={api_key}&phone_number={phone_number}"
        data = requests.get(url).json()
        output_manager.success(f"Whitepages: Valid? {data.get('valid')}")
    except Exception as e:
        output_manager.error(f"Whitepages lookup failed: {e}")

def check_fullcontact(phone_number, api_key):
    output_manager.info("Checking FullContact for phone enrichment...")
    try:
        url = f"https://api.fullcontact.com/v3/phone/enrich"
        r = requests.post(url, json={"phone": phone_number}, headers={"Authorization": f"Bearer {api_key}"})
        info = r.json()
        output_manager.success(f"FullContact: Found {len(info.keys())} fields")
    except Exception as e:
        output_manager.error(f"FullContact lookup failed: {e}")

def check_numlookup(phone_number, api_key):
    output_manager.info("Checking NumberAPI (numlookupapi.com)...")
    try:
        url = f"https://numlookupapi.com/api/v2/validate?number={phone_number}&apikey={api_key}"
        data = requests.get(url).json()
        output_manager.success(f"NumberAPI: Valid? {data.get('valid')}")
    except Exception as e:
        output_manager.error(f"NumberAPI lookup failed: {e}")

def check_phoneformat(phone_number, api_key):
    output_manager.info("Checking PhoneFormat.io...")
    try:
        url = f"https://phoneformat.io/api/v1/parse?phone={phone_number}&apikey={api_key}"
        data = requests.get(url).json()
        output_manager.success(f"PhoneFormat: Country code: {data.get('country_code')}")
    except Exception as e:
        output_manager.error(f"PhoneFormat lookup failed: {e}")

def check_hlrlookup(phone_number, api_key):
    output_manager.info("Checking HLR Lookup API...")
    try:
        url = f"https://api.hlrlookup.com/hlr.php?phone={phone_number}&apikey={api_key}"
        data = requests.get(url).json()
        output_manager.success(f"HLR Lookup status: {data.get('status')}")
    except Exception as e:
        output_manager.error(f"HLR lookup failed: {e}")

def check_infobel(phone_number, api_key):
    output_manager.info("Checking Infobel Phone Search...")
    try:
        url = f"https://api.infobel.com/services/rest/phone/search?key={api_key}&phoneNumber={phone_number}"
        data = requests.get(url).json()
        output_manager.success(f"Infobel results: {data.get('records_count')} record(s)")
    except Exception as e:
        output_manager.error(f"Infobel lookup failed: {e}")

def check_fraudcheck(phone_number, api_key):
    output_manager.info("Checking FraudCheck.net...")
    try:
        url = f"https://api.fraudcheck.net/phone?number={phone_number}&apikey={api_key}"
        data = requests.get(url).json()
        output_manager.success(f"FraudCheck risk: {data.get('risk')}")
    except Exception as e:
        output_manager.error(f"FraudCheck lookup failed: {e}")

def check_callerid(phone_number, api_key):
    output_manager.info("Checking CallerID API...")
    try:
        url = f"https://calleridapi.com/api/v1/phone/{phone_number}?key={api_key}"
        data = requests.get(url).json()
        output_manager.success(f"CallerID name: {data.get('name')}")
    except Exception as e:
        output_manager.error(f"CallerID lookup failed: {e}")

# Additional check_*() functions for any other desired services...
