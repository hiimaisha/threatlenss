import os
import re
import subprocess

# Auto-install WHOIS binary if missing (System package fix)
try:
    subprocess.run(["whois", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
except FileNotFoundError:
    try:
        subprocess.run(["apt-get", "update", "-y"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["apt-get", "install", "-y", "whois"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass

import streamlit as st
import whois
import requests
from google import genai

# ------------------------------------------------------------------------------
# 1. PAGE CONFIG & STYLING
# ------------------------------------------------------------------------------
st.set_page_config(
    page_title="ThreatLens - Security Analysis",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ ThreatLens - AI Threat Analysis")
st.caption("Analyze IP addresses, Domains, or URLs with VT, WHOIS & Gemini AI")

# ------------------------------------------------------------------------------
# 2. SIDEBAR - API KEYS & SETTINGS
# ------------------------------------------------------------------------------
st.sidebar.header("🔑 Configuration")

vt_key_default = st.secrets.get("VIRUSTOTAL_API_KEY", "") if "VIRUSTOTAL_API_KEY" in st.secrets else ""
gemini_key_default = st.secrets.get("GEMINI_API_KEY", "") if "GEMINI_API_KEY" in st.secrets else ""

vt_api_key = st.sidebar.text_input("VirusTotal API Key", value=vt_key_default, type="password")
gemini_api_key = st.sidebar.text_input("Gemini API Key", value=gemini_key_default, type="password")

st.sidebar.divider()
level = st.sidebar.selectbox(
    "Target Knowledge Level",
    ["Beginner", "Intermediate", "Expert"],
    index=0
)

# ------------------------------------------------------------------------------
# 3. HELPER FUNCTIONS
# ------------------------------------------------------------------------------
def detect_target_type(target: str) -> str:
    target = target.strip()
    ip_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    url_pattern = r"^https?://"

    if re.match(ip_pattern, target):
        return "ip"
    elif re.match(url_pattern, target):
        return "url"
    else:
        return "domain"

def get_virustotal_data(target: str, target_type: str, api_key: str):
    if not api_key:
        return {"source": "VirusTotal", "status": "skipped", "data": None, "error": "API Key missing"}

    headers = {"x-apikey": api_key}
    try:
        if target_type == "ip":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
        elif target_type == "domain":
            url = f"https://www.virustotal.com/api/v3/domains/{target}"
        else:
            import base64
            url_id = base64.urlsafe_b64encode(target.encode()).decode().strip("=")
            url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        res = requests.get(url, headers=headers, timeout=10)
        if res.status_code == 200:
            stats = res.json()["data"]["attributes"]["last_analysis_stats"]
            return {"source": "VirusTotal", "status": "success", "data": stats, "error": None}
        else:
            return {"source": "VirusTotal", "status": "error", "data": None, "error": f"HTTP {res.status_code}"}
    except Exception as e:
        return {"source": "VirusTotal", "status": "error", "data": None, "error": str(e)}

def get_whois_data(target: str, target_type: str, api_key: str = None):
    if target_type == "url":
        from urllib.parse import urlparse
        target = urlparse(target).netloc

    try:
        w = whois.whois(target)
        parsed_data = {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "country": w.country
        }
        return {"source": "WHOIS", "status": "success", "data": parsed_data, "error": None}
    except Exception as e:
        return {"source": "WHOIS", "status": "error", "data": None, "error": str(e)}

SOURCES = {
    "VirusTotal": get_virustotal_data,
    "WHOIS": get_whois_data,
}

# ------------------------------------------------------------------------------
# 4. MAIN APPLICATION
# ------------------------------------------------------------------------------
target_input = st.text_input("Enter IP Address, Domain, or URL:", placeholder="e.g., 8.8.8.8, example.com, https://login.com")

if st.button("Analyze Threat", type="primary"):
    if not target_input:
        st.warning("Please enter a valid target to analyze.")
    else:
        target_type = detect_target_type(target_input)
        st.info(f"Target Type Detected: **{target_type.upper()}**")

        aggregated_results = {}
        with st.spinner("Gathering intelligence from threat sources..."):
            for source_name, fetch_fn in SOURCES.items():
                if source_name == "VirusTotal":
                    aggregated_results[source_name] = fetch_fn(target_input, target_type, vt_api_key)
                else:
                    aggregated_results[source_name] = fetch_fn(target_input, target_type)

        with st.expander("🔍 View Raw Source Data"):
            st.json(aggregated_results)

        if not gemini_api_key:
            st.error("Please enter a Gemini API Key in the sidebar to generate the AI analysis report.")
        else:
            with st.spinner("Generating AI Analysis Report..."):
                try:
                    client = genai.Client(api_key=gemini_api_key)
                    
                    prompt = f"""
                    You are a cybersecurity threat analyst. Analyze the following target data and provide a concise assessment.
                    
                    Target: {target_input}
                    Target Type: {target_type}
                    User Expertise Level: {level}
                    Collected Intelligence Data: {aggregated_results}

                    Rules for response:
                    1. Verdict: Must start with a clear verdict line: `VERDICT: [SAFE / SUSPICIOUS / MALICIOUS / UNKNOWN]`
                    2. Risk Breakdown: Explain the key risk factors based on the user's level ({level}).
                    3. Actionable Advice: Provide 2-3 clear next steps for the user.
                    """

                    response = client.models.generate_content(
                        model="gemini-2.5-flash",
                        contents=prompt,
                    )

                    st.markdown("---")
                    st.subheader("📋 AI Risk Assessment")
                    st.markdown(response.text)

                except Exception as e:
                    st.error(f"Failed to generate AI analysis: {str(e)}")
