import ipaddress
import json
import os
import re
import time
from urllib.parse import urlparse

import streamlit as st
from google import genai

from sources import SOURCES


st.set_page_config(page_title="ThreatLens - Security Analysis", page_icon="🛡️", layout="wide")

st.title("🛡️ ThreatLens - AI Threat Analysis")
st.caption("Analyze IP addresses, domains, and URLs with VirusTotal, WHOIS, and Gemini AI")


def get_secret(name):
    try:
        value = st.secrets.get(name, "")
        if value:
            return value
    except Exception:
        pass
    return os.getenv(name, "")


def detect_target_type(target):
    target = target.strip()
    try:
        ipaddress.ip_address(target)
        return "ip"
    except ValueError:
        pass
    if re.match(r"^https?://", target, re.IGNORECASE):
        return "url"
    return "domain"


def validate_target(target, target_type):
    target = target.strip()
    if not target:
        return False, "Please enter an IP address, domain, or URL."

    if target_type == "ip":
        try:
            ipaddress.ip_address(target)
            return True, ""
        except ValueError:
            return False, "Invalid IP address."

    if target_type == "url":
        parsed = urlparse(target)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return False, "Invalid URL. Use a complete URL such as https://example.com."
        return True, ""

    domain = target.lower().rstrip(".")
    if len(domain) > 253 or not re.match(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$", domain):
        return False, "Invalid domain. Use a domain such as example.com."
    return True, ""


def get_available_gemini_models(client):
    """Return usable Gemini Flash models, preferring the newest practical model."""
    preferred = [
        "gemini-3.7-flash",
        "gemini-3.6-flash",
        "gemini-3.5-flash",
        "gemini-3.1-flash-lite",
    ]

    try:
        models = list(client.models.list())
        available = set()
        for model in models:
            name = getattr(model, "name", "") or ""
            name = name.removeprefix("models/")
            if name and "gemini" in name.lower() and "flash" in name.lower():
                available.add(name)

        selected = [name for name in preferred if name in available]
        remaining = sorted(available - set(selected))
        return selected + remaining
    except Exception:
        # Keep a safe fallback list if model discovery itself is temporarily unavailable.
        return preferred


def is_temporary_gemini_error(exc):
    message = str(exc).upper()
    return "503" in message or "UNAVAILABLE" in message or "429" in message or "RESOURCE_EXHAUSTED" in message


def build_prompt(target, target_type, level, results):
    return f"""You are a cybersecurity threat analyst.

Analyze this target using ONLY the collected VirusTotal and WHOIS information. Do not invent facts.

Target: {target}
Target type: {target_type}
User expertise: {level}
Collected data:
{json.dumps(results, indent=2, default=str)}

Return a concise report with exactly these sections:
1. VERDICT: SAFE, SUSPICIOUS, MALICIOUS, or UNKNOWN
2. CONFIDENCE: Low, Medium, or High
3. SUMMARY
4. KEY FINDINGS
5. RISK FACTORS
6. RECOMMENDATION

If the sources are unavailable, contradictory, or insufficient, use UNKNOWN rather than guessing.
Explain technical details at the user's {level} level.
"""


def analyze_with_gemini(api_key, prompt):
    client = genai.Client(api_key=api_key)
    models = get_available_gemini_models(client)
    last_error = None

    # Gemini can temporarily return 503 during capacity spikes. Retry with
    # exponential backoff, then automatically try another available Flash model.
    for model in models:
        for attempt in range(3):
            try:
                response = client.models.generate_content(model=model, contents=prompt)
                text = getattr(response, "text", None)
                if not text:
                    raise RuntimeError("Gemini returned an empty response.")
                return model, text
            except Exception as exc:
                last_error = exc
                if not is_temporary_gemini_error(exc):
                    break
                if attempt < 2:
                    time.sleep(3 * (2 ** attempt))

    raise RuntimeError(f"Gemini models were temporarily unavailable. Last error: {last_error}")


st.sidebar.header("🔑 Configuration")
vt_secret = get_secret("VIRUSTOTAL_API_KEY")
gemini_secret = get_secret("GEMINI_API_KEY")

vt_api_key = st.sidebar.text_input("VirusTotal API Key", value=vt_secret, type="password")
gemini_api_key = st.sidebar.text_input("Gemini API Key", value=gemini_secret, type="password")

st.sidebar.divider()
level = st.sidebar.selectbox("Target Knowledge Level", ["Beginner", "Intermediate", "Expert"])

if vt_secret:
    st.sidebar.caption("✓ VirusTotal key loaded from app secrets")
if gemini_secret:
    st.sidebar.caption("✓ Gemini key loaded from app secrets")


target_input = st.text_input(
    "Enter IP Address, Domain, or URL:",
    placeholder="e.g. 8.8.8.8, example.com, https://example.com",
)

if st.button("Analyze Threat", type="primary", use_container_width=True):
    target = target_input.strip()
    target_type = detect_target_type(target)
    valid, error = validate_target(target, target_type)

    if not valid:
        st.error(error)
        st.stop()

    st.info(f"Target Type Detected: **{target_type.upper()}**")

    aggregated_results = {}
    with st.spinner("Gathering intelligence from threat sources..."):
        for source_name, fetch_fn in SOURCES.items():
            try:
                key = vt_api_key if source_name == "VirusTotal" else None
                aggregated_results[source_name] = fetch_fn(target, target_type, key)
            except Exception as exc:
                aggregated_results[source_name] = {
                    "source": source_name,
                    "status": "error",
                    "data": None,
                    "error": str(exc),
                }

    st.subheader("🔍 Source Results")
    cols = st.columns(len(aggregated_results))
    for col, (name, result) in zip(cols, aggregated_results.items()):
        with col:
            status = result.get("status", "unknown")
            if status == "success":
                st.success(f"{name}: {status}")
            elif status in {"skipped", "not_applicable", "not_found"}:
                st.warning(f"{name}: {status}")
            else:
                st.error(f"{name}: {status}")

    with st.expander("View Raw Source Data"):
        st.json(aggregated_results)

    if not gemini_api_key:
        st.warning("Gemini API key is not configured. Source results are shown above; add GEMINI_API_KEY in Streamlit Secrets to enable AI analysis.")
    else:
        with st.spinner("Generating AI Analysis Report..."):
            try:
                prompt = build_prompt(target, target_type, level, aggregated_results)
                selected_model, report = analyze_with_gemini(gemini_api_key, prompt)
                st.divider()
                st.subheader("📋 AI Risk Assessment")
                st.caption(f"Powered by `{selected_model}`")
                st.markdown(report)
            except Exception as exc:
                st.error("AI analysis could not be generated right now. Please try Analyze Threat again in a moment.")
                st.caption(f"Technical detail: {exc}")
