import base64
import os
from urllib.parse import urlparse

import requests
import whois


VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")


def get_virustotal(target, input_type, api_key=None):
    key = api_key or VT_API_KEY
    if not key:
        return {"source": "VirusTotal", "status": "skipped", "data": None, "error": "VirusTotal API key is not configured."}

    try:
        if input_type == "ip":
            endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
        elif input_type == "domain":
            endpoint = f"https://www.virustotal.com/api/v3/domains/{target}"
        elif input_type == "url":
            url_id = base64.urlsafe_b64encode(target.encode("utf-8")).decode("utf-8").rstrip("=")
            endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        else:
            return {"source": "VirusTotal", "status": "error", "data": None, "error": "Unsupported target type."}

        response = requests.get(endpoint, headers={"x-apikey": key}, timeout=15)
        if response.status_code == 404:
            return {"source": "VirusTotal", "status": "not_found", "data": None, "error": "No existing VirusTotal report was found for this target."}
        response.raise_for_status()

        payload = response.json()
        attributes = payload.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        return {
            "source": "VirusTotal",
            "status": "success",
            "data": stats,
            "error": None,
        }
    except requests.RequestException as exc:
        return {"source": "VirusTotal", "status": "error", "data": None, "error": f"VirusTotal request failed: {exc}"}
    except (ValueError, KeyError, TypeError) as exc:
        return {"source": "VirusTotal", "status": "error", "data": None, "error": f"Invalid VirusTotal response: {exc}"}
    except Exception as exc:
        return {"source": "VirusTotal", "status": "error", "data": None, "error": str(exc)}


def get_whois(target, input_type, api_key=None):
    if input_type == "ip":
        return {
            "source": "WHOIS",
            "status": "not_applicable",
            "data": None,
            "error": "WHOIS domain registration data is not used for IP targets in this app.",
        }

    try:
        lookup_target = urlparse(target).hostname if input_type == "url" else target
        if not lookup_target:
            raise ValueError("Could not extract a hostname from the URL.")

        record = whois.whois(lookup_target)
        data = {
            "registrar": record.registrar,
            "creation_date": str(record.creation_date),
            "expiration_date": str(record.expiration_date),
            "country": record.country,
            "name_servers": record.name_servers,
        }
        return {"source": "WHOIS", "status": "success", "data": data, "error": None}
    except Exception as exc:
        return {"source": "WHOIS", "status": "error", "data": None, "error": str(exc)}


# Add future intelligence sources here without changing the orchestration/UI.
SOURCES = {
    "VirusTotal": get_virustotal,
    "WHOIS": get_whois,
}
