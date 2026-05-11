import requests
import time
import ipaddress

import os
from dotenv import load_dotenv
load_dotenv()
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
VT_BASE    = "https://www.virustotal.com/api/v3"

HEADERS = {
    "x-apikey": VT_API_KEY,
    "Accept":   "application/json",
}

def _is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

def _vt_request(endpoint):
    try:
        res = requests.get(f"{VT_BASE}{endpoint}", headers=HEADERS, timeout=30)
        if res.status_code == 429:
            time.sleep(15)
            res = requests.get(f"{VT_BASE}{endpoint}", headers=HEADERS, timeout=30)
        if res.status_code == 404:
            return None
        res.raise_for_status()
        return res.json()
    except Exception as e:
        print(f"VT error {endpoint}: {e}")
        return None

def enrich_ip(ip):
    if _is_private_ip(ip):
        return None
    data = _vt_request(f"/ip_addresses/{ip}")
    if not data:
        return None
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "value":        ip,
        "type":         "ip",
        "source":       "virustotal",
        "threat_score": min(100, stats.get("malicious", 0) * 10),
        "tags":         ["vt-enriched"],
    }

def enrich_domain(domain):
    data = _vt_request(f"/domains/{domain}")
    if not data:
        return None
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "value":        domain,
        "type":         "domain",
        "source":       "virustotal",
        "threat_score": min(100, stats.get("malicious", 0) * 10),
        "tags":         ["vt-enriched"],
    }

def enrich_hash(hash_value):
    data = _vt_request(f"/files/{hash_value}")
    if not data:
        return None
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "value":        hash_value,
        "type":         "hash",
        "source":       "virustotal",
        "threat_score": min(100, stats.get("malicious", 0) * 3),
        "tags":         ["vt-enriched", "malware"] if stats.get("malicious", 0) > 0 else ["vt-enriched"],
    }

def fetch_virustotal(limit=10):
    from threatintel.models import IOC
    results = []

    iocs = IOC.objects.filter(
        type__in=["ip", "domain", "hash", "md5", "sha256"]
    ).exclude(
        source="virustotal"
    ).order_by("-threat_score")[:limit]

    for ioc in iocs:
        try:
            enriched = None
            if ioc.type == "ip":
                enriched = enrich_ip(ioc.value)
            elif ioc.type == "domain":
                enriched = enrich_domain(ioc.value)
            elif ioc.type in ("hash", "md5", "sha256"):
                enriched = enrich_hash(ioc.value)

            if enriched:
                results.append(enriched)
            time.sleep(1) 
        except Exception as e:
            print(f"VT enrichment error for {ioc.value}: {e}")

    return results
