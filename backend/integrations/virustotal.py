#backend\integrations\virustotal.py

import httpx
import os
from dotenv import load_dotenv

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VIRUSTOTAL_BASE = "https://www.virustotal.com/api/v3"


async def query_virustotal(ioc: str, ioc_type: str) -> dict:
    """
    Queries VirusTotal for information about an IOC.
    Supports: ip, domain, sha256, md5, sha1
    """

    if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY == "your_virustotal_key_here":
        return {
            "success": False,
            "error": "VirusTotal API key not configured. Add VIRUSTOTAL_API_KEY to your .env file.",
            "source": "virustotal"
        }

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "Accept": "application/json"
    }

    # Build endpoint URL based on IOC type
    if ioc_type == "ip":
        url = f"{VIRUSTOTAL_BASE}/ip_addresses/{ioc}"
    elif ioc_type == "domain":
        url = f"{VIRUSTOTAL_BASE}/domains/{ioc}"
    elif ioc_type in ("sha256", "md5", "sha1"):
        url = f"{VIRUSTOTAL_BASE}/files/{ioc}"
    else:
        return {
            "success": False,
            "error": f"Unsupported IOC type for VirusTotal: {ioc_type}",
            "source": "virustotal"
        }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            data = response.json()

            attributes = data.get("data", {}).get("attributes", {})
            last_analysis = attributes.get("last_analysis_stats", {})

            malicious = last_analysis.get("malicious", 0)
            suspicious = last_analysis.get("suspicious", 0)
            undetected = last_analysis.get("undetected", 0)
            harmless = last_analysis.get("harmless", 0)
            total = malicious + suspicious + undetected + harmless

            # Extract malware families from results
            malware_families = []
            analysis_results = attributes.get("last_analysis_results", {})
            for engine_name, result in analysis_results.items():
                if result.get("category") == "malicious" and result.get("result"):
                    family = result["result"]
                    if family not in malware_families:
                        malware_families.append(family)

            result_data = {
                "malicious": malicious,
                "suspicious": suspicious,
                "undetected": undetected,
                "harmless": harmless,
                "total_engines": total,
                "detection_ratio": f"{malicious}/{total}" if total > 0 else "0/0",
                "malware_families": malware_families[:20],
                "last_analysis_date": attributes.get("last_analysis_date"),
                "reputation": attributes.get("reputation", 0),
            }

            # Add type-specific fields
            if ioc_type == "ip":
                result_data["country"] = attributes.get("country", "Unknown")
                result_data["as_owner"] = attributes.get("as_owner", "Unknown")
                result_data["asn"] = attributes.get("asn")
                result_data["network"] = attributes.get("network")
            elif ioc_type == "domain":
                result_data["registrar"] = attributes.get("registrar", "Unknown")
                result_data["creation_date"] = attributes.get("creation_date")
                result_data["last_dns_records"] = [
                    {"type": r.get("type"), "value": r.get("value")}
                    for r in attributes.get("last_dns_records", [])[:10]
                ]
            elif ioc_type in ("sha256", "md5", "sha1"):
                result_data["file_type"] = attributes.get("type_description", "Unknown")
                result_data["file_size"] = attributes.get("size")
                result_data["file_names"] = attributes.get("names", [])[:5]
                result_data["sha256"] = attributes.get("sha256")
                result_data["md5"] = attributes.get("md5")
                result_data["sha1"] = attributes.get("sha1")

            return {
                "success": True,
                "source": "virustotal",
                "data": result_data
            }

    except httpx.TimeoutException:
        return {
            "success": False,
            "error": "Request timed out",
            "source": "virustotal"
        }
    except httpx.HTTPStatusError as e:
        return {
            "success": False,
            "error": f"HTTP error: {e.response.status_code}",
            "source": "virustotal"
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "source": "virustotal"
        }
