#backend\integrations\threatfox.py

import httpx


async def fetch_threatfox() -> list:
    """
    Fetches recent IOCs from ThreatFox.
    """

    url = "https://threatfox-api.abuse.ch/api/v1/"
    payload = {
        "query": "get_iocs",
        "days": 1
    }

    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
            data = response.json()

            if data.get("query_status") != "ok":
                return []

            items = []
            for entry in data.get("data", [])[:100]:
                # Determine IOC type
                ioc_type_raw = entry.get("ioc_type", "")
                if "ip" in ioc_type_raw.lower():
                    ioc_type = "ip"
                elif "domain" in ioc_type_raw.lower():
                    ioc_type = "domain"
                elif "url" in ioc_type_raw.lower():
                    ioc_type = "url"
                elif "hash" in ioc_type_raw.lower() or "md5" in ioc_type_raw.lower() or "sha" in ioc_type_raw.lower():
                    ioc_type = "hash"
                else:
                    ioc_type = ioc_type_raw

                items.append({
                    "source": "threatfox",
                    "ioc_type": ioc_type,
                    "ioc_value": entry.get("ioc", ""),
                    "malware_family": entry.get("malware") or entry.get("malware_alias") or "Unknown",
                    "country": "",
                    "severity": "High" if entry.get("threat_type") == "botnet_cc" else "Medium",
                    "tags": ",".join(entry.get("tags", []) or []),
                    "raw_data": {
                        "ioc": entry.get("ioc"),
                        "ioc_type": entry.get("ioc_type"),
                        "threat_type": entry.get("threat_type"),
                        "malware": entry.get("malware"),
                        "malware_alias": entry.get("malware_alias"),
                        "first_seen_utc": entry.get("first_seen_utc"),
                        "confidence_level": entry.get("confidence_level"),
                        "tags": entry.get("tags"),
                    },
                    "first_seen": entry.get("first_seen_utc"),
                })
            return items

    except Exception as e:
        print(f"[ThreatFox] Error: {e}")
        return []
