#backend\integrations\feodotracker.py

import httpx


async def fetch_feodotracker() -> list:
    """
    Fetches recent Feodo Tracker botnet C2 IP blocklist.
    """

    url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"

    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            response = await client.get(url)
            response.raise_for_status()
            data = response.json()

            items = []
            for entry in data[:100]:
                items.append({
                    "source": "feodotracker",
                    "ioc_type": "ip",
                    "ioc_value": entry.get("ip_address", ""),
                    "malware_family": entry.get("malware", "Unknown"),
                    "country": entry.get("country") or "",
                    "severity": "Critical" if entry.get("status") == "online" else "High",
                    "tags": entry.get("malware", ""),
                    "raw_data": {
                        "ip_address": entry.get("ip_address"),
                        "port": entry.get("port"),
                        "status": entry.get("status"),
                        "malware": entry.get("malware"),
                        "first_seen": entry.get("first_seen"),
                        "last_seen": entry.get("last_online"),
                        "as_number": entry.get("as_number"),
                        "as_name": entry.get("as_name"),
                        "country": entry.get("country"),
                    },
                    "first_seen": entry.get("first_seen"),
                })
            return items

    except Exception as e:
        print(f"[FeodoTracker] Error: {e}")
        return []
