#backend\integrations\urlhaus.py

import httpx


async def fetch_urlhaus() -> list:
    """
    Fetches recent malicious URLs from URLhaus.
    """

    url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"

    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            response = await client.get(url)
            response.raise_for_status()
            data = response.json()

            items = []
            for entry in data.get("urls", [])[:100]:
                items.append({
                    "source": "urlhaus",
                    "ioc_type": "url",
                    "ioc_value": entry.get("url", ""),
                    "malware_family": entry.get("threat") or "Unknown",
                    "country": "",
                    "severity": "High" if entry.get("url_status") == "online" else "Medium",
                    "tags": ",".join(entry.get("tags", []) or []),
                    "raw_data": {
                        "url": entry.get("url"),
                        "url_status": entry.get("url_status"),
                        "threat": entry.get("threat"),
                        "host": entry.get("host"),
                        "date_added": entry.get("date_added"),
                        "tags": entry.get("tags"),
                        "reporter": entry.get("reporter"),
                    },
                    "first_seen": entry.get("date_added"),
                })
            return items

    except Exception as e:
        print(f"[URLhaus] Error: {e}")
        return []
