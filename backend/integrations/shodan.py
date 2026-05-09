#backend\integrations\shodan.py

import httpx
import os
from dotenv import load_dotenv

load_dotenv()

SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
SHODAN_BASE = "https://api.shodan.io"


async def query_shodan(ip: str) -> dict:
    """
    Queries Shodan for information about an IP address.
    Returns: open ports, hostnames, org, ISP, country, OS, vulns.
    """

    if not SHODAN_API_KEY or SHODAN_API_KEY == "your_shodan_key_here":
        return {
            "success": False,
            "error": "Shodan API key not configured. Add SHODAN_API_KEY to your .env file.",
            "source": "shodan"
        }

    url = f"{SHODAN_BASE}/shodan/host/{ip}"
    params = {"key": SHODAN_API_KEY}

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(url, params=params)
            response.raise_for_status()
            data = response.json()

            # Extract open ports from services
            ports = data.get("ports", [])
            services = []
            for item in data.get("data", [])[:20]:
                services.append({
                    "port": item.get("port"),
                    "transport": item.get("transport", "tcp"),
                    "product": item.get("product", "Unknown"),
                    "version": item.get("version", ""),
                    "banner": (item.get("data", "")[:200] if item.get("data") else ""),
                })

            # Extract vulnerabilities
            vulns = data.get("vulns", [])

            return {
                "success": True,
                "source": "shodan",
                "data": {
                    "ip": data.get("ip_str", ip),
                    "hostnames": data.get("hostnames", []),
                    "org": data.get("org", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "country_name": data.get("country_name", "Unknown"),
                    "country_code": data.get("country_code", ""),
                    "city": data.get("city", "Unknown"),
                    "os": data.get("os", "Unknown"),
                    "ports": ports,
                    "services": services,
                    "vulns": vulns,
                    "last_update": data.get("last_update", ""),
                    "tags": data.get("tags", []),
                }
            }

    except httpx.TimeoutException:
        return {
            "success": False,
            "error": "Request timed out",
            "source": "shodan"
        }
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            return {
                "success": True,
                "source": "shodan",
                "data": {
                    "ip": ip,
                    "note": "No information available for this IP",
                    "hostnames": [],
                    "ports": [],
                    "services": [],
                    "vulns": [],
                }
            }
        return {
            "success": False,
            "error": f"HTTP error: {e.response.status_code}",
            "source": "shodan"
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "source": "shodan"
        }
