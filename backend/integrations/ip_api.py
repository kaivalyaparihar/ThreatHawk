#backend\integrations\ip_api.py

import httpx


async def query_ip_api(ip: str) -> dict:
    """
    Queries ip-api.com for geolocation data about an IP address.
    Free tier — no API key required.
    """

    url = f"http://ip-api.com/json/{ip}"
    params = {
        "fields": "status,message,country,countryCode,region,regionName,city,isp,org,as,lat,lon"
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(url, params=params)
            response.raise_for_status()
            data = response.json()

            if data.get("status") == "fail":
                return {
                    "success": False,
                    "error": data.get("message", "IP geolocation lookup failed"),
                    "source": "ip_api"
                }

            return {
                "success": True,
                "source": "ip_api",
                "data": {
                    "country": data.get("country", "Unknown"),
                    "countryCode": data.get("countryCode", ""),
                    "region": data.get("regionName", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "org": data.get("org", "Unknown"),
                    "asn": data.get("as", "Unknown"),
                    "lat": data.get("lat", 0),
                    "lon": data.get("lon", 0),
                }
            }

    except httpx.TimeoutException:
        return {
            "success": False,
            "error": "Request timed out",
            "source": "ip_api"
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "source": "ip_api"
        }
