#backend\integrations\abuseipdb.py

import httpx
import os
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


async def query_abuseipdb(ip: str) -> dict:
    """
    Queries AbuseIPDB for information about an IP address.
    Returns a structured result dict.
    """

    if not ABUSEIPDB_API_KEY or ABUSEIPDB_API_KEY == "your_abuseipdb_key_here":
        return {
            "success": False,
            "error": "AbuseIPDB API key not configured. Add it to your .env file.",
            "source": "abuseipdb"
        }

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
        "verbose": True
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                ABUSEIPDB_URL,
                headers=headers,
                params=params
            )
            response.raise_for_status()
            data = response.json()

            return {
                "success": True,
                "source": "abuseipdb",
                "data": {
                    "ipAddress": data["data"]["ipAddress"],
                    "isPublic": data["data"]["isPublic"],
                    "ipVersion": data["data"]["ipVersion"],
                    "isWhitelisted": data["data"]["isWhitelisted"],
                    "abuseConfidenceScore": data["data"]["abuseConfidenceScore"],
                    "countryCode": data["data"]["countryCode"],
                    "usageType": data["data"]["usageType"],
                    "isp": data["data"]["isp"],
                    "domain": data["data"]["domain"],
                    "totalReports": data["data"]["totalReports"],
                    "numDistinctUsers": data["data"]["numDistinctUsers"],
                    "lastReportedAt": data["data"]["lastReportedAt"],
                }
            }

    except httpx.TimeoutException:
        return {
            "success": False,
            "error": "Request timed out",
            "source": "abuseipdb"
        }
    except httpx.HTTPStatusError as e:
        return {
            "success": False,
            "error": f"HTTP error: {e.response.status_code}",
            "source": "abuseipdb"
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "source": "abuseipdb"
        }