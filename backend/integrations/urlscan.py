#backend\integrations\urlscan.py

import httpx
import os
from dotenv import load_dotenv

load_dotenv()

URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY")
URLSCAN_BASE = "https://urlscan.io/api/v1"


async def query_urlscan(ioc: str, ioc_type: str) -> dict:
    """
    Queries URLScan.io for information about a domain or IP.
    Returns: scan results, verdicts, screenshots, linked domains.
    """

    if not URLSCAN_API_KEY or URLSCAN_API_KEY == "your_urlscan_key_here":
        return {
            "success": False,
            "error": "URLScan API key not configured. Add URLSCAN_API_KEY to your .env file.",
            "source": "urlscan"
        }

    if ioc_type not in ("domain", "ip"):
        return {
            "success": False,
            "error": f"Unsupported IOC type for URLScan: {ioc_type}",
            "source": "urlscan"
        }

    headers = {
        "API-Key": URLSCAN_API_KEY,
        "Accept": "application/json"
    }

    # Search for existing scans of this IOC
    if ioc_type == "domain":
        query = f"domain:{ioc}"
    else:
        query = f"ip:{ioc}"

    url = f"{URLSCAN_BASE}/search/?q={query}&size=10"

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            data = response.json()

            results = data.get("results", [])

            if not results:
                return {
                    "success": True,
                    "source": "urlscan",
                    "data": {
                        "total_results": 0,
                        "scans": [],
                        "note": "No scan results found for this IOC"
                    }
                }

            scans = []
            verdicts = []
            screenshots = []
            linked_domains = set()

            for result in results[:10]:
                task = result.get("task", {})
                page = result.get("page", {})
                stats = result.get("stats", {})

                scan = {
                    "uuid": result.get("_id", ""),
                    "url": task.get("url", ""),
                    "domain": page.get("domain", ""),
                    "ip": page.get("ip", ""),
                    "country": page.get("country", ""),
                    "server": page.get("server", ""),
                    "status_code": page.get("status", 0),
                    "title": page.get("title", ""),
                    "time": task.get("time", ""),
                    "verdicts_malicious": result.get("verdicts", {}).get("overall", {}).get("malicious", False),
                    "verdicts_score": result.get("verdicts", {}).get("overall", {}).get("score", 0),
                }
                scans.append(scan)

                # Collect verdict info
                verdict = result.get("verdicts", {}).get("overall", {})
                if verdict:
                    verdicts.append({
                        "malicious": verdict.get("malicious", False),
                        "score": verdict.get("score", 0),
                        "categories": verdict.get("categories", []),
                    })

                # Collect screenshots
                screenshot = result.get("screenshot", "")
                if screenshot:
                    screenshots.append(screenshot)

                # Collect linked domains
                if page.get("domain"):
                    linked_domains.add(page["domain"])

            # Determine overall verdict
            is_malicious = any(v.get("malicious") for v in verdicts) if verdicts else False

            return {
                "success": True,
                "source": "urlscan",
                "data": {
                    "total_results": len(results),
                    "is_malicious": is_malicious,
                    "scans": scans,
                    "verdicts": verdicts[:5],
                    "screenshots": screenshots[:5],
                    "linked_domains": list(linked_domains)[:20],
                }
            }

    except httpx.TimeoutException:
        return {
            "success": False,
            "error": "Request timed out",
            "source": "urlscan"
        }
    except httpx.HTTPStatusError as e:
        return {
            "success": False,
            "error": f"HTTP error: {e.response.status_code}",
            "source": "urlscan"
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "source": "urlscan"
        }
