#backend\integrations\dns_lookup.py

import asyncio
import dns.resolver


async def query_dns(domain: str) -> dict:
    """
    Queries DNS records for a domain.
    Returns: A, MX, NS, TXT, CNAME records.
    """

    try:
        loop = asyncio.get_event_loop()
        resolver = dns.resolver.Resolver()
        resolver.timeout = 10
        resolver.lifetime = 10

        records = {}

        # Query each record type
        record_types = ["A", "MX", "NS", "TXT", "CNAME"]
        for rtype in record_types:
            try:
                answers = await loop.run_in_executor(
                    None, lambda rt=rtype: resolver.resolve(domain, rt)
                )
                records[rtype] = [str(rdata) for rdata in answers]
            except dns.resolver.NoAnswer:
                records[rtype] = []
            except dns.resolver.NXDOMAIN:
                return {
                    "success": False,
                    "error": f"Domain {domain} does not exist (NXDOMAIN)",
                    "source": "dns"
                }
            except dns.resolver.NoNameservers:
                records[rtype] = []
            except Exception:
                records[rtype] = []

        return {
            "success": True,
            "source": "dns",
            "data": {
                "domain": domain,
                "a_records": records.get("A", []),
                "mx_records": records.get("MX", []),
                "ns_records": records.get("NS", []),
                "txt_records": records.get("TXT", []),
                "cname_records": records.get("CNAME", []),
            }
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "source": "dns"
        }
