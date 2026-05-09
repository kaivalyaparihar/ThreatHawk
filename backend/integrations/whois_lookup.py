#backend\integrations\whois_lookup.py

import asyncio
import whois


async def query_whois(domain: str) -> dict:
    """
    Queries WHOIS data for a domain.
    Returns: registrar, creation_date, expiration_date, name_servers, registrant_org.
    """

    try:
        # python-whois is sync, so run in executor
        loop = asyncio.get_event_loop()
        w = await loop.run_in_executor(None, whois.whois, domain)

        if not w or not w.domain_name:
            return {
                "success": True,
                "source": "whois",
                "data": {
                    "domain": domain,
                    "note": "No WHOIS data found for this domain"
                }
            }

        # Normalise fields (python-whois sometimes returns lists)
        def first_or_val(val):
            if isinstance(val, list):
                return str(val[0]) if val else None
            return str(val) if val else None

        def to_str_list(val):
            if isinstance(val, list):
                return [str(v) for v in val]
            if val:
                return [str(val)]
            return []

        return {
            "success": True,
            "source": "whois",
            "data": {
                "domain": first_or_val(w.domain_name),
                "registrar": w.registrar or "Unknown",
                "creation_date": first_or_val(w.creation_date),
                "expiration_date": first_or_val(w.expiration_date),
                "updated_date": first_or_val(w.updated_date),
                "name_servers": to_str_list(w.name_servers),
                "registrant_org": w.org or "Unknown",
                "registrant_country": w.country or "Unknown",
                "registrant_state": w.state or "Unknown",
                "emails": to_str_list(w.emails),
                "dnssec": w.dnssec if hasattr(w, "dnssec") else "Unknown",
                "status": to_str_list(w.status),
            }
        }

    except asyncio.TimeoutError:
        return {
            "success": False,
            "error": "WHOIS lookup timed out",
            "source": "whois"
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "source": "whois"
        }
