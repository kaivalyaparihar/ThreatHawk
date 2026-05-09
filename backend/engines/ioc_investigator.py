#backend\engines\ioc_investigator.py

import asyncio
import json
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from integrations.abuseipdb import query_abuseipdb
from integrations.virustotal import query_virustotal
from integrations.shodan import query_shodan
from integrations.urlscan import query_urlscan
from integrations.whois_lookup import query_whois
from integrations.dns_lookup import query_dns
from integrations.ip_api import query_ip_api
from engines.scorer import calculate_score
from engines.graph_builder import build_graph
import models


async def investigate(ioc: str, ioc_type: str, db: Session) -> dict:
    """
    Main investigation engine.
    Runs all applicable integrations concurrently, scores, builds graph, saves to DB.
    """

    results = {}

    if ioc_type == "ip":
        tasks = {
            "abuseipdb": query_abuseipdb(ioc),
            "virustotal": query_virustotal(ioc, ioc_type),
            "shodan": query_shodan(ioc),
            "urlscan": query_urlscan(ioc, ioc_type),
            "ip_api": query_ip_api(ioc),
        }
    elif ioc_type == "domain":
        tasks = {
            "virustotal": query_virustotal(ioc, ioc_type),
            "urlscan": query_urlscan(ioc, ioc_type),
            "whois": query_whois(ioc),
            "dns": query_dns(ioc),
        }
    elif ioc_type in ("md5", "sha1", "sha256"):
        tasks = {
            "virustotal": query_virustotal(ioc, ioc_type),
        }
    elif ioc_type == "email":
        # Extract domain from email and check if abusive
        email_domain = ioc.split("@")[-1] if "@" in ioc else ioc
        tasks = {
            "virustotal": query_virustotal(email_domain, "domain"),
            "whois": query_whois(email_domain),
            "dns": query_dns(email_domain),
        }
    else:
        tasks = {}

    # Run all tasks concurrently
    if tasks:
        keys = list(tasks.keys())
        gathered = await asyncio.gather(*tasks.values(), return_exceptions=True)

        for key, result in zip(keys, gathered):
            if isinstance(result, Exception):
                results[key] = {
                    "success": False,
                    "error": str(result),
                    "source": key
                }
            else:
                results[key] = result

    # Calculate threat score
    threat_score, severity = calculate_score(results, ioc_type)

    # Build relationship graph
    graph_data = build_graph(ioc, ioc_type, results)

    # Save to database
    db_record = models.IOCResult(
        ioc=ioc,
        ioc_type=ioc_type,
        threat_score=threat_score,
        severity=severity,
        raw_results=json.dumps(results, default=str),
        graph_data=json.dumps(graph_data, default=str),
        created_at=datetime.now(timezone.utc)
    )
    db.add(db_record)
    db.commit()
    db.refresh(db_record)

    return {
        "id": db_record.id,
        "ioc": ioc,
        "ioc_type": ioc_type,
        "threat_score": threat_score,
        "severity": severity,
        "results": results,
        "graph_data": graph_data,
        "created_at": str(db_record.created_at)
    }
