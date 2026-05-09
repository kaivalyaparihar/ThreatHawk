#backend\routers\dashboard.py

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from database import get_db
import models

router = APIRouter()


@router.get("/stats")
def get_dashboard_stats(db: Session = Depends(get_db)):
    total_iocs = db.query(models.IOCResult).count()

    total_threats = db.query(models.IOCResult).filter(
        models.IOCResult.severity.in_(["High", "Critical"])
    ).count()

    total_feed_items = db.query(models.FeedItem).count()
    total_victims = db.query(models.DarkWebVictim).count()

    # Recent high/critical alerts
    recent_alerts = db.query(models.IOCResult).filter(
        models.IOCResult.severity.in_(["High", "Critical"])
    ).order_by(
        models.IOCResult.created_at.desc()
    ).limit(10).all()

    # Top malware families from feed
    top_malware = db.query(
        models.FeedItem.malware_family,
        func.count(models.FeedItem.id).label("count")
    ).filter(
        models.FeedItem.malware_family.isnot(None),
        models.FeedItem.malware_family != "Unknown"
    ).group_by(
        models.FeedItem.malware_family
    ).order_by(
        func.count(models.FeedItem.id).desc()
    ).limit(5).all()

    # Top targeted countries from dark web
    top_countries = db.query(
        models.DarkWebVictim.country,
        func.count(models.DarkWebVictim.id).label("count")
    ).filter(
        models.DarkWebVictim.country.isnot(None),
        models.DarkWebVictim.country != ""
    ).group_by(
        models.DarkWebVictim.country
    ).order_by(
        func.count(models.DarkWebVictim.id).desc()
    ).limit(5).all()

    # IOCs by severity
    iocs_by_severity = db.query(
        models.IOCResult.severity,
        func.count(models.IOCResult.id).label("count")
    ).group_by(
        models.IOCResult.severity
    ).all()

    return {
        "total_iocs_investigated": total_iocs,
        "total_threats_detected": total_threats,
        "total_feed_items": total_feed_items,
        "total_dark_web_victims": total_victims,
        "recent_alerts": [
            {
                "id": r.id,
                "ioc": r.ioc,
                "ioc_type": r.ioc_type,
                "threat_score": r.threat_score,
                "severity": r.severity,
                "created_at": r.created_at,
            }
            for r in recent_alerts
        ],
        "top_malware_families": [
            {"name": m, "count": c} for m, c in top_malware
        ],
        "top_targeted_countries": [
            {"name": co, "count": c} for co, c in top_countries
        ],
        "iocs_by_severity": {s: c for s, c in iocs_by_severity},
    }
