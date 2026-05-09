#backend\routers\feed.py

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import func
from database import get_db
from engines.ioc_investigator import investigate
from utils.ioc_type_detector import detect_ioc_type
import json
import models

router = APIRouter()


@router.get("/")
def get_feed(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    source: str = None,
    ioc_type: str = None,
    malware_family: str = None,
    country: str = None,
    db: Session = Depends(get_db)
):
    query = db.query(models.FeedItem)

    if source:
        query = query.filter(models.FeedItem.source == source)
    if ioc_type:
        query = query.filter(models.FeedItem.ioc_type == ioc_type)
    if malware_family:
        query = query.filter(models.FeedItem.malware_family.ilike(f"%{malware_family}%"))
    if country:
        query = query.filter(models.FeedItem.country == country)

    total = query.count()
    items = query.order_by(
        models.FeedItem.created_at.desc()
    ).offset((page - 1) * limit).limit(limit).all()

    return {
        "total": total,
        "page": page,
        "limit": limit,
        "items": [
            {
                "id": item.id,
                "source": item.source,
                "ioc_type": item.ioc_type,
                "ioc_value": item.ioc_value,
                "malware_family": item.malware_family,
                "country": item.country,
                "severity": item.severity,
                "tags": item.tags,
                "first_seen": item.first_seen,
                "created_at": item.created_at,
            }
            for item in items
        ]
    }


@router.get("/stats")
def get_feed_stats(db: Session = Depends(get_db)):
    total = db.query(models.FeedItem).count()

    by_source = db.query(
        models.FeedItem.source,
        func.count(models.FeedItem.id)
    ).group_by(models.FeedItem.source).all()

    by_malware = db.query(
        models.FeedItem.malware_family,
        func.count(models.FeedItem.id)
    ).filter(
        models.FeedItem.malware_family.isnot(None),
        models.FeedItem.malware_family != "Unknown"
    ).group_by(
        models.FeedItem.malware_family
    ).order_by(
        func.count(models.FeedItem.id).desc()
    ).limit(10).all()

    by_country = db.query(
        models.FeedItem.country,
        func.count(models.FeedItem.id)
    ).filter(
        models.FeedItem.country.isnot(None),
        models.FeedItem.country != ""
    ).group_by(
        models.FeedItem.country
    ).order_by(
        func.count(models.FeedItem.id).desc()
    ).limit(10).all()

    return {
        "total": total,
        "by_source": {s: c for s, c in by_source},
        "top_malware_families": [{"name": m, "count": c} for m, c in by_malware],
        "top_countries": [{"name": co, "count": c} for co, c in by_country],
    }


@router.get("/{feed_id}")
def get_feed_item(feed_id: int, db: Session = Depends(get_db)):
    item = db.query(models.FeedItem).filter(models.FeedItem.id == feed_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Feed item not found")

    return {
        "id": item.id,
        "source": item.source,
        "ioc_type": item.ioc_type,
        "ioc_value": item.ioc_value,
        "malware_family": item.malware_family,
        "country": item.country,
        "severity": item.severity,
        "tags": item.tags,
        "raw_data": json.loads(item.raw_data) if item.raw_data else {},
        "first_seen": item.first_seen,
        "created_at": item.created_at,
    }


@router.post("/{feed_id}/investigate")
async def investigate_feed_item(feed_id: int, db: Session = Depends(get_db)):
    item = db.query(models.FeedItem).filter(models.FeedItem.id == feed_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Feed item not found")

    ioc = item.ioc_value
    ioc_type = detect_ioc_type(ioc)

    if ioc_type == "unknown":
        # Fallback to stored ioc_type
        ioc_type = item.ioc_type if item.ioc_type in ("ip", "domain", "hash", "md5", "sha1", "sha256") else "ip"

    result = await investigate(ioc, ioc_type, db)
    return result

@router.post("/collect")
async def trigger_collection(db: Session = Depends(get_db)):
    """Manually trigger a feed collection — useful for testing."""
    try:
        from engines.feed_collector import collect_all_feeds
        count = await collect_all_feeds(db)
        return {"success": True, "new_items": count}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))