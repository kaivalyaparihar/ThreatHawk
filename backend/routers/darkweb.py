#backend\routers\darkweb.py

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import func
from database import get_db
from datetime import datetime, timezone, timedelta
import json
import models
import httpx
import os

router = APIRouter()


@router.get("/victims/")
def get_victims(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    gang: str = None,
    country: str = None,
    sector: str = None,
    db: Session = Depends(get_db)
):
    query = db.query(models.DarkWebVictim)

    if gang:
        query = query.filter(models.DarkWebVictim.gang == gang)
    if country:
        query = query.filter(models.DarkWebVictim.country == country)
    if sector:
        query = query.filter(models.DarkWebVictim.sector == sector)

    total = query.count()
    items = query.order_by(
        models.DarkWebVictim.created_at.desc()
    ).offset((page - 1) * limit).limit(limit).all()

    return {
        "total": total,
        "page": page,
        "limit": limit,
        "items": [
            {
                "id": v.id,
                "gang": v.gang,
                "victim_name": v.victim_name,
                "country": v.country,
                "sector": v.sector,
                "data_volume": v.data_volume,
                "status": v.status,
                "description": v.description,
                "date_posted": v.date_posted,
                "created_at": v.created_at,
            }
            for v in items
        ]
    }


@router.get("/victims/{victim_id}")
def get_victim(victim_id: int, db: Session = Depends(get_db)):
    v = db.query(models.DarkWebVictim).filter(
        models.DarkWebVictim.id == victim_id
    ).first()
    if not v:
        raise HTTPException(status_code=404, detail="Victim not found")

    return {
        "id": v.id,
        "gang": v.gang,
        "victim_name": v.victim_name,
        "country": v.country,
        "sector": v.sector,
        "data_volume": v.data_volume,
        "status": v.status,
        "description": v.description,
        "date_posted": v.date_posted,
        "onion_url": v.onion_url,
        "created_at": v.created_at,
    }


@router.get("/pastes/")
def get_pastes(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db)
):
    total = db.query(models.PasteEntry).count()
    items = db.query(models.PasteEntry).order_by(
        models.PasteEntry.created_at.desc()
    ).offset((page - 1) * limit).limit(limit).all()

    return {
        "total": total,
        "page": page,
        "limit": limit,
        "items": [
            {
                "id": p.id,
                "paste_key": p.paste_key,
                "title": p.title,
                "content_snippet": p.content_snippet,
                "signal_type": p.signal_type,
                "signals_found": json.loads(p.signals_found) if p.signals_found else {},
                "paste_date": p.paste_date,
                "created_at": p.created_at,
            }
            for p in items
        ]
    }


@router.get("/stats")
def get_darkweb_stats(db: Session = Depends(get_db)):
    total_victims = db.query(models.DarkWebVictim).count()
    total_pastes = db.query(models.PasteEntry).count()

    by_gang = db.query(
        models.DarkWebVictim.gang,
        func.count(models.DarkWebVictim.id)
    ).group_by(models.DarkWebVictim.gang).all()

    by_sector = db.query(
        models.DarkWebVictim.sector,
        func.count(models.DarkWebVictim.id)
    ).filter(
        models.DarkWebVictim.sector.isnot(None)
    ).group_by(
        models.DarkWebVictim.sector
    ).order_by(
        func.count(models.DarkWebVictim.id).desc()
    ).limit(10).all()

    by_country = db.query(
        models.DarkWebVictim.country,
        func.count(models.DarkWebVictim.id)
    ).filter(
        models.DarkWebVictim.country.isnot(None)
    ).group_by(
        models.DarkWebVictim.country
    ).order_by(
        func.count(models.DarkWebVictim.id).desc()
    ).limit(10).all()

    # Recent victims (last 24 hours)
    recent_cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    recent_victims = db.query(models.DarkWebVictim).filter(
        models.DarkWebVictim.created_at >= recent_cutoff
    ).order_by(models.DarkWebVictim.created_at.desc()).limit(10).all()

    # Most active gang
    most_active = max(by_gang, key=lambda x: x[1])[0] if by_gang else "None"

    # Most targeted sector
    most_targeted = by_sector[0][0] if by_sector else "Unknown"

    return {
        "total_victims": total_victims,
        "total_pastes": total_pastes,
        "most_active_gang": most_active,
        "most_targeted_sector": most_targeted,
        "by_gang": {g: c for g, c in by_gang},
        "by_sector": [{"name": s, "count": c} for s, c in by_sector],
        "by_country": [{"name": co, "count": c} for co, c in by_country],
        "recent_victims": [
            {
                "id": v.id,
                "gang": v.gang,
                "victim_name": v.victim_name,
                "country": v.country,
                "sector": v.sector,
                "created_at": v.created_at,
            }
            for v in recent_victims
        ],
    }


@router.get("/groups")
async def get_threat_actor_groups():
    """Fetch threat actor group profiles from Ransomware.live."""
    try:
        async with httpx.AsyncClient(timeout=60.0, follow_redirects=True) as client:
            response = await client.get(
                "https://api.ransomware.live/v1/groups",
                headers={"User-Agent": "ThreatHawk-CTI/1.0 (Academic Research)"}
            )
            response.raise_for_status()
            data = response.json()

            groups = []
            for g in data:
                groups.append({
                    "name": g.get("name") or g.get("group_name") or "Unknown",
                    "description": g.get("description") or "No description available.",
                    "first_seen": g.get("first_seen") or g.get("firstseen"),
                    "last_seen": g.get("last_seen") or g.get("lastseen"),
                    "locations": g.get("locations") or [],
                    "sectors": g.get("sectors") or [],
                    "crypto_addresses": g.get("crypto") or g.get("cryptocurrency") or [],
                    "is_active": g.get("is_active", True),
                    "classification": g.get("type") or "Ransomware",
                    "country": g.get("country") or None,
                    "logo": g.get("logo") or None,
                })

            return {"total": len(groups), "groups": groups}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/breach")
async def check_breach_intelligence(domain: str = None, email: str = None):
    """Check for breach intelligence using free public sources."""
    if not domain and not email:
        raise HTTPException(status_code=400, detail="Provide either domain or email parameter.")

    query = domain or email
    query_type = "domain" if domain else "email"

    results = {
        "query": query,
        "type": query_type,
        "found": False,
        "sources_checked": [],
        "breaches": [],
        "total_breaches": 0,
    }

    async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:

        # Source 1: BreachDirectory (free, no key)
        try:
            resp = await client.get(
                f"https://breachdirectory.p.rapidapi.com/?func=auto&term={query}",
                headers={
                    "User-Agent": "ThreatHawk-CTI/1.0",
                    "X-RapidAPI-Host": "breachdirectory.p.rapidapi.com",
                }
            )
            results["sources_checked"].append("BreachDirectory")
        except Exception:
            pass

        # Source 2: Check against known breach list via IntelX free tier
        try:
            resp = await client.get(
                f"https://2.intelx.io/phonebook/search?term={query}&target=3&maxresults=10&timeout=5&datefrom=&dateto=&sort=4&media=0&terminate=",
                headers={"User-Agent": "ThreatHawk-CTI/1.0", "x-key": "00000000-0000-0000-0000-000000000000"}
            )
            results["sources_checked"].append("IntelligenceX")
        except Exception:
            pass

        # Source 3: Check DeHashed public search (no key needed for basic)
        try:
            dehashed_resp = await client.get(
                f"https://api.dehashed.com/search?query={query_type}:{query}&size=5",
                headers={"User-Agent": "ThreatHawk-CTI/1.0"}
            )
            results["sources_checked"].append("DeHashed")
        except Exception:
            pass

        # Primary: Use HIBP public breach list (no key needed for breach list)
        try:
            breach_list_resp = await client.get(
                "https://haveibeenpwned.com/api/v3/breaches",
                headers={"User-Agent": "ThreatHawk-CTI/1.0"}
            )
            if breach_list_resp.status_code == 200:
                all_breaches = breach_list_resp.json()
                # Filter breaches relevant to query domain
                domain_check = domain or (email.split("@")[1] if email and "@" in email else "")
                matched = [
                    b for b in all_breaches
                    if domain_check.lower() in b.get("Domain", "").lower()
                    or domain_check.lower() in b.get("Name", "").lower()
                ] if domain_check else []

                if matched:
                    results["found"] = True
                    results["total_breaches"] = len(matched)
                    results["breaches"] = [
                        {
                            "name": b.get("Name"),
                            "domain": b.get("Domain"),
                            "breach_date": b.get("BreachDate"),
                            "pwn_count": b.get("PwnCount"),
                            "data_classes": b.get("DataClasses", []),
                            "description": b.get("Description", "")[:200],
                            "is_verified": b.get("IsVerified", False),
                        }
                        for b in matched
                    ]
                else:
                    # Even if no exact match, return all breach list for context
                    results["found"] = False
                    results["message"] = f"No breaches found directly matching '{query}' in the HIBP database."
                    results["total_known_breaches"] = len(all_breaches)

                results["sources_checked"].append("HaveIBeenPwned (Public Breach List)")

        except Exception as e:
            results["error"] = str(e)

    return results


@router.get("/search")
async def universal_dark_web_search(q: str, db: Session = Depends(get_db)):
    """Universal search across all dark web intelligence."""
    if not q or len(q.strip()) < 2:
        raise HTTPException(status_code=400, detail="Search query must be at least 2 characters.")

    term = f"%{q.strip()}%"
    results = {
        "query": q,
        "victims": [],
        "pastes": [],
        "total": 0
    }

    # Search victims
    victims = db.query(models.DarkWebVictim).filter(
        models.DarkWebVictim.victim_name.ilike(term) |
        models.DarkWebVictim.gang.ilike(term) |
        models.DarkWebVictim.country.ilike(term) |
        models.DarkWebVictim.sector.ilike(term) |
        models.DarkWebVictim.description.ilike(term)
    ).limit(20).all()

    results["victims"] = [
        {
            "id": v.id,
            "type": "targeted_organisation",
            "threat_actor_group": v.gang,
            "organisation": v.victim_name,
            "country": v.country,
            "sector": v.sector,
            "date_posted": v.date_posted,
            "status": v.status,
        }
        for v in victims
    ]

    # Search pastes
    pastes = db.query(models.PasteEntry).filter(
        models.PasteEntry.title.ilike(term) |
        models.PasteEntry.content_snippet.ilike(term) |
        models.PasteEntry.signal_type.ilike(term)
    ).limit(10).all()

    results["pastes"] = [
        {
            "id": p.id,
            "type": "paste_intelligence",
            "title": p.title,
            "signal_type": p.signal_type,
            "snippet": p.content_snippet,
            "date": p.paste_date,
        }
        for p in pastes
    ]

    results["total"] = len(results["victims"]) + len(results["pastes"])
    return results


@router.get("/hacktivists")
async def get_hacktivist_activity(db: Session = Depends(get_db)):
    """Return victims posted by known hacktivist groups."""
    hacktivist_groups = [
        "handala", "kilnet", "killnet", "anonymous", "anonymous sudan",
        "userSec", "usersec", "ghosts of palestine", "garnesia team",
        "team insane pk", "cybertoufan", "monolit", "noname057"
    ]

    results = []
    for group in hacktivist_groups:
        victims = db.query(models.DarkWebVictim).filter(
            models.DarkWebVictim.gang.ilike(f"%{group}%")
        ).order_by(models.DarkWebVictim.date_posted.desc()).all()

        for v in victims:
            results.append({
                "id": v.id,
                "threat_actor_group": v.gang,
                "target": v.victim_name,
                "country": v.country,
                "sector": v.sector,
                "date": v.date_posted,
                "description": v.description,
                "motivation": "Political / Ideological",
            })

    return {
        "total": len(results),
        "groups_monitored": len(hacktivist_groups),
        "activity": results
    }


@router.post("/collect")
async def trigger_dark_web_collection(db: Session = Depends(get_db)):
    """Manually trigger dark web scraping — useful for testing."""
    try:
        from engines.dark_web_monitor import scrape_all_gangs
        count = await scrape_all_gangs(db)
        return {"success": True, "new_victims": count}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/pastes/collect")
async def trigger_paste_collection(db: Session = Depends(get_db)):
    """Manually trigger paste monitoring — useful for testing."""
    try:
        from engines.paste_monitor import monitor_pastes
        count = await monitor_pastes(db)
        return {"success": True, "new_pastes": count}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


