# backend/engines/dark_web_monitor.py

import httpx
import json
from datetime import datetime, timezone
from sqlalchemy.orm import Session
import models


RANSOMWARE_LIVE_URL = "https://api.ransomware.live/recentvictims"


async def scrape_all_gangs(db: Session) -> int:
    """
    Fetches ransomware victim data from Ransomware.live public API.
    Deduplicates by victim_name + gang combo.
    Returns count of new victims added.
    """

    print("[DarkWebMonitor] Fetching from Ransomware.live API...")

    try:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            response = await client.get(RANSOMWARE_LIVE_URL, headers={"User-Agent": "ThreatHawk-CTI/1.0 (Academic Research)"})
            response.raise_for_status()
            data = response.json()
    except httpx.TimeoutException:
        print("[DarkWebMonitor] Request timed out")
        return 0
    except httpx.HTTPStatusError as e:
        print(f"[DarkWebMonitor] HTTP error: {e.response.status_code}")
        return 0
    except Exception as e:
        print(f"[DarkWebMonitor] Failed to fetch data: {e}")
        return 0

    if not isinstance(data, list):
        print("[DarkWebMonitor] Unexpected response format")
        return 0

    print(f"[DarkWebMonitor] Retrieved {len(data)} total victims from API")

    new_count = 0

    for entry in data:
        try:
            victim_name = (entry.get("post_title") or entry.get("victim") or entry.get("name") or entry.get("company") or "Unknown")
            gang = (entry.get("group_name") or entry.get("group") or entry.get("gang") or entry.get("threat_actor") or entry.get("ransomware_group") or "Unknown")
            country = entry.get("country") or None
            sector = entry.get("activity") or entry.get("sector") or None
            description = entry.get("description") or None
            website = entry.get("website") or None

            # Parse date
            date_posted = None
            raw_date = entry.get("published") or entry.get("date") or entry.get("discovered")
            if raw_date:
                try:
                    date_posted = datetime.fromisoformat(str(raw_date).replace("Z", "+00:00"))
                except (ValueError, TypeError):
                    try:
                        date_posted = datetime.strptime(str(raw_date)[:10], "%Y-%m-%d")
                    except Exception:
                        pass

            # Check for duplicates
            existing = db.query(models.DarkWebVictim).filter(
                models.DarkWebVictim.victim_name == victim_name,
                models.DarkWebVictim.gang == gang,
            ).first()

            if existing:
                continue

            victim = models.DarkWebVictim(
                gang=gang,
                victim_name=victim_name,
                country=country,
                sector=sector,
                data_volume=None,
                status="published",
                description=description,
                date_posted=date_posted,
                onion_url=website,
                created_at=datetime.now(timezone.utc),
            )
            db.add(victim)
            new_count += 1

        except Exception as e:
            print(f"[DarkWebMonitor] Error processing entry: {e}")
            continue

    if new_count > 0:
        db.commit()

    print(f"[DarkWebMonitor] Added {new_count} new victims")
    return new_count