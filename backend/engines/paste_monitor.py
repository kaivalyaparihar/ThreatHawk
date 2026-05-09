#backend\engines\paste_monitor.py

import re
import json
import httpx
from datetime import datetime, timezone
from sqlalchemy.orm import Session
import models


# Signal patterns
PATTERNS = {
    "credential": re.compile(r'[\w.\-]+@[\w\-]+\.[\w.]+:[\S]+'),
    "aws_key": re.compile(r'AKIA[0-9A-Z]{16}'),
    "github_token": re.compile(r'ghp_[a-zA-Z0-9]{36}'),
    "sha256_hash": re.compile(r'\b[a-fA-F0-9]{64}\b'),
    "api_key": re.compile(r'(?:api[_-]?key|apikey|secret)["\s:=]+["\']?([a-zA-Z0-9]{20,})', re.IGNORECASE),
}


async def monitor_pastes(db: Session) -> int:
    """
    Monitors Pastebin scraping API for intelligence signals.
    Returns count of new paste entries added.
    """

    scrape_url = "https://scrape.pastebin.com/api_scraping.php?limit=100"
    content_url = "https://scrape.pastebin.com/api_scrape_item.php?i="

    new_count = 0

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            # Fetch recent pastes list
            response = await client.get(scrape_url)

            if response.status_code == 403:
                print("[PasteMonitor] Pastebin scraping API requires whitelisted IP — skipping")
                return 0

            if response.status_code != 200:
                print(f"[PasteMonitor] API returned {response.status_code}")
                return 0

            try:
                pastes = response.json()
            except Exception:
                print("[PasteMonitor] Invalid JSON response")
                return 0

            if not isinstance(pastes, list):
                return 0

            for paste in pastes[:50]:
                paste_key = paste.get("key", "")

                if not paste_key:
                    continue

                # Check if already processed
                existing = db.query(models.PasteEntry).filter(
                    models.PasteEntry.paste_key == paste_key
                ).first()
                if existing:
                    continue

                # Fetch paste content
                try:
                    content_response = await client.get(f"{content_url}{paste_key}")
                    if content_response.status_code != 200:
                        continue
                    content = content_response.text[:10000]  # Limit content size
                except Exception:
                    continue

                # Apply signal patterns
                signals_found = {}
                signal_type = None

                for pattern_name, pattern in PATTERNS.items():
                    matches = pattern.findall(content)
                    if matches:
                        signals_found[pattern_name] = matches[:5]
                        if not signal_type:
                            signal_type = pattern_name

                # Only save if signals were found
                if not signals_found:
                    continue

                # Parse paste date
                paste_date = None
                if paste.get("date"):
                    try:
                        paste_date = datetime.fromtimestamp(
                            int(paste["date"]), tz=timezone.utc
                        )
                    except (ValueError, TypeError):
                        pass

                entry = models.PasteEntry(
                    paste_key=paste_key,
                    title=paste.get("title", "Untitled")[:200],
                    content_snippet=content[:500],
                    signal_type=signal_type,
                    signals_found=json.dumps(signals_found),
                    paste_date=paste_date,
                    created_at=datetime.now(timezone.utc),
                )
                db.add(entry)
                new_count += 1

    except httpx.TimeoutException:
        print("[PasteMonitor] Request timed out")
    except Exception as e:
        print(f"[PasteMonitor] Error: {e}")

    if new_count > 0:
        db.commit()

    print(f"[PasteMonitor] Added {new_count} new paste entries")
    return new_count
