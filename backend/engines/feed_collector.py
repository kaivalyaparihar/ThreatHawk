#backend\engines\feed_collector.py

import asyncio
import json
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from integrations.malwarebazaar import fetch_malwarebazaar
from integrations.urlhaus import fetch_urlhaus
from integrations.threatfox import fetch_threatfox
from integrations.feodotracker import fetch_feodotracker
import models


async def collect_all_feeds(db: Session) -> int:
    """
    Runs all 4 feed fetchers concurrently, normalises to FeedItem schema,
    deduplicates by ioc_value, and inserts new items.
    Returns count of new items inserted.
    """

    # Run all fetchers concurrently
    results = await asyncio.gather(
        fetch_malwarebazaar(),
        fetch_urlhaus(),
        fetch_threatfox(),
        fetch_feodotracker(),
        return_exceptions=True
    )

    all_items = []
    for result in results:
        if isinstance(result, Exception):
            print(f"[FeedCollector] Feed error: {result}")
            continue
        all_items.extend(result)

    if not all_items:
        return 0

    # Deduplicate within this batch
    seen = set()
    unique_items = []
    for item in all_items:
        key = item.get("ioc_value", "")
        if key and key not in seen:
            seen.add(key)
            unique_items.append(item)

    # Check existing IOC values in DB to avoid duplicates
    existing_values = set()
    batch_values = [item["ioc_value"] for item in unique_items if item.get("ioc_value")]
    if batch_values:
        # Query in chunks to avoid SQL limits
        for i in range(0, len(batch_values), 500):
            chunk = batch_values[i:i+500]
            existing = db.query(models.FeedItem.ioc_value).filter(
                models.FeedItem.ioc_value.in_(chunk)
            ).all()
            existing_values.update(v[0] for v in existing)

    # Insert new items
    new_count = 0
    for item in unique_items:
        if item["ioc_value"] in existing_values:
            continue

        first_seen = None
        if item.get("first_seen"):
            try:
                first_seen = datetime.fromisoformat(str(item["first_seen"]).replace("Z", "+00:00"))
            except (ValueError, TypeError):
                try:
                    first_seen = datetime.strptime(str(item["first_seen"]), "%Y-%m-%d %H:%M:%S")
                except (ValueError, TypeError):
                    first_seen = None

        feed_item = models.FeedItem(
            source=item.get("source", "unknown"),
            ioc_type=item.get("ioc_type", "unknown"),
            ioc_value=item.get("ioc_value", ""),
            malware_family=item.get("malware_family"),
            country=item.get("country"),
            severity=item.get("severity", "Medium"),
            tags=item.get("tags"),
            raw_data=json.dumps(item.get("raw_data", {}), default=str),
            first_seen=first_seen,
            created_at=datetime.now(timezone.utc),
        )
        db.add(feed_item)
        new_count += 1

    if new_count > 0:
        db.commit()

    print(f"[FeedCollector] Inserted {new_count} new feed items")
    return new_count
