#backend\scheduler.py

import asyncio
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from database import SessionLocal


def _run_async(coro_func):
    """Helper to run an async function in a sync context."""
    db = SessionLocal()
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(coro_func(db))
        loop.close()
        return result
    except Exception as e:
        print(f"[Scheduler] Error: {e}")
    finally:
        db.close()


def collect_feeds_job():
    """Scheduled job to collect threat feeds."""
    from engines.feed_collector import collect_all_feeds
    print("[Scheduler] Running feed collection...")
    _run_async(collect_all_feeds)


def scrape_darkweb_job():
    """Scheduled job to scrape dark web gang sites."""
    from engines.dark_web_monitor import scrape_all_gangs
    print("[Scheduler] Running dark web scrape...")
    _run_async(scrape_all_gangs)


def monitor_pastes_job():
    """Scheduled job to monitor paste sites."""
    from engines.paste_monitor import monitor_pastes
    print("[Scheduler] Running paste monitor...")
    _run_async(monitor_pastes)


scheduler = BackgroundScheduler()

# Feed collection every 30 minutes
scheduler.add_job(
    collect_feeds_job,
    trigger=IntervalTrigger(minutes=30),
    id="collect_feeds",
    name="Collect Threat Feeds",
    replace_existing=True,
)

# Dark web scraping every 2 hours
scheduler.add_job(
    scrape_darkweb_job,
    trigger=IntervalTrigger(hours=2),
    id="scrape_darkweb",
    name="Scrape Dark Web",
    replace_existing=True,
)

# Paste monitoring every 30 minutes
scheduler.add_job(
    monitor_pastes_job,
    trigger=IntervalTrigger(minutes=30),
    id="monitor_pastes",
    name="Monitor Pastes",
    replace_existing=True,
)


def start_scheduler():
    """Start the APScheduler background scheduler."""
    if not scheduler.running:
        scheduler.start()
        print("[Scheduler] Started — feed collection every 30m, dark web every 2h, pastes every 30m")


def stop_scheduler():
    """Stop the scheduler gracefully."""
    if scheduler.running:
        scheduler.shutdown(wait=False)
        print("[Scheduler] Stopped")
