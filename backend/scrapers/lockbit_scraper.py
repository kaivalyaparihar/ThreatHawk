#backend\scrapers\lockbit_scraper.py

import json
import os
from scrapers.base_scraper import BaseScraper


class LockBitScraper(BaseScraper):
    def __init__(self):
        config_path = os.path.join(os.path.dirname(__file__), "..", "config", "gang_urls.json")
        with open(config_path) as f:
            config = json.load(f)
        gang = config.get("lockbit", {})
        super().__init__("LockBit", gang.get("onion_url", ""))

    def get_victims(self) -> list:
        """Parse LockBit leak site for victim entries."""
        soup = self.scrape()
        if not soup:
            return []

        victims = []
        try:
            # LockBit typically lists victims in post/card elements
            for entry in soup.find_all(["div", "article", "li"], class_=True):
                text = entry.get_text(strip=True)
                if len(text) < 10:
                    continue

                # Try to extract structured data
                victim = {
                    "gang": "LockBit",
                    "victim_name": text[:100].split("\n")[0].strip(),
                    "country": None,
                    "sector": None,
                    "data_volume": None,
                    "status": "unknown",
                    "description": text[:500],
                    "date_posted": None,
                }

                # Look for links
                link = entry.find("a")
                if link and link.get("href"):
                    victim["onion_url"] = link["href"]

                victims.append(victim)

        except Exception as e:
            print(f"[LockBit] Parse error: {e}")

        return victims[:50]
