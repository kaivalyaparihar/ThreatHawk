#backend\scrapers\ransomhub_scraper.py

import json
import os
from scrapers.base_scraper import BaseScraper


class RansomHubScraper(BaseScraper):
    def __init__(self):
        config_path = os.path.join(os.path.dirname(__file__), "..", "config", "gang_urls.json")
        with open(config_path) as f:
            config = json.load(f)
        gang = config.get("ransomhub", {})
        super().__init__("RansomHub", gang.get("onion_url", ""))

    def get_victims(self) -> list:
        soup = self.scrape()
        if not soup:
            return []

        victims = []
        try:
            for entry in soup.find_all(["div", "article", "li"], class_=True):
                text = entry.get_text(strip=True)
                if len(text) < 10:
                    continue
                victim = {
                    "gang": "RansomHub",
                    "victim_name": text[:100].split("\n")[0].strip(),
                    "country": None,
                    "sector": None,
                    "data_volume": None,
                    "status": "unknown",
                    "description": text[:500],
                    "date_posted": None,
                }
                link = entry.find("a")
                if link and link.get("href"):
                    victim["onion_url"] = link["href"]
                victims.append(victim)
        except Exception as e:
            print(f"[RansomHub] Parse error: {e}")

        return victims[:50]
