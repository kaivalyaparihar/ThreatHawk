#backend\scrapers\clop_scraper.py

import json
import os
from scrapers.base_scraper import BaseScraper


class ClopScraper(BaseScraper):
    def __init__(self):
        config_path = os.path.join(os.path.dirname(__file__), "..", "config", "gang_urls.json")
        with open(config_path) as f:
            config = json.load(f)
        gang = config.get("clop", {})
        super().__init__("Cl0p", gang.get("onion_url", ""))

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
                    "gang": "Cl0p",
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
            print(f"[Cl0p] Parse error: {e}")

        return victims[:50]
