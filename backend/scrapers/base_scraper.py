#backend\scrapers\base_scraper.py

import time
from bs4 import BeautifulSoup
from utils.tor_controller import get_tor_session, is_tor_running


class BaseScraper:
    """Base scraper that uses Tor to access .onion sites."""

    def __init__(self, gang_name: str, onion_url: str):
        self.gang_name = gang_name
        self.onion_url = onion_url
        self.max_retries = 3
        self.retry_delay = 5
        self.timeout = 30

    def scrape(self, url: str = None):
        """
        GET request through Tor, returns BeautifulSoup object.
        Retry logic: 3 attempts with 5 second delay.
        Returns None on failure — never raises exceptions.
        """
        target_url = url or self.onion_url

        if not is_tor_running():
            print(f"[{self.gang_name}] Tor not running — skipping scrape")
            return None

        for attempt in range(1, self.max_retries + 1):
            try:
                session = get_tor_session()
                response = session.get(target_url, timeout=self.timeout)
                response.raise_for_status()
                return BeautifulSoup(response.text, "html.parser")
            except Exception as e:
                print(f"[{self.gang_name}] Attempt {attempt}/{self.max_retries} failed: {e}")
                if attempt < self.max_retries:
                    time.sleep(self.retry_delay)

        print(f"[{self.gang_name}] All {self.max_retries} attempts failed")
        return None

    def get_victims(self) -> list:
        """Override in subclass to parse victim data."""
        return []
