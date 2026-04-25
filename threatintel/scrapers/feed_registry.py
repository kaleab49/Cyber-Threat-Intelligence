from threatintel.scrapers.threat_feed_scraper import fetch_threat_feed
from threatintel.scrapers.pastebin_scraper import fetch_pastebin
from threatintel.scrapers.twitter_scraper import fetch_twitter
from threatintel.scrapers.malwarebazaar_api import fetch_malwarebazaar
from threatintel.scrapers.darkweb_scraper import fetch_darkweb


FEEDS = {
    "threat_feed": fetch_threat_feed,
    "pastebin": fetch_pastebin,
    "twitter": fetch_twitter,
    "malwarebazaar": fetch_malwarebazaar,
    "darkweb": fetch_darkweb,
}