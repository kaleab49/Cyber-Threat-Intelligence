from django.core.management.base import BaseCommand

from threatintel.services.feed_ingest import ingest_cisa_kev, ingest_urlhaus_recent, scrape_ioc_page


class Command(BaseCommand):
    help = "Ingest URLhaus + CISA KEV, with optional IOC web scraping."

    def add_arguments(self, parser):
        parser.add_argument("--urlhaus-limit", type=int, default=100)
        parser.add_argument("--kev-limit", type=int, default=100)
        parser.add_argument(
            "--scrape-url",
            action="append",
            default=[],
            help="Repeatable URL(s) to scrape for IOC text.",
        )
        parser.add_argument("--scrape-limit", type=int, default=500)

    def handle(self, *args, **options):
        result = {
            "urlhaus": ingest_urlhaus_recent(limit=options["urlhaus_limit"]),
            "cisa_kev": ingest_cisa_kev(limit=options["kev_limit"]),
            "scraped": [],
        }

        for url in options["scrape_url"]:
            scrape_result = scrape_ioc_page(
                url=url,
                source="web-scrape",
                limit=options["scrape_limit"],
            )
            result["scraped"].append(scrape_result)

        self.stdout.write(self.style.SUCCESS(str(result)))
