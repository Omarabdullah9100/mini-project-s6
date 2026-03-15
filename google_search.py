"""
Google Search API integration module — powered by SerpAPI
"""
from serpapi import GoogleSearch
from config import settings
import time
import logging
from typing import Optional, Callable
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class GoogleSearchAPI:
    """SerpAPI-backed Google Search wrapper (drop-in replacement)"""

    def __init__(self):
        self.max_retries = settings.max_retries
        self.api_key = settings.serpapi_key

    def search(
        self,
        query: str,
        num_results: int = 10,
        file_type: str = None,
        max_pages: int = 10,
        should_stop: Optional[Callable[[], bool]] = None,
    ):
        """
        Execute Google search via SerpAPI with pagination support.

        Dork queries are passed directly — SerpAPI handles all Google
        search operators (site:, intitle:, ext:, etc.) natively.

        Args:
            query: Search query (including any Google dork operators)
            num_results: Number of results per page (max 10 per request)
            file_type: Optional file type filter (pdf, doc, docx, etc.)
            max_pages: Maximum number of pages to fetch (default 10 = 100 results)

        Returns:
            List of search results with URLs and metadata
        """
        if not self.api_key:
            logger.error("❌ SERPAPI_KEY not configured. Set it in .env")
            return []

        # Build the search query
        search_query = query
        if file_type:
            search_query += f" ext:{file_type}"

        all_results = []
        seen_urls = set()

        for page in range(max_pages):
            if should_stop and should_stop():
                logger.info("⏹️ Search cancelled before next page request")
                return all_results

            attempts = 0
            page_success = False

            while attempts < self.max_retries and not page_success:
                if should_stop and should_stop():
                    logger.info("⏹️ Search cancelled during retry loop")
                    return all_results

                try:
                    start_index = page * 10

                    logger.info(
                        f"Executing SerpAPI search (page {page + 1}/{max_pages}): "
                        f"{search_query} [start: {start_index}]"
                    )

                    params = {
                        "engine": "google",
                        "q": search_query,
                        "google_domain": "google.com",
                        "hl": "en",
                        "gl": "us",
                        "num": min(num_results, 10),
                        "start": start_index,
                        "api_key": self.api_key,
                    }

                    search_obj = GoogleSearch(params)
                    response = search_obj.get_dict()

                    # Check for SerpAPI-level errors
                    if "error" in response:
                        raise RuntimeError(response["error"])

                    organic = response.get("organic_results", [])

                    if not organic:
                        logger.info(f"⚠️ Page {page + 1}: No more results available")
                        return all_results

                    for item in organic:
                        url = item.get("link", "")
                        if url:
                            normalized_url = self._normalize_url(url)
                            if normalized_url in seen_urls:
                                continue
                            seen_urls.add(normalized_url)
                            all_results.append({
                                "title": item.get("title", ""),
                                "link": normalized_url,
                                "snippet": item.get("snippet", ""),
                                "file_format": item.get("file_format", ""),
                                "mime": item.get("mime", ""),
                            })

                    logger.info(
                        f"✅ Page {page + 1}: Found {len(organic)} results "
                        f"(Total: {len(all_results)})"
                    )
                    page_success = True

                except Exception as e:
                    attempts += 1
                    logger.warning(
                        f"⚠️ SerpAPI error on page {page + 1} "
                        f"(attempt {attempts}/{self.max_retries}): {e}"
                    )
                    if attempts < self.max_retries:
                        time.sleep(2 ** attempts)  # Exponential backoff
                    else:
                        logger.error(
                            f"❌ Failed after {self.max_retries} attempts on page {page + 1}"
                        )
                        return all_results

        logger.info(f"✅ Search completed. Total results: {len(all_results)}")
        return all_results

    def _normalize_url(self, url: str) -> str:
        """Normalize URLs for stable deduplication across search pages."""
        try:
            parsed = urlparse(url.strip())

            # Remove tracking query params while preserving meaningful ones.
            tracking_keys = {
                "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
                "gclid", "fbclid", "ref", "source"
            }
            filtered_query = [
                (k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True)
                if k.lower() not in tracking_keys
            ]

            normalized = parsed._replace(
                scheme=(parsed.scheme or "https").lower(),
                netloc=parsed.netloc.lower(),
                query=urlencode(filtered_query, doseq=True),
                fragment=""
            )
            return urlunparse(normalized).rstrip("/")
        except Exception:
            return (url or "").strip().rstrip("/")

    def generate_dork_queries(self, data_types: list, domain: str = "gov.in", file_types: Optional[list] = None):
        """
        Generate Google dorking queries for sensitive data detection
        
        Args:
            data_types: List of data types to search for (aadhaar, pan, etc.)
            domain: Target domain (default: gov.in)
        
        Returns:
            List of dorking queries
        """
        queries = []
        safe_domain = (domain or "gov.in").strip() or "gov.in"
        selected_file_types = [
            str(file_type).strip().lower()
            for file_type in (file_types or ["pdf"])
            if str(file_type).strip()
        ]
        if not selected_file_types:
            selected_file_types = ["pdf"]
        
        # Mapping of data types to specific dork queries
        dork_queries = {
            "aadhaar": [
                f'site:{safe_domain} "Aadhaar card no"',
                f'site:{safe_domain} "Aadhaar number"',
            ],
            
            "pan": [
                f'site:{safe_domain} "Pan Card no"',
                f'site:{safe_domain} "Permanent Account Number"',
            ],
           
            "voter_id": [
                f'site:{safe_domain} "Voter ID no"',
                f'site:{safe_domain} "EPIC no."'
            ],
            "passport": [
                f'site:{safe_domain} "Passport No"',
                f'site:{safe_domain} "Passport number"',
            ]
        }
        
        for data_type in data_types:
            if data_type in dork_queries:
                for dork in dork_queries[data_type]:
                    for file_type in selected_file_types:
                        queries.append({
                            "query": dork,
                            "data_type": data_type,
                            "file_type": file_type
                        })
        
        logger.info(f"📋 Generated {len(queries)} dorking queries")
        return queries
