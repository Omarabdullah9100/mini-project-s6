"""
Google Search API integration module — powered by SerpAPI
"""
from serpapi import GoogleSearch
from config import settings
import time
import logging
from typing import Optional, Callable

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
                            all_results.append({
                                "title": item.get("title", ""),
                                "link": url,
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

    def generate_dork_queries(self, data_types: list, domain: str = "gov.in"):
        """
        Generate Google dorking queries for sensitive data detection
        
        Args:
            data_types: List of data types to search for (aadhaar, pan, etc.)
            domain: Target domain (default: gov.in)
        
        Returns:
            List of dorking queries
        """
        queries = []
        
        # Mapping of data types to specific dork queries
        dork_queries = {
            "aadhaar": [
                f'site:gov.in ext:pdf "Aadhaar card no"'
                ],
            
            "pan": [
                f'site:{domain} ext:pdf "Pan Card no"'
            ],
           
            "voter_id": [
                f'site:{domain} ext:pdf "Voter ID no"',
                f'site:{domain} ext:pdf "EPIC no."'
            ],
            "passport": [
                f'site:{domain} ext:pdf "Passport No"'
            ]
        }
        
        for data_type in data_types:
            if data_type in dork_queries:
                for dork in dork_queries[data_type]:
                    queries.append({
                        "query": dork,
                        "data_type": data_type,
                        "file_type": "pdf"
                    })
        
        logger.info(f"📋 Generated {len(queries)} dorking queries")
        return queries
