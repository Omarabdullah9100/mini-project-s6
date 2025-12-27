"""
Google Search API integration module
"""
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from config import settings, get_next_api_key
import time
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class GoogleSearchAPI:
    """Google Custom Search API wrapper"""
    
    def __init__(self):
        self.max_retries = settings.max_retries
        self.retry_count = 0
    
    def search(self, query: str, num_results: int = 10, file_type: str = None, max_pages: int = 10):
        """
        Execute Google search with pagination support
        
        Args:
            query: Search query
            num_results: Number of results per page (max 10 per request)
            file_type: Optional file type filter (pdf, doc, docx, etc.)
            max_pages: Maximum number of pages to fetch (default 10 = 100 results)
        
        Returns:
            List of search results with URLs and metadata
        """
        # Check if API keys are configured
        if not settings.google_api_keys or not settings.google_search_engine_ids:
            logger.error("❌ No Google API keys configured. Please set GOOGLE_API_KEYS and GOOGLE_SEARCH_ENGINE_IDS in .env file")
            return []
        
        all_results = []
        
        # Paginate through results
        for page in range(max_pages):
            attempts = 0
            page_success = False
            
            while attempts < self.max_retries and not page_success:
                try:
                    # Get next API key and search engine ID (rotate for rate limiting)
                    api_key, search_engine_id = get_next_api_key()
                    
                    if not api_key or not search_engine_id:
                        logger.error("❌ Invalid API key or search engine ID")
                        return all_results if all_results else []
                    
                    # Build search query
                    search_query = query
                    if file_type:
                        search_query += f" ext:{file_type}"
                    
                    # Calculate start index for pagination (1-based)
                    start_index = (page * 10) + 1
                    
                    logger.info(f"Executing search (page {page + 1}/{max_pages}): {search_query} [startIndex: {start_index}]")
                    
                    # Build the service
                    service = build("customsearch", "v1", developerKey=api_key)
                    
                    # Execute search with pagination
                    response = service.cse().list(
                        q=search_query,
                        cx=search_engine_id,
                        num=min(num_results, 10),  # Google allows max 10 per request
                        start=start_index
                    ).execute()
                    
                    # Extract results
                    if "items" in response:
                        for item in response["items"]:
                            url = item.get("link", "")
                            # Validate URL is not empty
                            if url:
                                all_results.append({
                                    "title": item.get("title", ""),
                                    "link": url,
                                    "snippet": item.get("snippet", ""),
                                    "file_format": item.get("fileFormat", ""),
                                    "mime": item.get("mime", "")
                                })
                        
                        logger.info(f"✅ Page {page + 1}: Found {len(response['items'])} results (Total: {len(all_results)})")
                        page_success = True
                    else:
                        # No more results available
                        logger.info(f"⚠️ Page {page + 1}: No more results available")
                        return all_results
                    
                except HttpError as e:
                    attempts += 1
                    logger.warning(f"⚠️ API Error on page {page + 1} (attempt {attempts}/{self.max_retries}): {str(e)}")
                    
                    if attempts < self.max_retries:
                        time.sleep(2 ** attempts)  # Exponential backoff
                    else:
                        logger.error(f"❌ Failed after {self.max_retries} attempts on page {page + 1}")
                        return all_results  # Return partial results collected so far
                        
                except Exception as e:
                    logger.error(f"❌ Unexpected error on page {page + 1}: {str(e)}")
                    return all_results  # Return partial results collected so far
        
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
                f'site:{domain} ext:pdf "Aadhaar Card No" -site:uidai.gov.in -site:styandptg.py.gov.in -site:mhc.tn.gov.in -site:goaprintingpress.gov.in  -inurl:gazette',
                f'site:{domain} ext:pdf "Aadhaar Number" -site:uidai.gov.in -site:styandptg.py.gov.in -site:mhc.tn.gov.in -site:goaprintingpress.gov.in  -inurl:gazette',
                f'site:{domain} ext:pdf "Aadhaar No" -site:uidai.gov.in -site:styandptg.py.gov.in -site:mhc.tn.gov.in -site:goaprintingpress.gov.in  -inurl:gazette'
                ],
            
            "pan": [
                f'site:{domain} ext:pdf "Pan Card"',
                f'site:{domain} ext:pdf "Permanent Account Number"'
            ],
            "bank_account": [
                f'site:{domain} ext:pdf "Account Number" "IFSC"',
                f'site:{domain} ext:pdf "Bank Account"'
            ],
            "voter_id": [
                f'site:{domain} ext:pdf "Voter ID"',
                f'site:{domain} ext:pdf "EPIC Number"'
            ],
            "passport": [
                f'site:{domain} ext:pdf "Passport Number"'
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
