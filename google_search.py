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
    
    def search(self, query: str, num_results: int = 10, file_type: str = None):
        """
        Execute Google search with dorking query
        
        Args:
            query: Search query
            num_results: Number of results to return (max 10 per request)
            file_type: Optional file type filter (pdf, doc, docx, etc.)
        
        Returns:
            List of search results with URLs and metadata
        """
        # Check if API keys are configured
        if not settings.google_api_keys or not settings.google_search_engine_ids:
            logger.error("❌ No Google API keys configured. Please set GOOGLE_API_KEYS and GOOGLE_SEARCH_ENGINE_IDS in .env file")
            return []
        
        results = []
        attempts = 0
        
        while attempts < self.max_retries:
            try:
                # Get next API key and search engine ID
                api_key, search_engine_id = get_next_api_key()
                
                if not api_key or not search_engine_id:
                    logger.error("❌ Invalid API key or search engine ID")
                    return []
                
                # Build search query
                search_query = query
                if file_type:
                    search_query += f" ext:{file_type}"
                
                logger.info(f"Executing search: {search_query}")
                
                # Build the service
                service = build("customsearch", "v1", developerKey=api_key)
                
                # Execute search
                response = service.cse().list(
                    q=search_query,
                    cx=search_engine_id,
                    num=min(num_results, 10)
                ).execute()
                
                # Extract results
                if "items" in response:
                    for item in response["items"]:
                        url = item.get("link", "")
                        # Validate URL is not empty
                        if url:
                            results.append({
                                "title": item.get("title", ""),
                                "link": url,
                                "snippet": item.get("snippet", ""),
                                "file_format": item.get("fileFormat", ""),
                                "mime": item.get("mime", "")
                            })
                
                logger.info(f"✅ Found {len(results)} valid results")
                return results
                
            except HttpError as e:
                attempts += 1
                logger.warning(f"⚠️ API Error (attempt {attempts}/{self.max_retries}): {str(e)}")
                
                if attempts < self.max_retries:
                    time.sleep(2 ** attempts)  # Exponential backoff
                else:
                    logger.error(f"❌ Failed after {self.max_retries} attempts")
                    raise
                    
            except Exception as e:
                logger.error(f"❌ Unexpected error: {str(e)}")
                raise
        
        return results
    
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
                f'site:{domain} ext:pdf "Aadhaar Card No" -site:uidai.gov.in',
                f'site:{domain} ext:pdf "Aadhaar Number" -site:uidai.gov.in',
                f'site:{domain} ext:pdf "Aadhaar No" -site:uidai.gov.in'
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
