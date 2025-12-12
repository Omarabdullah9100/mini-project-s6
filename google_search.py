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
        results = []
        attempts = 0
        
        while attempts < self.max_retries:
            try:
                # Get next API key and search engine ID
                api_key, search_engine_id = get_next_api_key()
                
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
                        results.append({
                            "title": item.get("title", ""),
                            "link": item.get("link", ""),
                            "snippet": item.get("snippet", ""),
                            "file_format": item.get("fileFormat", ""),
                            "mime": item.get("mime", "")
                        })
                
                logger.info(f"✅ Found {len(results)} results")
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
        
        # Mapping of data types to search keywords
        keywords_map = {
            "aadhaar": ["aadhaar", "aadhar", "uid", "uidai"],
            "pan": ["pan card", "pan number", "permanent account"],
            "bank_account": ["bank account", "account number", "ifsc"],
            "voter_id": ["voter id", "epic", "election card"],
            "passport": ["passport", "passport number"],
            "salary": ["salary slip", "pay slip", "salary details"]
        }
        
        for data_type in data_types:
            if data_type in keywords_map:
                for keyword in keywords_map[data_type]:
                    # Generate query for each file type
                    for file_type in ["pdf", "doc", "docx"]:
                        query = f'site:{domain} ext:{file_type} "{keyword}"'
                        queries.append({
                            "query": query,
                            "data_type": data_type,
                            "file_type": file_type
                        })
        
        logger.info(f"📋 Generated {len(queries)} dorking queries")
        return queries
