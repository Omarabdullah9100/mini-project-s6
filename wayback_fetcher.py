"""
Module 2 - Wayback Machine URL Fetcher
Uses waybackurls CLI tool for fast historical URL retrieval
"""

import aiohttp
import asyncio
import subprocess
import logging
from typing import Set, List
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class WaybackFetcher:
    """Fetch URLs from Wayback Machine using waybackurls CLI tool"""
    
    def __init__(self, domain: str):
        self.domain = domain
        self.urls: Set[str] = set()
        self.timeout = 30
    
    async def fetch_urls(self) -> Set[str]:
        """Fetch all captured URLs from Wayback Machine using waybackurls CLI"""
        logger.info(f"Fetching URLs from Wayback Machine for {self.domain} using waybackurls...")
        
        try:
            # Run waybackurls CLI tool
            result = subprocess.run(
                ['waybackurls', self.domain],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    url = line.strip()
                    if url and self.domain in url:
                        self.urls.add(url)
                
                logger.info(f"waybackurls found {len(self.urls)} URLs and endpoints")
            else:
                logger.error(f"waybackurls failed: {result.stderr}")
        
        except FileNotFoundError:
            logger.error("❌ waybackurls CLI not installed. Please install it first.")
            raise Exception("waybackurls CLI tool not found. Install from: https://github.com/tomnomnom/waybackurls/releases")
        except subprocess.TimeoutExpired:
            logger.error("waybackurls timeout")
            raise Exception("waybackurls tool timed out")
        except Exception as e:
            logger.error(f"waybackurls error: {e}")
            raise
        
        return self.urls
    
    def get_urls(self) -> List[str]:
        """Get fetched URLs as sorted list"""
        return sorted(list(self.urls))
    
    def get_unique_domains(self) -> Set[str]:
        """Extract unique domains from fetched URLs"""
        domains = set()
        for url in self.urls:
            try:
                parsed = urlparse(url)
                domain = parsed.netloc
                if domain:
                    domains.add(domain)
            except Exception:
                pass
        return domains
