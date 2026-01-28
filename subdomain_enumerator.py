"""
Module 2 - Subdomain Enumeration for *.gov.in phishing detection
Uses multiple techniques: DNS, CT logs, WHOIS, subfinder
"""

import subprocess
import json
import asyncio
import aiohttp
import re
from typing import Set, List
import logging
from datetime import datetime
import requests

logger = logging.getLogger(__name__)


class SubdomainEnumerator:
    """Enumerate subdomains using multiple fast methods"""
    
    def __init__(self, domain: str = "gov.in"):
        self.domain = domain
        self.subdomains: Set[str] = set()
        self.timeout = 30
        
    async def enumerate_all(self) -> Set[str]:
        """Run all enumeration techniques in parallel"""
        tasks = [
            self._crtsh_enumeration(),
            self._dns_brute_common(),
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, set):
                self.subdomains.update(result)
            elif isinstance(result, Exception):
                logger.warning(f"Enumeration error: {result}")
        
        # Remove duplicates and sort
        self.subdomains = {s for s in self.subdomains if self.domain in s}
        logger.info(f"Total unique subdomains found: {len(self.subdomains)}")
        return self.subdomains
    
    async def _crtsh_enumeration(self) -> Set[str]:
        """Enumerate using Certificate Transparency logs (crt.sh)"""
        logger.info("Starting CT log enumeration...")
        subdomains = set()
        
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=self.timeout) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for entry in data:
                            # Extract domain names
                            names = entry.get('name_value', '').split('\n')
                            for name in names:
                                if self.domain in name:
                                    subdomains.add(name.strip())
            
            logger.info(f"CT logs found {len(subdomains)} domains")
        except Exception as e:
            logger.error(f"CT enumeration error: {e}")
        
        return subdomains
    
    async def _dns_brute_common(self) -> Set[str]:
        """DNS brute force with common subdomains"""
        logger.info("Starting DNS brute force enumeration...")
        subdomains = set()
        
        # Common gov.in subdomains
        common = [
            'www', 'mail', 'ftp', 'admin', 'api', 'test', 'dev',
            'portal', 'dashboard', 'login', 'auth', 'cdn', 'dns',
            'secure', 'ssl', 'vpn', 'mail', 'smtp', 'pop3', 'imap',
            'web', 'server', 'app', 'mobile', 'service', 'support',
            'help', 'download', 'upload', 'file', 'data', 'backup'
        ]
        
        try:
            async with aiohttp.ClientSession() as session:
                for subdomain in common:
                    full_domain = f"{subdomain}.{self.domain}"
                    try:
                        # Try to resolve DNS
                        async with session.head(
                            f"https://{full_domain}", 
                            timeout=5,
                            ssl=False,
                            allow_redirects=False
                        ) as resp:
                            subdomains.add(full_domain)
                            logger.debug(f"Found: {full_domain} (status: {resp.status})")
                    except Exception:
                        pass  # Domain doesn't exist
            
            logger.info(f"DNS brute found {len(subdomains)} domains")
        except Exception as e:
            logger.error(f"DNS brute error: {e}")
        
        return subdomains
    
    def get_results(self) -> List[str]:
        """Get enumerated subdomains as sorted list"""
        return sorted(list(self.subdomains))
