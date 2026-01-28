"""
Module 2 - Phishing Detector
Analyzes domains for phishing indicators:
1. Redirect chains to unknown domains
2. SSL/HTTPS issues
3. Content analysis (expected vs actual)
4. Typosquatting detection
"""

import aiohttp
import asyncio
import ssl
import logging
from typing import Dict, List, Tuple, Optional
from urllib.parse import urlparse
import re
from datetime import datetime
import certifi
from difflib import SequenceMatcher

logger = logging.getLogger(__name__)


class PhishingDetector:
    """Detect phishing indicators in domains"""
    
    def __init__(self, domain: str = "gov.in"):
        self.domain = domain
        self.timeout = 10
        self.results: List[Dict] = []
        
        # Expected government domain patterns
        self.legit_patterns = [
            r'(login|portal|dashboard|admin|auth)',
            r'(service|application|system)',
            r'(official|gov|ministry|department)',
        ]
        
        # Phishing domain patterns
        self.phishing_patterns = [
            r'(trading|trade|forex|crypto|bitcoin)',
            r'(betting|gamble|casino|lottery|lotto)',
            r'(porn|adult|xxx|sex)',
            r'(bank|financial|investment|stock)',
            r'(fake|spam|scam|malware)',
            r'(-verify|-confirm|-secure|-update|-login)',
        ]
    
    async def scan_domain(self, domain_url: str) -> Dict:
        """Comprehensive phishing scan for single domain"""
        logger.info(f"Scanning: {domain_url}")
        
        result = {
            'domain': domain_url,
            'timestamp': datetime.now().isoformat(),
            'phishing_score': 0,
            'phishing_percentage': 0,
            'indicators': [],
            'risk_level': 'LOW',
            'details': {}
        }
        
        try:
            # Check SSL/HTTPS
            ssl_check = await self._check_ssl(domain_url)
            result['details']['ssl'] = ssl_check
            if not ssl_check['valid']:
                result['indicators'].append('Invalid or missing SSL certificate')
                result['phishing_score'] += 30
            
            # Check if HTTP (not HTTPS)
            if domain_url.startswith('http://'):
                result['indicators'].append('Using unencrypted HTTP instead of HTTPS')
                result['phishing_score'] += 25
            
            # Check redirect chains
            redirects = await self._check_redirects(domain_url)
            result['details']['redirects'] = redirects
            if redirects['has_suspicious_redirect']:
                result['indicators'].append(f"Redirects to external domain: {redirects['final_domain']}")
                result['phishing_score'] += 35
            
            # Check content
            content_check = await self._analyze_content(domain_url)
            result['details']['content'] = content_check
            if content_check['suspicious_keywords']:
                result['indicators'].append(f"Suspicious content: {', '.join(content_check['suspicious_keywords'])}")
                result['phishing_score'] += 30
            
            # Check typosquatting
            typo_score = self._check_typosquatting(domain_url)
            result['details']['typosquatting_score'] = typo_score
            if typo_score > 0.7:  # High similarity
                result['indicators'].append('Possible typosquatting domain')
                result['phishing_score'] += 20
            
            # Normalize score to 0-100
            result['phishing_score'] = min(result['phishing_score'], 100)
            result['phishing_percentage'] = result['phishing_score']
            
            # Determine risk level
            if result['phishing_score'] >= 70:
                result['risk_level'] = 'CRITICAL'
            elif result['phishing_score'] >= 50:
                result['risk_level'] = 'HIGH'
            elif result['phishing_score'] >= 30:
                result['risk_level'] = 'MEDIUM'
            else:
                result['risk_level'] = 'LOW'
            
            self.results.append(result)
            logger.info(f"Score for {domain_url}: {result['phishing_percentage']}% ({result['risk_level']})")
            
        except Exception as e:
            logger.error(f"Error scanning {domain_url}: {e}")
            result['error'] = str(e)
            result['phishing_score'] = 0
        
        return result
    
    async def _check_ssl(self, domain_url: str) -> Dict:
        """Check SSL certificate validity"""
        result = {
            'valid': False,
            'certificate_info': None,
            'error': None
        }
        
        try:
            parsed = urlparse(domain_url)
            hostname = parsed.netloc
            
            # Create SSL context
            context = ssl.create_default_context(cafile=certifi.where())
            
            # Try to connect and get certificate
            try:
                with asyncio.timeout(self.timeout):
                    import socket
                    with socket.create_connection((hostname, 443), timeout=5) as sock:
                        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            cert = ssock.getpeercert()
                            result['valid'] = True
                            result['certificate_info'] = {
                                'subject': dict(x[0] for x in cert.get('subject', [])),
                                'issuer': dict(x[0] for x in cert.get('issuer', []))
                            }
            except ssl.SSLError as e:
                result['error'] = str(e)
                result['valid'] = False
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    async def _check_redirects(self, domain_url: str) -> Dict:
        """Check for suspicious redirect chains"""
        result = {
            'redirect_chain': [],
            'final_domain': None,
            'has_suspicious_redirect': False,
            'total_redirects': 0
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.head(
                    domain_url,
                    allow_redirects=False,
                    timeout=self.timeout,
                    ssl=False
                ) as resp:
                    result['redirect_chain'].append((domain_url, resp.status))
                    
                    # Follow redirects manually
                    current_url = domain_url
                    redirect_count = 0
                    
                    while resp.status in (301, 302, 303, 307, 308) and redirect_count < 5:
                        redirect_url = resp.headers.get('Location', '')
                        if not redirect_url:
                            break
                        
                        # Make absolute URL
                        if redirect_url.startswith('/'):
                            parsed = urlparse(current_url)
                            redirect_url = f"{parsed.scheme}://{parsed.netloc}{redirect_url}"
                        
                        current_url = redirect_url
                        result['redirect_chain'].append(redirect_url)
                        redirect_count += 1
                        
                        try:
                            async with session.head(
                                redirect_url,
                                allow_redirects=False,
                                timeout=self.timeout,
                                ssl=False
                            ) as resp2:
                                resp = resp2
                        except Exception:
                            break
                    
                    result['final_domain'] = current_url
                    result['total_redirects'] = redirect_count
                    
                    # Check if redirects to different domain
                    orig_domain = urlparse(domain_url).netloc
                    final_domain = urlparse(current_url).netloc
                    
                    if orig_domain != final_domain and 'gov.in' not in final_domain:
                        result['has_suspicious_redirect'] = True
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    async def _analyze_content(self, domain_url: str) -> Dict:
        """Analyze page content for phishing indicators"""
        result = {
            'suspicious_keywords': [],
            'expected_keywords': [],
            'content_type': None
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    domain_url,
                    timeout=self.timeout,
                    ssl=False,
                    allow_redirects=True
                ) as resp:
                    result['content_type'] = resp.headers.get('Content-Type', '')
                    
                    if resp.status == 200:
                        content = await resp.text()
                        content_lower = content.lower()
                        
                        # Check for phishing keywords
                        for pattern in self.phishing_patterns:
                            if re.search(pattern, content_lower):
                                match = re.search(pattern, content_lower)
                                result['suspicious_keywords'].append(match.group(0))
                        
                        # Check for expected government content
                        for pattern in self.legit_patterns:
                            if re.search(pattern, content_lower):
                                match = re.search(pattern, content_lower)
                                result['expected_keywords'].append(match.group(0))
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _check_typosquatting(self, domain_url: str) -> float:
        """Check similarity to legitimate gov.in domains"""
        parsed = urlparse(domain_url)
        domain = parsed.netloc
        
        # Common legitimate gov.in subdomains
        legitimate = [
            'www.gov.in',
            'portal.gov.in',
            'service.gov.in',
            'login.gov.in',
            'secure.gov.in'
        ]
        
        # Calculate similarity score (0-1)
        max_similarity = 0
        for legit in legitimate:
            similarity = SequenceMatcher(None, domain, legit).ratio()
            max_similarity = max(max_similarity, similarity)
        
        return max_similarity
    
    def get_results(self) -> List[Dict]:
        """Get all scan results"""
        return sorted(
            self.results,
            key=lambda x: x['phishing_percentage'],
            reverse=True
        )
    
    def get_critical_findings(self) -> List[Dict]:
        """Get only critical and high-risk domains"""
        return [r for r in self.results if r['risk_level'] in ['CRITICAL', 'HIGH']]
