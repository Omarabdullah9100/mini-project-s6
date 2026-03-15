"""
Module 2 - Government Impersonation Detection System (GIDS)
Detects websites impersonating Indian government sites using Google Dorks
"""

import asyncio
import json
import logging
from typing import List, Dict, Optional, Callable
from google_search import GoogleSearchAPI

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class GovernmentImersonationDetector:
    """Detect government impersonation websites using Google dorks"""
    
    def __init__(self):
        self.google_search = GoogleSearchAPI()
        self.impersonation_patterns = {
            "aadhaar_login": {
                "dork": 'intitle:"aadhaar login" -site:gov.in',
                "keywords": ["aadhaar", "login", "uid", "id verification", "government"],
                "indicators": ["aadhaar", "resident", "uid", "enrolment", "identity", "authentication"],
                "risk_level": "CRITICAL"
            },
            "pan_verification": {
                "dork": 'intitle:"pan verification" OR intitle:"pan card" -site:gov.in',
                "keywords": ["pan", "verification", "tax", "income tax", "pan card"],
                "indicators": ["pan", "permanent account number", "tax", "india revenue", "verification"],
                "risk_level": "CRITICAL"
            },
            "voter_registration": {
                "dork": 'intitle:"voter registration" OR intitle:"voter id" -site:gov.in',
                "keywords": ["voter", "election", "registration", "voter id"],
                "indicators": ["voter", "election commission", "electoral", "registration", "constituency"],
                "risk_level": "HIGH"
            },
            "passport_services": {
                "dork": 'intitle:"passport" intitle:"apply" -site:gov.in -site:passport.gov.in',
                "keywords": ["passport", "apply", "renewal", "india"],
                "indicators": ["passport", "application", "renewal", "visa", "foreign ministry"],
                "risk_level": "HIGH"
            },
            "license_services": {
                "dork": 'intitle:"driving license" OR intitle:"dl apply" -site:gov.in -site:sarthi.parivahan.gov.in',
                "keywords": ["driving license", "dl", "road transport"],
                "indicators": ["license", "driving", "rto", "vehicle", "learner"],
                "risk_level": "HIGH"
            }
        }
    
    async def scan_for_impersonation(
        self,
        selected_types: List[str] = None,
        should_stop: Optional[Callable[[], bool]] = None
    ) -> Dict:
        """
        Scan the web for government impersonation sites
        
        Args:
            selected_types: List of impersonation types to check
        
        Returns:
            Dictionary with scan results
        """
        if not selected_types:
            selected_types = list(self.impersonation_patterns.keys())
        
        all_findings = []
        seen_finding_keys = set()
        total_queries = 0
        
        for impersonation_type in selected_types:
            if should_stop and should_stop():
                logger.info("⏹️ GIDS scan cancellation detected. Stopping further type scans.")
                break

            if impersonation_type not in self.impersonation_patterns:
                logger.warning(f"Unknown impersonation type: {impersonation_type}")
                continue
            
            config = self.impersonation_patterns[impersonation_type]
            dork = config["dork"]
            
            logger.info(f"Scanning {impersonation_type} with dork: {dork}")
            
            try:
                # Execute Google search with dork
                results = self.google_search.search(
                    query=dork,
                    num_results=10,
                    max_pages=3,  # 30 results per type
                    should_stop=should_stop
                )
                
                total_queries += 1
                
                for result in results:
                    if should_stop and should_stop():
                        logger.info("⏹️ GIDS scan cancellation detected while analyzing results.")
                        break

                    finding = self._analyze_result(
                        result,
                        impersonation_type,
                        config
                    )
                    if finding:
                        finding_key = (finding.get("domain", "").lower(), finding.get("impersonation_type", ""))
                        if finding_key in seen_finding_keys:
                            continue
                        seen_finding_keys.add(finding_key)
                        all_findings.append(finding)
            
            except Exception as e:
                logger.error(f"Error scanning {impersonation_type}: {e}")
                continue
        
        # Calculate risk breakdown
        critical_count = len([f for f in all_findings if f["risk_level"] == "CRITICAL"])
        high_count = len([f for f in all_findings if f["risk_level"] == "HIGH"])
        medium_count = len([f for f in all_findings if f["risk_level"] == "MEDIUM"])
        low_count = len([f for f in all_findings if f["risk_level"] == "LOW"])
        
        return {
            "scan_id": None,  # Will be set by main.py
            "total_findings": len(all_findings),
            "total_queries": total_queries,
            "risk_breakdown": {
                "CRITICAL": critical_count,
                "HIGH": high_count,
                "MEDIUM": medium_count,
                "LOW": low_count
            },
            "findings": all_findings
        }
    
    def _analyze_result(self, result: Dict, impersonation_type: str, config: Dict) -> Dict:
        """
        Analyze a search result for government impersonation indicators
        
        Args:
            result: Google search result
            impersonation_type: Type of government site being impersonated
            config: Configuration for this impersonation type
        
        Returns:
            Finding dictionary or None
        """
        try:
            url = result.get("link", "")
            title = result.get("title", "")
            snippet = result.get("snippet", "")
            
            if not url:
                return None
            
            # Combine text to search
            combined_text = f"{title} {snippet}".lower()
            
            # Count indicators found
            indicators_found = []
            for indicator in config.get("indicators", []):
                if indicator.lower() in combined_text:
                    indicators_found.append(indicator)
            
            # If no indicators found, skip
            if not indicators_found:
                return None
            
            # Check if URL contains legitimate gov.in domain
            is_legitimate_gov = "gov.in" in url.lower()
            
            # Calculate confidence based on indicators
            confidence = len(indicators_found) * 18  # 18% per indicator
            
            # Determine risk level
            if len(indicators_found) >= 3:
                risk_level = "CRITICAL"
                confidence = min(100, confidence + 25)
            elif len(indicators_found) >= 2:
                risk_level = "HIGH"
                confidence = min(100, confidence + 15)
            else:
                risk_level = "MEDIUM"
            
            # If it's actually a gov.in domain, lower the risk
            if is_legitimate_gov:
                risk_level = "LOW"
                confidence = max(0, confidence - 30)
            
            # Extract domain from URL
            import urllib.parse
            parsed_url = urllib.parse.urlparse(url)
            domain = parsed_url.netloc
            
            finding = {
                "url": url,
                "domain": domain,
                "title": title[:80],
                "snippet": snippet[:120],
                "impersonation_type": impersonation_type.replace("_", " ").title(),
                "indicators": indicators_found,
                "risk_level": risk_level,
                "confidence": min(100, int(confidence)),
                "is_legitimate_gov": is_legitimate_gov,
                "threat_details": self._generate_threat_details(impersonation_type, indicators_found, domain)
            }
            
            return finding
        
        except Exception as e:
            logger.error(f"Error analyzing result: {e}")
            return None
    
    def _generate_threat_details(self, impersonation_type: str, indicators: List[str], domain: str) -> str:
        """Generate detailed threat information"""
        threat_detail = f"Domain '{domain}' impersonating {impersonation_type.replace('_', ' ')}. "
        threat_detail += f"Detected indicators: {', '.join(indicators)}. "
        threat_detail += "This domain may be used to steal sensitive government credentials."
        return threat_detail
    
    def get_dorks(self) -> Dict[str, str]:
        """Get all dorks for impersonation detection"""
        dorks = {}
        for imp_type, config in self.impersonation_patterns.items():
            dorks[imp_type] = config["dork"]
        return dorks
