"""
Configuration module for the Cybersecurity Detection Framework
"""
from typing import List, Dict
import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    """Application settings"""
    
    def __init__(self):
        # SerpAPI Configuration (replaces Google Custom Search API)
        self.serpapi_key: str = os.getenv("SERPAPI_KEY", "").strip()
        
        # Email Configuration
        self.smtp_server: str = os.getenv("SMTP_SERVER", "smtp.gmail.com")
        self.smtp_port: int = int(os.getenv("SMTP_PORT", "587"))
        self.smtp_email: str = os.getenv("SMTP_EMAIL", "")
        self.smtp_password: str = os.getenv("SMTP_PASSWORD", "")
        self.cert_in_email: str = os.getenv("CERT_IN_EMAIL", "vdisclose@cert-in.org.in")
        
        # Database Configuration
        self.database_url: str = os.getenv("DATABASE_URL", "sqlite:///./cybersecurity.db")
        
        # Application Settings
        self.debug: bool = os.getenv("DEBUG", "True").lower() == "true"
        self.host: str = os.getenv("HOST", "0.0.0.0")
        self.port: int = int(os.getenv("PORT", "8000"))
        
        # Sensitive Data Patterns
        self.patterns: Dict[str, str] = {
            "aadhaar": r"\b\d{4}\s?\d{4}\s?\d{4}\b",
            "pan": r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b",
            "bank_account": r"\b\d{9,18}\b",
            "voter_id": r"\b[A-Z]{3}[0-9]{7}\b",
            "passport": r"\b[A-Z]{1}[0-9]{7}\b"
        }
        
        # File Type Extensions
        self.supported_file_types: List[str] = ["pdf", "doc", "docx", "html", "log", "txt"]
        
        # Search Configuration
        self.max_results_per_query: int = 10
        self.max_retries: int = 3
        self.request_timeout: int = 30


# Global settings instance
settings = Settings()


def validate_api_config() -> dict:
    """Return a summary of the current SerpAPI configuration status."""
    configured = bool(settings.serpapi_key)

    return {
        "configured": configured,
        "api_keys_count": 1 if configured else 0,
        "search_engine_ids_count": 1 if configured else 0,
        "usable_pairs": 1 if configured else 0,
        "mismatched": False,
        "message": (
            "SerpAPI key configured and ready"
            if configured
            else "No SerpAPI key configured — set SERPAPI_KEY in .env"
        ),
    }
