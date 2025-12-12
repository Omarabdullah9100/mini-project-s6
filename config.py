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
        # Google Search API Configuration
        api_keys_str = os.getenv("GOOGLE_API_KEYS", "")
        search_ids_str = os.getenv("GOOGLE_SEARCH_ENGINE_IDS", "")
        
        self.google_api_keys: List[str] = [k.strip() for k in api_keys_str.split(",") if k.strip()]
        self.google_search_engine_ids: List[str] = [s.strip() for s in search_ids_str.split(",") if s.strip()]
        self.current_api_index: int = 0
        
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


def get_next_api_key():
    """Rotate through available API keys for rate limiting"""
    settings.current_api_index = (settings.current_api_index + 1) % len(settings.google_api_keys)
    api_key = settings.google_api_keys[settings.current_api_index]
    search_engine_id = settings.google_search_engine_ids[settings.current_api_index]
    return api_key.strip(), search_engine_id.strip()
