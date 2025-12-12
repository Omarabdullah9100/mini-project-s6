"""
Document processing and text extraction module
"""
import os
import re
import requests
from io import BytesIO
from typing import Dict, List, Tuple
import logging

# PDF processing
from pdfminer.high_level import extract_text as pdf_extract_text

# DOCX processing
from docx import Document as DocxDocument

# HTML processing
from bs4 import BeautifulSoup

# Image processing (OCR)
from PIL import Image
import pytesseract

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DocumentProcessor:
    """Process and extract text from various document formats"""
    
    def __init__(self, download_dir: str = "./downloads"):
        self.download_dir = download_dir
        os.makedirs(download_dir, exist_ok=True)
    
    def download_file(self, url: str) -> Tuple[bytes, str]:
        """
        Download file from URL
        
        Returns:
            Tuple of (file_content, file_extension)
        """
        try:
            logger.info(f"📥 Downloading: {url}")
            response = requests.get(url, timeout=30, verify=False)
            response.raise_for_status()
            
            # Determine file extension
            content_type = response.headers.get('content-type', '').lower()
            ext = self._get_extension_from_content_type(content_type, url)
            
            logger.info(f"✅ Downloaded {len(response.content)} bytes ({ext})")
            return response.content, ext
            
        except Exception as e:
            logger.error(f"❌ Download failed: {str(e)}")
            raise
    
    def _get_extension_from_content_type(self, content_type: str, url: str) -> str:
        """Determine file extension from content type or URL"""
        ext_map = {
            'application/pdf': 'pdf',
            'application/msword': 'doc',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'docx',
            'text/html': 'html',
            'text/plain': 'txt'
        }
        
        for ct, ext in ext_map.items():
            if ct in content_type:
                return ext
        
        # Fallback to URL extension
        if '.' in url:
            return url.split('.')[-1].lower()
        
        return 'unknown'
    
    def extract_text(self, file_content: bytes, file_extension: str) -> str:
        """
        Extract text from file based on extension
        
        Args:
            file_content: Binary file content
            file_extension: File extension (pdf, doc, docx, html, txt)
        
        Returns:
            Extracted text content
        """
        try:
            if file_extension == 'pdf':
                return self._extract_from_pdf(file_content)
            elif file_extension in ['doc', 'docx']:
                return self._extract_from_docx(file_content)
            elif file_extension == 'html':
                return self._extract_from_html(file_content)
            elif file_extension in ['txt', 'log']:
                return file_content.decode('utf-8', errors='ignore')
            else:
                logger.warning(f"⚠️ Unsupported file type: {file_extension}")
                return ""
                
        except Exception as e:
            logger.error(f"❌ Text extraction failed: {str(e)}")
            return ""
    
    def _extract_from_pdf(self, file_content: bytes) -> str:
        """Extract text from PDF"""
        try:
            text = pdf_extract_text(BytesIO(file_content))
            logger.info(f"✅ Extracted {len(text)} characters from PDF")
            return text
        except Exception as e:
            logger.error(f"❌ PDF extraction error: {str(e)}")
            # Try OCR as fallback
            return self._ocr_fallback(file_content)
    
    def _extract_from_docx(self, file_content: bytes) -> str:
        """Extract text from DOCX"""
        try:
            doc = DocxDocument(BytesIO(file_content))
            text = '\n'.join([paragraph.text for paragraph in doc.paragraphs])
            logger.info(f"✅ Extracted {len(text)} characters from DOCX")
            return text
        except Exception as e:
            logger.error(f"❌ DOCX extraction error: {str(e)}")
            return ""
    
    def _extract_from_html(self, file_content: bytes) -> str:
        """Extract text from HTML"""
        try:
            soup = BeautifulSoup(file_content, 'html.parser')
            
            # Remove script and style elements
            for script in soup(["script", "style"]):
                script.decompose()
            
            text = soup.get_text(separator=' ', strip=True)
            logger.info(f"✅ Extracted {len(text)} characters from HTML")
            return text
        except Exception as e:
            logger.error(f"❌ HTML extraction error: {str(e)}")
            return ""
    
    def _ocr_fallback(self, file_content: bytes) -> str:
        """OCR fallback for image-based PDFs"""
        try:
            logger.info("🔍 Attempting OCR extraction...")
            image = Image.open(BytesIO(file_content))
            text = pytesseract.image_to_string(image)
            logger.info(f"✅ OCR extracted {len(text)} characters")
            return text
        except Exception as e:
            logger.error(f"❌ OCR failed: {str(e)}")
            return ""
