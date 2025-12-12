"""
Pattern matching and sensitive data detection module
"""
import re
from typing import Dict, List, Tuple
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SensitiveDataDetector:
    """Detect sensitive data patterns in text"""
    
    def __init__(self):
        # Regex patterns for different data types
        # Aadhaar: Requires "Aadhaar Card No" or similar prefix followed by 12 digits (with or without spaces)
        # This ensures we match actual Aadhaar card numbers in context, not just random 12-digit numbers
        self.patterns = {
            "aadhaar": r"(?i)(aadhaar\s+card\s+no\.?|aadhar\s+card\s+no\.?|aadhaar\s+number|enrollment\s+number)\s*[:\-]?\s*(\d{4}\s?\d{4}\s?\d{4}|\d{12})",
            "pan": r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b",
            "bank_account": r"\b\d{9,18}\b",
            "voter_id": r"\b[A-Z]{3}[0-9]{7}\b",
            "passport": r"\b[A-Z]{1}[0-9]{7}\b"
        }
        
        # Context keywords to improve detection accuracy
        self.context_keywords = {
            "aadhaar": ["aadhaar", "aadhar", "uid", "uidai", "enrollment", "card no"],
            "pan": ["pan", "permanent account", "income tax"],
            "bank_account": ["account", "bank", "ifsc", "account number"],
            "voter_id": ["voter", "epic", "election"],
            "passport": ["passport", "travel document"]
        }
    
    def detect_all(self, text: str, selected_types: List[str] = None) -> Dict[str, List[Dict]]:
        """
        Detect specific types of sensitive data in text
        
        Args:
            text: Text to scan
            selected_types: List of data types to detect. If None, detect all types
        
        Returns:
            Dictionary with data_type as key and list of detections
        """
        results = {}
        
        # Use selected_types if provided, otherwise scan all patterns
        types_to_scan = selected_types if selected_types else list(self.patterns.keys())
        
        for data_type in types_to_scan:
            if data_type in self.patterns:
                detections = self.detect_pattern(text, data_type)
                if detections:
                    results[data_type] = detections
        
        return results
    
    def detect_pattern(self, text: str, data_type: str) -> List[Dict]:
        """
        Detect specific pattern in text with validation
        
        Returns:
            List of detection dictionaries with match, confidence, context
        """
        if data_type not in self.patterns:
            logger.warning(f"⚠️ Unknown data type: {data_type}")
            return []
        
        pattern = self.patterns[data_type]
        matches = re.finditer(pattern, text, re.MULTILINE | re.IGNORECASE)
        
        detections = []
        seen_numbers = set()  # Track unique numbers to avoid duplicates
        
        for match in matches:
            matched_text = match.group()
            
            # For Aadhaar, extract the actual number for duplicate checking
            if data_type == "aadhaar":
                numbers = re.findall(r'\d+', matched_text)
                clean_number = ''.join(numbers) if numbers else ""
                
                # Skip if we've already detected this number
                if clean_number in seen_numbers:
                    continue
                
                if clean_number:
                    seen_numbers.add(clean_number)
            
            # Validate the match
            is_valid, confidence = self._validate_match(matched_text, data_type, text, match.start())
            
            if is_valid:
                # Extract context (80 characters before and after)
                start = max(0, match.start() - 80)
                end = min(len(text), match.end() + 80)
                context = text[start:end].replace('\n', ' ')
                
                detections.append({
                    "match": self._anonymize(matched_text, data_type),
                    "confidence": confidence,
                    "context": context,
                    "position": match.start()
                })
        
        if detections:
            logger.info(f"🔍 Detected {len(detections)} {data_type} instances (avg confidence: {sum(d['confidence'] for d in detections)/len(detections):.1f}%)")
        
        return detections
    
    def _validate_match(self, matched_text: str, data_type: str, full_text: str, position: int) -> Tuple[bool, float]:
        """
        Validate matched pattern and calculate confidence score
        
        Returns:
            Tuple of (is_valid, confidence_score)
        """
        confidence = 50.0  # Base confidence
        
        # Extract surrounding context
        start = max(0, position - 100)
        end = min(len(full_text), position + len(matched_text) + 100)
        context = full_text[start:end].lower()
        
        # Check for context keywords
        keywords_found = sum(1 for keyword in self.context_keywords.get(data_type, []) 
                           if keyword.lower() in context)
        
        if keywords_found > 0:
            confidence += keywords_found * 15  # +15% per keyword
        
        # Type-specific validation
        if data_type == "aadhaar":
            aadhaar_score = self._validate_aadhaar(matched_text)
            if aadhaar_score == 0.0:  # Validation failed (e.g., masked number)
                return False, 0.0
            confidence += aadhaar_score
        elif data_type == "pan":
            confidence += self._validate_pan(matched_text)
        elif data_type == "bank_account":
            confidence += self._validate_bank_account(matched_text, context)
        
        # Cap confidence at 100
        confidence = min(confidence, 100.0)
        
        # Consider valid if confidence >= 60%
        is_valid = confidence >= 60.0
        
        return is_valid, confidence
    
    def _validate_aadhaar(self, matched_text: str) -> float:
        """
        Validate Aadhaar number with enhanced checks:
        1. Extract actual number (with or without spaces)
        2. Reject masked numbers (XXXX XXXX 1234)
        3. Validate checksum
        4. Ensure number portion exists
        """
        # Extract the numeric part from the match
        numbers = re.findall(r'\d+', matched_text)
        
        if not numbers:
            return 0.0  # No numbers found, reject
        
        # Combine all numbers (handles both spaced and non-spaced formats)
        clean_number = ''.join(numbers)
        
        # Must be exactly 12 digits
        if len(clean_number) != 12:
            return 0.0
        
        # Check if it's a masked number (contains or appears as XXXX XXXX XXXX pattern)
        if 'x' in matched_text.lower() or matched_text.count('X') > 0:
            logger.info(f"⚠️ Masked Aadhaar detected, rejecting: {matched_text}")
            return 0.0  # Reject masked numbers
        
        # Check if all digits are the same (invalid Aadhaar)
        if len(set(clean_number)) == 1:
            return 0.0  # All same digits, invalid
        
        # Verhoeff checksum validation
        try:
            if self._verhoeff_checksum(clean_number):
                logger.info(f"✅ Valid Aadhaar checksum: {clean_number[-4:]}...")
                return 35.0  # +35% for valid checksum
        except Exception as e:
            logger.debug(f"Checksum validation error: {e}")
            pass
        
        return 15.0  # +15% for correct length and format (without checksum validation)
    
    def _verhoeff_checksum(self, number: str) -> bool:
        """Verhoeff algorithm for Aadhaar validation"""
        # Verhoeff multiplication table
        d = [
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
            [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
            [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
            [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
            [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
            [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
            [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
            [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
            [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
        ]
        
        # Permutation table
        p = [
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
            [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
            [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
            [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
            [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
            [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
            [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]
        ]
        
        # Inverse table
        inv = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]
        
        c = 0
        for i, digit in enumerate(reversed(number)):
            c = d[c][p[(i % 8)][int(digit)]]
        
        return c == 0
    
    def _validate_pan(self, pan: str) -> float:
        """Validate PAN card format"""
        # PAN format: AAAAA9999A
        # First 3: Alphabetic series (AAA)
        # 4th: Type of holder (C, P, H, F, A, T, B, L, J, G)
        # 5th: First character of last name/surname
        # Next 4: Sequential number (0001-9999)
        # Last: Check digit (alphabetic)
        
        if len(pan) != 10:
            return 0.0
        
        # Check 4th character (entity type)
        valid_types = ['C', 'P', 'H', 'F', 'A', 'T', 'B', 'L', 'J', 'G']
        if pan[3] in valid_types:
            return 20.0  # +20% for valid format
        
        return 10.0  # +10% for correct length
    
    def _validate_bank_account(self, number: str, context: str) -> float:
        """Validate bank account number"""
        # Check for IFSC code in context
        ifsc_pattern = r'\b[A-Z]{4}0[A-Z0-9]{6}\b'
        if re.search(ifsc_pattern, context):
            return 25.0  # +25% if IFSC code found nearby
        
        # Check for banking keywords
        bank_keywords = ['bank', 'account', 'ifsc', 'savings', 'current']
        keywords_found = sum(1 for keyword in bank_keywords if keyword in context)
        
        return keywords_found * 5.0  # +5% per banking keyword
    
    def _anonymize(self, text: str, data_type: str) -> str:
        """Anonymize sensitive data for evidence storage"""
        # Extract only numbers for Aadhaar
        if data_type == "aadhaar":
            numbers = re.findall(r'\d+', text)
            clean_text = ''.join(numbers)
            if len(clean_text) >= 4:
                # Show only last 4 digits: XXXX XXXX 1234
                return f"XXXX XXXX {clean_text[-4:]}"
            return "AADHAAR_DETECTED"
        
        clean_text = re.sub(r'[\s-]', '', text)
        
        if data_type == "pan":
            # Show only first and last character: AXXXX9999X
            if len(text) >= 5:
                return f"{text[0]}XXXX{text[5:9]}{text[-1]}"
            return "PAN_DETECTED"
        elif data_type == "bank_account":
            # Show only last 4 digits
            if len(clean_text) >= 4:
                return f"XXXXXX{clean_text[-4:]}"
            return "ACCOUNT_DETECTED"
        else:
            # Default: show last 4 characters
            if len(text) >= 4:
                return f"XXX...{text[-4:]}"
            return f"XXX...{text}"
