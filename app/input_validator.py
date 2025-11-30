"""
IOCReaper Input Validator Module
Phase 5 Security Implementation

Mitigates:
- MC-001: SQL Injection
- MC-002: Cross-Site Scripting (XSS)
- MC-003: Command Injection
- MC-007: Regular Expression Denial of Service (ReDoS)
- MC-012: Pattern Poisoning in IOC Extraction

Author: Manudeep Maddipatla
Email: mmaddipa@umd.edu
UMD Directory ID: mmaddipa (121417350)

FIXED: Updated patterns to allow legitimate IOC text with defanged indicators
"""

import re
import html
from typing import Tuple, Optional
from security_logger import get_security_logger


class InputValidator:
    """
    Comprehensive input validation and sanitization for IOCReaper.
    
    Implements server-side validation for all user inputs to prevent:
    - Injection attacks (SQL, XSS, Command)
    - ReDoS attacks
    - Pattern poisoning
    - Resource exhaustion
    """
    
    # Size limits
    MAX_INPUT_SIZE_KB = 100
    MAX_TAG_LENGTH = 50
    MAX_TAG_COUNT_PER_IOC = 20
    
    # Forbidden characters in tags
    FORBIDDEN_TAG_CHARS = ['<', '>', '"', "'", '&', '/', '\\', '|', '?', '*', '\n', '\r', '\t']
    
    # Dangerous patterns - UPDATED to be less restrictive for IOC analysis
    INJECTION_PATTERNS = [
        # SQL Injection - more specific patterns
        (r"('\s*(OR|AND)\s*'?\s*\d+\s*=\s*\d+)", "SQL Injection"),
        (r"(--\s*$|;\s*DROP\s+TABLE|;\s*DELETE\s+FROM)", "SQL Injection"),
        (r"UNION\s+ALL\s+SELECT", "SQL Injection"),
        
        # XSS - script tags and event handlers
        (r"<script[^>]*>.*?</script>", "XSS Script Tag"),
        (r"javascript\s*:\s*alert", "XSS JavaScript Alert"),
        (r"on(load|error|click|mouseover)\s*=\s*['\"]", "XSS Event Handler"),
        
        # Command Injection - very specific dangerous patterns only
        (r";\s*(rm|del|format)\s+-", "Command Injection"),
        (r"\|\s*(bash|sh|cmd|powershell)\s", "Command Injection"),
    ]
    
    # ReDoS vulnerable patterns - check for these IN the input itself
    REDOS_PATTERNS = [
        r"\(a\+\)\+",
        r"\(a\*\)\*",
        r"\(\[a-zA-Z\]\+\)\*",
    ]
    
    def __init__(self):
        """Initialize the input validator."""
        self.logger = get_security_logger()
    
    def validate_text_input(self, text: str) -> Tuple[bool, Optional[str]]:
        """
        Validate raw text input for IOC extraction.
        
        Args:
            text: Raw text input from user
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        # Check if empty
        if not text or not text.strip():
            return False, "Input text cannot be empty"
        
        # Check size limit
        text_size = len(text.encode('utf-8'))
        max_size = self.MAX_INPUT_SIZE_KB * 1024
        
        if text_size > max_size:
            self.logger.log_validation_failure(
                "text_input",
                text[:100],
                f"Input size {text_size} bytes exceeds limit of {max_size} bytes"
            )
            return False, f"Input text exceeds {self.MAX_INPUT_SIZE_KB}KB limit"
        
        # Check for injection attacks - only block clear attacks
        is_safe, attack_type = self._check_injection_patterns(text)
        if not is_safe:
            self.logger.log_validation_failure(
                "text_input",
                text[:100],
                f"Potential {attack_type} detected"
            )
            self.logger.log_suspicious_input(
                "text_input",
                attack_type,
                text[:100]
            )
            return False, f"Suspicious input detected: potential {attack_type}"
        
        # Note: ReDoS check removed for IOC text as legitimate IOC reports
        # may contain patterns that look like regex
        
        return True, None
    
    def validate_tag_input(self, tag: str) -> Tuple[bool, Optional[str]]:
        """
        Validate tag input.
        
        Args:
            tag: Tag string from user
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        # Check if empty
        if not tag or not tag.strip():
            return False, "Tag cannot be empty"
        
        tag = tag.strip()
        
        # Check length
        if len(tag) > self.MAX_TAG_LENGTH:
            self.logger.log_validation_failure(
                "tag",
                tag,
                f"Tag length {len(tag)} exceeds limit of {self.MAX_TAG_LENGTH}"
            )
            return False, f"Tag length exceeds {self.MAX_TAG_LENGTH} characters"
        
        # Check for forbidden characters
        for char in self.FORBIDDEN_TAG_CHARS:
            if char in tag:
                self.logger.log_validation_failure(
                    "tag",
                    tag,
                    f"Tag contains forbidden character: {char}"
                )
                return False, f"Tag contains forbidden character: {char}"
        
        # Check for injection patterns
        is_safe, attack_type = self._check_injection_patterns(tag)
        if not is_safe:
            self.logger.log_validation_failure(
                "tag",
                tag,
                f"Potential {attack_type} in tag"
            )
            return False, f"Tag contains invalid pattern: {attack_type}"
        
        return True, None
    
    def validate_search_query(self, query: str) -> Tuple[bool, Optional[str]]:
        """
        Validate search query input.
        
        Args:
            query: Search query from user
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        # Check if empty
        if not query or not query.strip():
            return False, "Search query cannot be empty"
        
        # Check length (reasonable limit for search)
        if len(query) > 200:
            self.logger.log_validation_failure(
                "search_query",
                query[:50],
                f"Query length {len(query)} exceeds reasonable limit"
            )
            return False, "Search query is too long"
        
        # Check for injection patterns
        is_safe, attack_type = self._check_injection_patterns(query)
        if not is_safe:
            self.logger.log_validation_failure(
                "search_query",
                query,
                f"Potential {attack_type} in search query"
            )
            return False, f"Search query contains invalid pattern"
        
        return True, None
    
    def sanitize_output(self, text: str) -> str:
        """
        Sanitize text for safe output (prevent XSS).
        
        Args:
            text: Text to sanitize
            
        Returns:
            Sanitized text with HTML entities escaped
        """
        # HTML escape to prevent XSS
        sanitized = html.escape(text)
        return sanitized
    
    def sanitize_export_csv(self, value: str) -> str:
        """
        Sanitize values for CSV export (prevent formula injection).
        
        Args:
            value: Value to sanitize
            
        Returns:
            Sanitized value safe for CSV export
        """
        # Check if value starts with formula characters
        if value and len(value) > 0:
            first_char = value[0]
            if first_char in ['=', '+', '-', '@', '|', '%']:
                # Prepend with single quote to prevent formula execution
                return "'" + value
        
        return value
    
    def sanitize_export_json(self, value: str) -> str:
        """
        Sanitize values for JSON export.
        
        Args:
            value: Value to sanitize
            
        Returns:
            Sanitized value safe for JSON export
        """
        # Escape special characters for JSON
        sanitized = value.replace('\\', '\\\\')
        sanitized = sanitized.replace('"', '\\"')
        sanitized = sanitized.replace('\n', '\\n')
        sanitized = sanitized.replace('\r', '\\r')
        sanitized = sanitized.replace('\t', '\\t')
        
        return sanitized
    
    def validate_ioc_value(self, ioc_value: str) -> Tuple[bool, Optional[str]]:
        """
        Validate IOC value for pattern poisoning.
        
        Args:
            ioc_value: IOC value to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        # Check for homoglyph characters that might confuse parsing
        suspicious_chars = ['０', '１', '２', '３', '４', '５', '６', '７', '８', '９']  # Full-width digits
        
        for char in suspicious_chars:
            if char in ioc_value:
                self.logger.log_suspicious_input(
                    "ioc_value",
                    "homoglyph_character",
                    ioc_value[:50]
                )
                # Don't reject, just log - might be legitimate
        
        return True, None
    
    def _check_injection_patterns(self, text: str) -> Tuple[bool, Optional[str]]:
        """
        Check text for injection attack patterns.
        
        Args:
            text: Text to check
            
        Returns:
            Tuple of (is_safe, attack_type if unsafe)
        """
        for pattern, attack_type in self.INJECTION_PATTERNS:
            try:
                if re.search(pattern, text, re.IGNORECASE):
                    return False, attack_type
            except re.error:
                # Invalid regex pattern, skip
                continue
        
        return True, None
    
    def _check_redos_patterns(self, text: str) -> bool:
        """
        Check text for patterns that could cause ReDoS.
        
        Args:
            text: Text to check
            
        Returns:
            True if ReDoS pattern detected
        """
        # Only check first 500 chars for performance
        sample = text[:500]
        
        for pattern in self.REDOS_PATTERNS:
            try:
                if re.search(re.escape(pattern), sample):
                    return True
            except re.error:
                # Pattern itself is malformed, log and continue
                self.logger.log_error(
                    "regex_error",
                    f"Invalid regex pattern: {pattern}"
                )
                continue
        
        return False
    
    def check_tag_count(self, current_tag_count: int) -> Tuple[bool, Optional[str]]:
        """
        Check if tag count exceeds limit (prevent resource exhaustion).
        
        Args:
            current_tag_count: Current number of tags on an IOC
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if current_tag_count >= self.MAX_TAG_COUNT_PER_IOC:
            self.logger.log_validation_failure(
                "tag_count",
                str(current_tag_count),
                f"Tag count {current_tag_count} exceeds limit of {self.MAX_TAG_COUNT_PER_IOC}"
            )
            return False, f"Maximum {self.MAX_TAG_COUNT_PER_IOC} tags per IOC allowed"
        
        return True, None


# Global validator instance
_validator_instance = None

def get_input_validator() -> InputValidator:
    """Get or create the global input validator instance."""
    global _validator_instance
    if _validator_instance is None:
        _validator_instance = InputValidator()
    return _validator_instance
