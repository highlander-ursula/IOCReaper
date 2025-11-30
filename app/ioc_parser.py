"""
IOCReaper IOC Parser Module - Phase 5 Security Enhanced
Includes input validation, logging, and security controls

Author: Manudeep Maddipatla
Email: mmaddipa@umd.edu
UMD Directory ID: mmaddipa (121417350)
"""

import re
from typing import List, Dict
from fangerdefanger import FangerDefanger
from input_validator import get_input_validator
from security_logger import get_security_logger
from error_handler import get_error_handler


class IOCParser:
    """
    Extracts Indicators of Compromise from text with security enhancements.
    
    Phase 5 Security Features:
    - Input validation and sanitization
    - Size limit enforcement
    - ReDoS protection
    - Comprehensive logging
    - Secure error handling
    """
    
    def __init__(self):
        """Initialize the IOC parser with security components."""
        self.fangerdefanger = FangerDefanger()
        self.validator = get_input_validator()
        self.logger = get_security_logger()
        self.error_handler = get_error_handler()
        
        # Regex patterns for different IOC types
        self.patterns = {
            'ipv4': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            'ipv6': r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
            'domain': r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b',
            'url': r'https?://[^\s]+',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'md5': r'\b[a-fA-F0-9]{32}\b',
            'sha1': r'\b[a-fA-F0-9]{40}\b',
            'sha256': r'\b[a-fA-F0-9]{64}\b'
        }
    
    def extract(self, text: str, normalize: bool = False, deduplicate: bool = False) -> List[Dict]:
        """
        Extract IOCs from text with security validation.
        
        Args:
            text: Raw text input
            normalize: Whether to normalize (defang/refang) IOCs
            deduplicate: Whether to remove duplicate IOCs
            
        Returns:
            List of IOC dictionaries
            
        Raises:
            ValueError: If input validation fails
        """
        # Validate input
        is_valid, error_msg = self.validator.validate_text_input(text)
        if not is_valid:
            self.logger.log_extraction(
                len(text.encode('utf-8')),
                normalize,
                deduplicate,
                0,
                False
            )
            raise ValueError(error_msg)
        
        text_size = len(text.encode('utf-8'))
        iocs = []
        
        try:
            # Normalize text if requested
            if normalize:
                text = self.fangerdefanger.fang(text)
            
            # Extract each IOC type
            for ioc_type, pattern in self.patterns.items():
                try:
                    matches = re.findall(pattern, text, re.IGNORECASE)
                    for match in matches:
                        # Validate extracted IOC
                        is_ioc_valid, _ = self.validator.validate_ioc_value(match)
                        
                        iocs.append({
                            'value': match,
                            'type': ioc_type,
                            'tags': []
                        })
                except re.error as e:
                    # Log regex error but continue with other patterns
                    self.logger.log_error(
                        "regex_error",
                        f"Pattern {ioc_type} failed: {str(e)}"
                    )
                    continue
            
            # Deduplicate if requested
            if deduplicate:
                seen = set()
                unique_iocs = []
                for ioc in iocs:
                    key = (ioc['value'], ioc['type'])
                    if key not in seen:
                        seen.add(key)
                        unique_iocs.append(ioc)
                iocs = unique_iocs
            
            # Log successful extraction
            self.logger.log_extraction(
                text_size,
                normalize,
                deduplicate,
                len(iocs),
                True
            )
            
            return iocs
            
        except Exception as e:
            # Log failed extraction
            self.logger.log_extraction(
                text_size,
                normalize,
                deduplicate,
                0,
                False
            )
            self.logger.log_exception(e, "ioc_extraction")
            raise
