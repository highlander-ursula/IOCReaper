"""
IOCReaper Exporter Module - Phase 5 Security Enhanced
Includes CSV formula injection prevention and output sanitization

Mitigates: MC-006 (Export Format Manipulation for Code Execution)

Author: Manudeep Maddipatla
Email: mmaddipa@umd.edu
UMD Directory ID: mmaddipa (121417350)
"""

import json
import csv
from io import StringIO
from typing import Tuple
from input_validator import get_input_validator
from security_logger import get_security_logger


class Exporter:
    """
    Export IOCs with security enhancements.
    
    Phase 5 Security Features:
    - CSV formula injection prevention
    - JSON sanitization
    - Output encoding
    - Export logging
    """
    
    def __init__(self):
        """Initialize the exporter with security components."""
        self.validator = get_input_validator()
        self.logger = get_security_logger()
    
    def export(self, session_manager, format: str, include_tags: bool = False) -> Tuple[bytes, str, str]:
        """
        Export IOCs in specified format with security enhancements.
        
        Args:
            session_manager: Session manager instance
            format: Export format (csv, json, txt)
            include_tags: Whether to include tags
            
        Returns:
            Tuple of (content_bytes, filename, media_type)
        """
        iocs = session_manager.get_iocs()
        
        if format.lower() == 'json':
            return self._export_json(iocs, include_tags)
        elif format.lower() == 'csv':
            return self._export_csv(iocs, include_tags)
        elif format.lower() == 'txt':
            return self._export_txt(iocs, include_tags)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _export_json(self, iocs: dict, include_tags: bool) -> Tuple[bytes, str, str]:
        """
        Export as JSON with sanitization.
        
        Args:
            iocs: IOC dictionary
            include_tags: Whether to include tags
            
        Returns:
            Tuple of (content_bytes, filename, media_type)
        """
        export_data = []
        
        for ioc_type, data in iocs.items():
            for ioc in data['items']:
                # Sanitize values for JSON
                item = {
                    'value': self.validator.sanitize_export_json(ioc['value']),
                    'type': ioc['type']
                }
                
                if include_tags:
                    # Sanitize each tag
                    item['tags'] = [
                        self.validator.sanitize_export_json(tag)
                        for tag in ioc['tags']
                    ]
                
                export_data.append(item)
        
        content = json.dumps(export_data, indent=2, ensure_ascii=False).encode('utf-8')
        return content, 'iocs.json', 'application/json'
    
    def _export_csv(self, iocs: dict, include_tags: bool) -> Tuple[bytes, str, str]:
        """
        Export as CSV with formula injection prevention.
        
        Mitigates MC-006: Export Format Manipulation for Code Execution
        
        Args:
            iocs: IOC dictionary
            include_tags: Whether to include tags
            
        Returns:
            Tuple of (content_bytes, filename, media_type)
        """
        output = StringIO()
        fieldnames = ['value', 'type']
        if include_tags:
            fieldnames.append('tags')
        
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        
        for ioc_type, data in iocs.items():
            for ioc in data['items']:
                # SECURITY: Prevent CSV formula injection
                # Prepend ' to values starting with =, +, -, @, |, %
                safe_value = self.validator.sanitize_export_csv(ioc['value'])
                
                row = {
                    'value': safe_value,
                    'type': ioc['type']
                }
                
                if include_tags:
                    # Sanitize tags and join with comma
                    safe_tags = [
                        self.validator.sanitize_export_csv(tag)
                        for tag in ioc['tags']
                    ]
                    row['tags'] = ','.join(safe_tags)
                
                writer.writerow(row)
        
        content = output.getvalue().encode('utf-8')
        return content, 'iocs.csv', 'text/csv'
    
    def _export_txt(self, iocs: dict, include_tags: bool) -> Tuple[bytes, str, str]:
        """
        Export as plain text.
        
        Args:
            iocs: IOC dictionary
            include_tags: Whether to include tags
            
        Returns:
            Tuple of (content_bytes, filename, media_type)
        """
        lines = []
        
        for ioc_type, data in iocs.items():
            for ioc in data['items']:
                line = ioc['value']
                
                if include_tags and ioc['tags']:
                    # Sanitize tags
                    safe_tags = [
                        self.validator.sanitize_output(tag)
                        for tag in ioc['tags']
                    ]
                    line += f" [Tags: {', '.join(safe_tags)}]"
                
                lines.append(line)
        
        content = '\n'.join(lines).encode('utf-8')
        return content, 'iocs.txt', 'text/plain'
