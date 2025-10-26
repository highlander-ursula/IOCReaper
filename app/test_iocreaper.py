"""
IOCReaper - Comprehensive Unit Tests
Tests for all functionalities defined in the requirements specification

Author: Test Suite for IOCReaper
"""

import pytest
import json
import csv
from io import StringIO
from typing import List, Dict, Set


# Mock classes representing the IOCReaper components
# In actual implementation, these would be imported from the application modules

class IOCObject:
    """Represents a single Indicator of Compromise"""
    def __init__(self, value: str, ioc_type: str):
        self.ioc_value = value
        self.ioc_type = ioc_type
        self.ioc_tags: List[str] = []
    
    def add_tag(self, tag: str):
        if tag and tag not in self.ioc_tags:
            self.ioc_tags.append(tag)
    
    def remove_tag(self, tag: str):
        if tag in self.ioc_tags:
            self.ioc_tags.remove(tag)


class IOCParser:
    """Extracts IOCs from raw text using regex patterns"""
    
    # Regex patterns for different IOC types
    IPV4_PATTERN = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    IPV6_PATTERN = r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
    DOMAIN_PATTERN = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    URL_PATTERN = r'https?://[^\s]+'
    EMAIL_PATTERN = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    MD5_PATTERN = r'\b[a-fA-F0-9]{32}\b'
    SHA1_PATTERN = r'\b[a-fA-F0-9]{40}\b'
    SHA256_PATTERN = r'\b[a-fA-F0-9]{64}\b'
    
    def __init__(self):
        self.max_input_size = 100 * 1024  # 100 KB
    
    def validate_input_size(self, text: str) -> bool:
        """Validate that input text is within size limits"""
        return len(text.encode('utf-8')) <= self.max_input_size
    
    def parse(self, text: str, deduplicate: bool = True, 
              normalize: bool = False) -> List[IOCObject]:
        """Parse IOCs from raw text"""
        import re
        
        if not text:
            return []
        
        if not self.validate_input_size(text):
            raise ValueError("Input size exceeds maximum limit of 100KB")
        
        iocs = []
        
        # Extract different IOC types
        patterns = {
            'IPv4': self.IPV4_PATTERN,
            'IPv6': self.IPV6_PATTERN,
            'Domain': self.DOMAIN_PATTERN,
            'URL': self.URL_PATTERN,
            'Email': self.EMAIL_PATTERN,
            'MD5': self.MD5_PATTERN,
            'SHA1': self.SHA1_PATTERN,
            'SHA256': self.SHA256_PATTERN
        }
        
        for ioc_type, pattern in patterns.items():
            matches = re.findall(pattern, text)
            for match in matches:
                value = match if not normalize else match.lower()
                iocs.append(IOCObject(value, ioc_type))
        
        if deduplicate:
            unique_iocs = {}
            for ioc in iocs:
                key = (ioc.ioc_value, ioc.ioc_type)
                if key not in unique_iocs:
                    unique_iocs[key] = ioc
            iocs = list(unique_iocs.values())
        
        return iocs


class FangerDefanger:
    """Converts IOCs between defanged and fanged versions"""
    
    @staticmethod
    def defang(ioc: str) -> str:
        """Defang an IOC (make it non-clickable)"""
        ioc = ioc.replace('http://', 'hxxp://')
        ioc = ioc.replace('https://', 'hxxps://')
        ioc = ioc.replace('.', '[.]')
        return ioc
    
    @staticmethod
    def refang(ioc: str) -> str:
        """Refang an IOC (restore to normal format)"""
        ioc = ioc.replace('hxxp://', 'http://')
        ioc = ioc.replace('hxxps://', 'https://')
        ioc = ioc.replace('[.]', '.')
        ioc = ioc.replace('[:]', ':')
        return ioc


class Categorizer:
    """Organizes IOCs into types and provides unique counts"""
    
    def categorize(self, iocs: List[IOCObject]) -> Dict[str, List[IOCObject]]:
        """Categorize IOCs by type"""
        categorized = {}
        for ioc in iocs:
            if ioc.ioc_type not in categorized:
                categorized[ioc.ioc_type] = []
            categorized[ioc.ioc_type].append(ioc)
        return categorized
    
    def get_counts(self, categorized: Dict[str, List[IOCObject]]) -> Dict[str, int]:
        """Get count of unique IOCs per category"""
        return {ioc_type: len(iocs) for ioc_type, iocs in categorized.items()}


class TagManager:
    """Manages tags for IOCs"""
    
    def __init__(self):
        self.tags: Dict[str, Set[IOCObject]] = {}
    
    def add_tag(self, iocs: List[IOCObject], tag: str) -> bool:
        """Add tag to IOCs"""
        if not tag or not tag.strip():
            raise ValueError("Tag cannot be empty")
        
        # Check for forbidden characters
        forbidden_chars = ['<', '>', '/', '\\', '|', '?', '*']
        if any(char in tag for char in forbidden_chars):
            raise ValueError("Tag contains forbidden characters")
        
        tag = tag.strip()
        
        if tag not in self.tags:
            self.tags[tag] = set()
        
        for ioc in iocs:
            ioc.add_tag(tag)
            self.tags[tag].add(ioc)
        
        return True
    
    def remove_tag(self, tag: str) -> bool:
        """Remove a tag from all IOCs"""
        if tag not in self.tags:
            return False
        
        iocs = self.tags[tag]
        for ioc in iocs:
            ioc.remove_tag(tag)
        
        del self.tags[tag]
        return True
    
    def rename_tag(self, old_tag: str, new_tag: str) -> bool:
        """Rename a tag"""
        if old_tag not in self.tags:
            return False
        
        if not new_tag or not new_tag.strip():
            raise ValueError("New tag name cannot be empty")
        
        iocs = self.tags[old_tag]
        
        for ioc in iocs:
            ioc.remove_tag(old_tag)
            ioc.add_tag(new_tag)
        
        self.tags[new_tag] = self.tags[old_tag]
        del self.tags[old_tag]
        
        return True
    
    def get_all_tags(self) -> List[str]:
        """Get all tags in use"""
        return list(self.tags.keys())


class Searcher:
    """Supports searching for IOCs and tags"""
    
    def search_ioc(self, iocs: List[IOCObject], query: str, 
                   case_sensitive: bool = False) -> List[IOCObject]:
        """Search for IOCs by value"""
        if not case_sensitive:
            query = query.lower()
        
        results = []
        for ioc in iocs:
            value = ioc.ioc_value if case_sensitive else ioc.ioc_value.lower()
            if query in value:
                results.append(ioc)
        
        return results
    
    def search_by_tag(self, iocs: List[IOCObject], tag: str) -> List[IOCObject]:
        """Search for IOCs by tag"""
        return [ioc for ioc in iocs if tag in ioc.ioc_tags]


class Exporter:
    """Exports IOCs to various formats"""
    
    def export_csv(self, iocs: List[IOCObject], include_tags: bool = False) -> str:
        """Export IOCs to CSV format"""
        output = StringIO()
        writer = csv.writer(output)
        
        if include_tags:
            writer.writerow(['IOC Value', 'IOC Type', 'Tags'])
            for ioc in iocs:
                tags = ','.join(ioc.ioc_tags) if ioc.ioc_tags else ''
                writer.writerow([ioc.ioc_value, ioc.ioc_type, tags])
        else:
            writer.writerow(['IOC Value', 'IOC Type'])
            for ioc in iocs:
                writer.writerow([ioc.ioc_value, ioc.ioc_type])
        
        return output.getvalue()
    
    def export_json(self, iocs: List[IOCObject], include_tags: bool = False) -> str:
        """Export IOCs to JSON format"""
        data = []
        for ioc in iocs:
            item = {
                'value': ioc.ioc_value,
                'type': ioc.ioc_type
            }
            if include_tags:
                item['tags'] = ioc.ioc_tags
            data.append(item)
        
        return json.dumps(data, indent=2)
    
    def export_txt(self, iocs: List[IOCObject], include_tags: bool = False) -> str:
        """Export IOCs to TXT format"""
        lines = []
        for ioc in iocs:
            if include_tags and ioc.ioc_tags:
                lines.append(f"{ioc.ioc_value} ({ioc.ioc_type}) [Tags: {', '.join(ioc.ioc_tags)}]")
            else:
                lines.append(f"{ioc.ioc_value} ({ioc.ioc_type})")
        
        return '\n'.join(lines)
    
    def copy_to_clipboard(self, iocs: List[IOCObject]) -> str:
        """Format IOCs for clipboard (newline-separated)"""
        return '\n'.join([ioc.ioc_value for ioc in iocs])


class SessionManager:
    """Manages in-memory IOC storage and session lifecycle"""
    
    def __init__(self):
        self.ioc_store: Dict[str, List[IOCObject]] = {}
        self.tag_manager = TagManager()
    
    def store_iocs(self, iocs: List[IOCObject]):
        """Store IOCs in session"""
        categorizer = Categorizer()
        self.ioc_store = categorizer.categorize(iocs)
    
    def clear_session(self):
        """Clear all session data"""
        self.ioc_store.clear()
        self.tag_manager = TagManager()
    
    def get_all_iocs(self) -> List[IOCObject]:
        """Get all IOCs from session"""
        all_iocs = []
        for iocs in self.ioc_store.values():
            all_iocs.extend(iocs)
        return all_iocs


# =============================================================================
# UNIT TESTS
# =============================================================================

class TestIOCParser:
    """Tests for FR-001: Parse IOCs from Raw Text"""
    
    def test_parse_valid_ipv4(self):
        """Test extraction of valid IPv4 addresses"""
        parser = IOCParser()
        text = "Server at 192.168.1.1 and 10.0.0.1 were compromised"
        iocs = parser.parse(text)
        
        ipv4_iocs = [ioc for ioc in iocs if ioc.ioc_type == 'IPv4']
        assert len(ipv4_iocs) == 2
        assert any(ioc.ioc_value == '192.168.1.1' for ioc in ipv4_iocs)
        assert any(ioc.ioc_value == '10.0.0.1' for ioc in ipv4_iocs)
    
    def test_parse_valid_domain(self):
        """Test extraction of valid domains"""
        parser = IOCParser()
        text = "Malicious domains: malware.com and evil.example.org"
        iocs = parser.parse(text)
        
        domain_iocs = [ioc for ioc in iocs if ioc.ioc_type == 'Domain']
        assert len(domain_iocs) >= 2
    
    def test_parse_valid_url(self):
        """Test extraction of valid URLs"""
        parser = IOCParser()
        text = "C2 server at http://malicious.com/payload and https://evil.net/download"
        iocs = parser.parse(text)
        
        url_iocs = [ioc for ioc in iocs if ioc.ioc_type == 'URL']
        assert len(url_iocs) == 2
    
    def test_parse_valid_email(self):
        """Test extraction of valid email addresses"""
        parser = IOCParser()
        text = "Contact attacker@malware.com or phishing@evil.net"
        iocs = parser.parse(text)
        
        email_iocs = [ioc for ioc in iocs if ioc.ioc_type == 'Email']
        assert len(email_iocs) == 2
    
    def test_parse_valid_hashes(self):
        """Test extraction of valid hash values"""
        parser = IOCParser()
        md5 = "5d41402abc4b2a76b9719d911017c592"
        sha1 = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
        sha256 = "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
        
        text = f"Hashes: {md5} and {sha1} and {sha256}"
        iocs = parser.parse(text)
        
        hash_iocs = [ioc for ioc in iocs if ioc.ioc_type in ['MD5', 'SHA1', 'SHA256']]
        assert len(hash_iocs) == 3
    
    def test_parse_empty_input(self):
        """Test parsing empty input returns empty list"""
        parser = IOCParser()
        iocs = parser.parse("")
        assert len(iocs) == 0
    
    def test_parse_no_iocs_found(self):
        """Test parsing text with no IOCs"""
        parser = IOCParser()
        text = "This is just regular text with no indicators"
        iocs = parser.parse(text)
        # May contain some false positives from domain matching
        # The key is it doesn't crash
        assert isinstance(iocs, list)
    
    def test_parse_with_deduplication(self):
        """Test deduplication of IOCs"""
        parser = IOCParser()
        text = "IP 192.168.1.1 and again 192.168.1.1 appears twice"
        iocs = parser.parse(text, deduplicate=True)
        
        ipv4_iocs = [ioc for ioc in iocs if ioc.ioc_type == 'IPv4']
        assert len(ipv4_iocs) == 1
    
    def test_parse_without_deduplication(self):
        """Test parsing without deduplication"""
        parser = IOCParser()
        text = "IP 192.168.1.1 and again 192.168.1.1 appears twice"
        iocs = parser.parse(text, deduplicate=False)
        
        ipv4_iocs = [ioc for ioc in iocs if ioc.ioc_type == 'IPv4']
        assert len(ipv4_iocs) == 2
    
    def test_input_size_validation_within_limit(self):
        """Test input validation accepts valid size"""
        parser = IOCParser()
        text = "A" * 1000  # 1KB
        assert parser.validate_input_size(text) == True
    
    def test_input_size_validation_exceeds_limit(self):
        """Test input validation rejects oversized input"""
        parser = IOCParser()
        text = "A" * (101 * 1024)  # 101 KB
        assert parser.validate_input_size(text) == False
    
    def test_parse_oversized_input_raises_error(self):
        """Test parsing oversized input raises ValueError"""
        parser = IOCParser()
        text = "A" * (101 * 1024)  # 101 KB
        
        with pytest.raises(ValueError, match="exceeds maximum limit"):
            parser.parse(text)


class TestCategorizer:
    """Tests for FR-002: Categorize Extracted IOCs"""
    
    def test_categorize_mixed_iocs(self):
        """Test categorization of mixed IOC types"""
        iocs = [
            IOCObject('192.168.1.1', 'IPv4'),
            IOCObject('example.com', 'Domain'),
            IOCObject('10.0.0.1', 'IPv4'),
            IOCObject('test.org', 'Domain')
        ]
        
        categorizer = Categorizer()
        categorized = categorizer.categorize(iocs)
        
        assert len(categorized['IPv4']) == 2
        assert len(categorized['Domain']) == 2
    
    def test_categorize_empty_list(self):
        """Test categorization of empty IOC list"""
        categorizer = Categorizer()
        categorized = categorizer.categorize([])
        
        assert len(categorized) == 0
    
    def test_get_counts(self):
        """Test getting counts of categorized IOCs"""
        iocs = [
            IOCObject('192.168.1.1', 'IPv4'),
            IOCObject('example.com', 'Domain'),
            IOCObject('10.0.0.1', 'IPv4'),
        ]
        
        categorizer = Categorizer()
        categorized = categorizer.categorize(iocs)
        counts = categorizer.get_counts(categorized)
        
        assert counts['IPv4'] == 2
        assert counts['Domain'] == 1


class TestFangerDefanger:
    """Tests for FR-003: Apply Filters and Normalization"""
    
    def test_defang_http_url(self):
        """Test defanging HTTP URL"""
        url = "http://malicious.com/payload"
        defanged = FangerDefanger.defang(url)
        
        assert "hxxp://" in defanged
        assert "[.]" in defanged
    
    def test_defang_https_url(self):
        """Test defanging HTTPS URL"""
        url = "https://evil.net/download"
        defanged = FangerDefanger.defang(url)
        
        assert "hxxps://" in defanged
        assert "[.]" in defanged
    
    def test_refang_url(self):
        """Test refanging URL"""
        defanged = "hxxps://evil[.]net/download"
        fanged = FangerDefanger.refang(defanged)
        
        assert fanged == "https://evil.net/download"
    
    def test_defang_domain(self):
        """Test defanging domain"""
        domain = "malware.example.com"
        defanged = FangerDefanger.defang(domain)
        
        assert "[.]" in defanged
        assert "malware[.]example[.]com" == defanged
    
    def test_refang_ipv4(self):
        """Test refanging IPv4 address"""
        defanged = "192[.]168[.]1[.]1"
        fanged = FangerDefanger.refang(defanged)
        
        assert fanged == "192.168.1.1"


class TestSearcher:
    """Tests for FR-004: Search Results"""
    
    def test_search_ioc_case_insensitive(self):
        """Test case-insensitive IOC search"""
        iocs = [
            IOCObject('MALWARE.COM', 'Domain'),
            IOCObject('example.org', 'Domain'),
            IOCObject('192.168.1.1', 'IPv4')
        ]
        
        searcher = Searcher()
        results = searcher.search_ioc(iocs, 'malware', case_sensitive=False)
        
        assert len(results) == 1
        assert results[0].ioc_value == 'MALWARE.COM'
    
    def test_search_ioc_case_sensitive(self):
        """Test case-sensitive IOC search"""
        iocs = [
            IOCObject('MALWARE.COM', 'Domain'),
            IOCObject('malware.org', 'Domain'),
        ]
        
        searcher = Searcher()
        results = searcher.search_ioc(iocs, 'MALWARE', case_sensitive=True)
        
        assert len(results) == 1
        assert results[0].ioc_value == 'MALWARE.COM'
    
    def test_search_ioc_no_results(self):
        """Test search with no matching results"""
        iocs = [
            IOCObject('example.com', 'Domain'),
            IOCObject('192.168.1.1', 'IPv4')
        ]
        
        searcher = Searcher()
        results = searcher.search_ioc(iocs, 'nonexistent')
        
        assert len(results) == 0
    
    def test_search_by_tag(self):
        """Test searching IOCs by tag"""
        ioc1 = IOCObject('malware.com', 'Domain')
        ioc1.add_tag('phishing')
        
        ioc2 = IOCObject('192.168.1.1', 'IPv4')
        ioc2.add_tag('c2')
        
        ioc3 = IOCObject('evil.net', 'Domain')
        ioc3.add_tag('phishing')
        
        iocs = [ioc1, ioc2, ioc3]
        
        searcher = Searcher()
        results = searcher.search_by_tag(iocs, 'phishing')
        
        assert len(results) == 2
    
    def test_search_partial_match(self):
        """Test search finds partial matches"""
        iocs = [
            IOCObject('malware.example.com', 'Domain'),
            IOCObject('test.org', 'Domain')
        ]
        
        searcher = Searcher()
        results = searcher.search_ioc(iocs, 'example')
        
        assert len(results) == 1


class TestExporter:
    """Tests for FR-005 & FR-006: Copy to Clipboard and Export Results"""
    
    def test_export_csv_without_tags(self):
        """Test CSV export without tags"""
        iocs = [
            IOCObject('192.168.1.1', 'IPv4'),
            IOCObject('malware.com', 'Domain')
        ]
        
        exporter = Exporter()
        csv_output = exporter.export_csv(iocs, include_tags=False)
        
        assert 'IOC Value' in csv_output
        assert 'IOC Type' in csv_output
        assert '192.168.1.1' in csv_output
        assert 'malware.com' in csv_output
        assert 'Tags' not in csv_output
    
    def test_export_csv_with_tags(self):
        """Test CSV export with tags"""
        ioc = IOCObject('192.168.1.1', 'IPv4')
        ioc.add_tag('malicious')
        iocs = [ioc]
        
        exporter = Exporter()
        csv_output = exporter.export_csv(iocs, include_tags=True)
        
        assert 'Tags' in csv_output
        assert 'malicious' in csv_output
    
    def test_export_json_without_tags(self):
        """Test JSON export without tags"""
        iocs = [
            IOCObject('192.168.1.1', 'IPv4'),
            IOCObject('malware.com', 'Domain')
        ]
        
        exporter = Exporter()
        json_output = exporter.export_json(iocs, include_tags=False)
        data = json.loads(json_output)
        
        assert len(data) == 2
        assert data[0]['value'] == '192.168.1.1'
        assert data[0]['type'] == 'IPv4'
        assert 'tags' not in data[0]
    
    def test_export_json_with_tags(self):
        """Test JSON export with tags"""
        ioc = IOCObject('192.168.1.1', 'IPv4')
        ioc.add_tag('c2')
        iocs = [ioc]
        
        exporter = Exporter()
        json_output = exporter.export_json(iocs, include_tags=True)
        data = json.loads(json_output)
        
        assert 'tags' in data[0]
        assert 'c2' in data[0]['tags']
    
    def test_export_txt_without_tags(self):
        """Test TXT export without tags"""
        iocs = [
            IOCObject('192.168.1.1', 'IPv4'),
            IOCObject('malware.com', 'Domain')
        ]
        
        exporter = Exporter()
        txt_output = exporter.export_txt(iocs, include_tags=False)
        
        assert '192.168.1.1' in txt_output
        assert 'IPv4' in txt_output
        assert 'malware.com' in txt_output
        assert 'Tags' not in txt_output
    
    def test_export_txt_with_tags(self):
        """Test TXT export with tags"""
        ioc = IOCObject('192.168.1.1', 'IPv4')
        ioc.add_tag('suspicious')
        iocs = [ioc]
        
        exporter = Exporter()
        txt_output = exporter.export_txt(iocs, include_tags=True)
        
        assert 'Tags' in txt_output
        assert 'suspicious' in txt_output
    
    def test_copy_to_clipboard(self):
        """Test copy to clipboard format"""
        iocs = [
            IOCObject('192.168.1.1', 'IPv4'),
            IOCObject('malware.com', 'Domain'),
            IOCObject('10.0.0.1', 'IPv4')
        ]
        
        exporter = Exporter()
        clipboard_text = exporter.copy_to_clipboard(iocs)
        
        lines = clipboard_text.split('\n')
        assert len(lines) == 3
        assert '192.168.1.1' in clipboard_text
        assert 'malware.com' in clipboard_text
    
    def test_export_empty_list(self):
        """Test exporting empty IOC list"""
        exporter = Exporter()
        
        csv_output = exporter.export_csv([])
        json_output = exporter.export_json([])
        txt_output = exporter.export_txt([])
        
        assert 'IOC Value' in csv_output  # Headers present
        assert json.loads(json_output) == []
        assert txt_output == ''


class TestSessionManager:
    """Tests for FR-007 & FR-008: Session Management"""
    
    def test_store_iocs(self):
        """Test storing IOCs in session"""
        iocs = [
            IOCObject('192.168.1.1', 'IPv4'),
            IOCObject('malware.com', 'Domain')
        ]
        
        session = SessionManager()
        session.store_iocs(iocs)
        
        assert len(session.ioc_store) == 2
        assert 'IPv4' in session.ioc_store
        assert 'Domain' in session.ioc_store
    
    def test_clear_session(self):
        """Test clearing session data"""
        iocs = [
            IOCObject('192.168.1.1', 'IPv4'),
            IOCObject('malware.com', 'Domain')
        ]
        
        session = SessionManager()
        session.store_iocs(iocs)
        
        assert len(session.ioc_store) > 0
        
        session.clear_session()
        
        assert len(session.ioc_store) == 0
        assert len(session.tag_manager.get_all_tags()) == 0
    
    def test_get_all_iocs(self):
        """Test retrieving all IOCs from session"""
        iocs = [
            IOCObject('192.168.1.1', 'IPv4'),
            IOCObject('malware.com', 'Domain'),
            IOCObject('10.0.0.1', 'IPv4')
        ]
        
        session = SessionManager()
        session.store_iocs(iocs)
        
        all_iocs = session.get_all_iocs()
        assert len(all_iocs) == 3
    
    def test_session_scoped_data(self):
        """Test that session data is isolated"""
        session1 = SessionManager()
        session2 = SessionManager()
        
        iocs = [IOCObject('192.168.1.1', 'IPv4')]
        session1.store_iocs(iocs)
        
        assert len(session1.get_all_iocs()) == 1
        assert len(session2.get_all_iocs()) == 0


class TestTagManager:
    """Tests for FR-011, FR-012, FR-013: Tag Management"""
    
    def test_add_tag_to_single_ioc(self):
        """Test adding tag to a single IOC"""
        ioc = IOCObject('192.168.1.1', 'IPv4')
        tag_manager = TagManager()
        
        result = tag_manager.add_tag([ioc], 'malicious')
        
        assert result == True
        assert 'malicious' in ioc.ioc_tags
        assert 'malicious' in tag_manager.get_all_tags()
    
    def test_add_tag_to_multiple_iocs(self):
        """Test adding tag to multiple IOCs"""
        iocs = [
            IOCObject('192.168.1.1', 'IPv4'),
            IOCObject('malware.com', 'Domain')
        ]
        tag_manager = TagManager()
        
        tag_manager.add_tag(iocs, 'phishing')
        
        assert all('phishing' in ioc.ioc_tags for ioc in iocs)
    
    def test_add_empty_tag_raises_error(self):
        """Test adding empty tag raises ValueError"""
        ioc = IOCObject('192.168.1.1', 'IPv4')
        tag_manager = TagManager()
        
        with pytest.raises(ValueError, match="Tag cannot be empty"):
            tag_manager.add_tag([ioc], '')
    
    def test_add_tag_with_forbidden_chars_raises_error(self):
        """Test adding tag with forbidden characters raises error"""
        ioc = IOCObject('192.168.1.1', 'IPv4')
        tag_manager = TagManager()
        
        forbidden_tags = ['tag<script>', 'tag/path', 'tag\\back', 'tag|pipe', 'tag?query', 'tag*wild']
        
        for bad_tag in forbidden_tags:
            with pytest.raises(ValueError, match="forbidden characters"):
                tag_manager.add_tag([ioc], bad_tag)
    
    def test_remove_tag(self):
        """Test removing a tag"""
        ioc = IOCObject('192.168.1.1', 'IPv4')
        tag_manager = TagManager()
        
        tag_manager.add_tag([ioc], 'temporary')
        assert 'temporary' in ioc.ioc_tags
        
        result = tag_manager.remove_tag('temporary')
        
        assert result == True
        assert 'temporary' not in ioc.ioc_tags
        assert 'temporary' not in tag_manager.get_all_tags()
    
    def test_remove_nonexistent_tag(self):
        """Test removing non-existent tag returns False"""
        tag_manager = TagManager()
        result = tag_manager.remove_tag('nonexistent')
        
        assert result == False
    
    def test_rename_tag(self):
        """Test renaming a tag"""
        ioc = IOCObject('192.168.1.1', 'IPv4')
        tag_manager = TagManager()
        
        tag_manager.add_tag([ioc], 'old_name')
        result = tag_manager.rename_tag('old_name', 'new_name')
        
        assert result == True
        assert 'new_name' in ioc.ioc_tags
        assert 'old_name' not in ioc.ioc_tags
        assert 'new_name' in tag_manager.get_all_tags()
        assert 'old_name' not in tag_manager.get_all_tags()
    
    def test_rename_nonexistent_tag(self):
        """Test renaming non-existent tag returns False"""
        tag_manager = TagManager()
        result = tag_manager.rename_tag('nonexistent', 'new_name')
        
        assert result == False
    
    def test_rename_tag_to_empty_name_raises_error(self):
        """Test renaming tag to empty name raises error"""
        ioc = IOCObject('192.168.1.1', 'IPv4')
        tag_manager = TagManager()
        
        tag_manager.add_tag([ioc], 'old_name')
        
        with pytest.raises(ValueError, match="cannot be empty"):
            tag_manager.rename_tag('old_name', '')
    
    def test_get_all_tags(self):
        """Test getting all tags"""
        iocs = [
            IOCObject('192.168.1.1', 'IPv4'),
            IOCObject('malware.com', 'Domain')
        ]
        tag_manager = TagManager()
        
        tag_manager.add_tag([iocs[0]], 'tag1')
        tag_manager.add_tag([iocs[1]], 'tag2')
        
        all_tags = tag_manager.get_all_tags()
        
        assert len(all_tags) == 2
        assert 'tag1' in all_tags
        assert 'tag2' in all_tags
    
    def test_multiple_tags_on_single_ioc(self):
        """Test adding multiple tags to a single IOC"""
        ioc = IOCObject('192.168.1.1', 'IPv4')
        tag_manager = TagManager()
        
        tag_manager.add_tag([ioc], 'tag1')
        tag_manager.add_tag([ioc], 'tag2')
        tag_manager.add_tag([ioc], 'tag3')
        
        assert len(ioc.ioc_tags) == 3
        assert all(tag in ioc.ioc_tags for tag in ['tag1', 'tag2', 'tag3'])


class TestErrorHandling:
    """Tests for FR-009 & FR-010: Input Validation and Error Messaging"""
    
    def test_parser_validates_input_size(self):
        """Test parser validates input size"""
        parser = IOCParser()
        
        # Valid size
        small_text = "test"
        assert parser.validate_input_size(small_text) == True
        
        # Invalid size
        large_text = "A" * (101 * 1024)
        assert parser.validate_input_size(large_text) == False
    
    def test_parser_raises_error_on_oversized_input(self):
        """Test parser raises error for oversized input"""
        parser = IOCParser()
        large_text = "A" * (101 * 1024)
        
        with pytest.raises(ValueError) as exc_info:
            parser.parse(large_text)
        
        assert "exceeds maximum limit" in str(exc_info.value)
    
    def test_tag_manager_validates_tag_input(self):
        """Test tag manager validates tag input"""
        ioc = IOCObject('192.168.1.1', 'IPv4')
        tag_manager = TagManager()
        
        # Empty tag
        with pytest.raises(ValueError):
            tag_manager.add_tag([ioc], '')
        
        # Whitespace only
        with pytest.raises(ValueError):
            tag_manager.add_tag([ioc], '   ')
    
    def test_exporter_handles_empty_input(self):
        """Test exporter handles empty input gracefully"""
        exporter = Exporter()
        
        # Should not raise errors
        csv_out = exporter.export_csv([])
        json_out = exporter.export_json([])
        txt_out = exporter.export_txt([])
        clip_out = exporter.copy_to_clipboard([])
        
        assert isinstance(csv_out, str)
        assert isinstance(json_out, str)
        assert isinstance(txt_out, str)
        assert isinstance(clip_out, str)


class TestIntegrationScenarios:
    """Integration tests covering multiple components"""
    
    def test_full_workflow_parse_categorize_tag_export(self):
        """Test complete workflow from parsing to export"""
        # Parse IOCs
        parser = IOCParser()
        text = """
        Malicious activity detected:
        C2 servers: 192.168.1.100, malware.evil.com
        Phishing email: attacker@phish.net
        Hash: 5d41402abc4b2a76b9719d911017c592
        """
        iocs = parser.parse(text, deduplicate=True)
        
        # Categorize
        categorizer = Categorizer()
        categorized = categorizer.categorize(iocs)
        
        assert len(categorized) > 0
        
        # Add tags
        tag_manager = TagManager()
        all_iocs = []
        for ioc_list in categorized.values():
            all_iocs.extend(ioc_list)
        
        tag_manager.add_tag(all_iocs, 'incident_123')
        
        # Export
        exporter = Exporter()
        json_output = exporter.export_json(all_iocs, include_tags=True)
        
        assert 'incident_123' in json_output
        assert len(all_iocs) > 0
    
    def test_search_tagged_iocs(self):
        """Test searching for tagged IOCs"""
        # Create IOCs with tags
        ioc1 = IOCObject('malware.com', 'Domain')
        ioc1.add_tag('phishing')
        
        ioc2 = IOCObject('192.168.1.1', 'IPv4')
        ioc2.add_tag('c2')
        
        ioc3 = IOCObject('evil.net', 'Domain')
        ioc3.add_tag('phishing')
        
        iocs = [ioc1, ioc2, ioc3]
        
        # Search by tag
        searcher = Searcher()
        phishing_iocs = searcher.search_by_tag(iocs, 'phishing')
        
        assert len(phishing_iocs) == 2
        
        # Export tagged results
        exporter = Exporter()
        export_data = exporter.export_csv(phishing_iocs, include_tags=True)
        
        assert 'phishing' in export_data
    
    def test_session_with_multiple_operations(self):
        """Test session manager with multiple operations"""
        session = SessionManager()
        
        # Parse and store
        parser = IOCParser()
        text = "IPs: 10.0.0.1, 192.168.1.1 Domains: test.com, example.org"
        iocs = parser.parse(text)
        session.store_iocs(iocs)
        
        # Add tags
        all_iocs = session.get_all_iocs()
        session.tag_manager.add_tag(all_iocs, 'test_session')
        
        assert len(session.get_all_iocs()) > 0
        assert 'test_session' in session.tag_manager.get_all_tags()
        
        # Clear session
        session.clear_session()
        
        assert len(session.get_all_iocs()) == 0
        assert len(session.tag_manager.get_all_tags()) == 0
    
    def test_defang_then_export(self):
        """Test defanging IOCs before export"""
        iocs = [
            IOCObject('http://malware.com', 'URL'),
            IOCObject('evil.net', 'Domain')
        ]
        
        # Defang values
        for ioc in iocs:
            ioc.ioc_value = FangerDefanger.defang(ioc.ioc_value)
        
        # Export
        exporter = Exporter()
        txt_output = exporter.export_txt(iocs)
        
        assert 'hxxp://' in txt_output or '[.]' in txt_output


if __name__ == '__main__':
    # Run tests with pytest
    pytest.main([__file__, '-v', '--tb=short'])
