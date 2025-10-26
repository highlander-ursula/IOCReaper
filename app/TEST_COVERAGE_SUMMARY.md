# IOCReaper - Functionality List and Test Coverage

## Complete Functionality List

### 1. FR-001: Parse IOCs from Raw Text
**Description:** Extract IOCs (IP addresses, domains, URLs, hashes, emails) from raw text input using regex patterns.

**Test Coverage:**
- ✅ `test_parse_valid_ipv4` - Test extraction of valid IPv4 addresses
- ✅ `test_parse_valid_domain` - Test extraction of valid domains
- ✅ `test_parse_valid_url` - Test extraction of valid URLs
- ✅ `test_parse_valid_email` - Test extraction of valid email addresses
- ✅ `test_parse_valid_hashes` - Test extraction of MD5, SHA1, SHA256 hashes
- ✅ `test_parse_empty_input` - Test parsing empty input returns empty list
- ✅ `test_parse_no_iocs_found` - Test parsing text with no IOCs
- ✅ `test_parse_with_deduplication` - Test deduplication of IOCs
- ✅ `test_parse_without_deduplication` - Test parsing without deduplication
- ✅ `test_parse_oversized_input_raises_error` - Test parsing oversized input raises ValueError

---

### 2. FR-002: Categorize Extracted IOCs
**Description:** Organize extracted IOCs into their respective types (IPv4, IPv6, Domain, URL, Email, Hashes) with unique counts.

**Test Coverage:**
- ✅ `test_categorize_mixed_iocs` - Test categorization of mixed IOC types
- ✅ `test_categorize_empty_list` - Test categorization of empty IOC list
- ✅ `test_get_counts` - Test getting counts of categorized IOCs

---

### 3. FR-003: Apply Filters and Normalization
**Description:** Apply transformation operations including de-duplication, refang, normalize, and defang.

**Test Coverage:**
- ✅ `test_defang_http_url` - Test defanging HTTP URL
- ✅ `test_defang_https_url` - Test defanging HTTPS URL
- ✅ `test_refang_url` - Test refanging URL
- ✅ `test_defang_domain` - Test defanging domain
- ✅ `test_refang_ipv4` - Test refanging IPv4 address

---

### 4. FR-004: Search Results
**Description:** Search for specific IOC values or tags with optional case-sensitive matching.

**Test Coverage:**
- ✅ `test_search_ioc_case_insensitive` - Test case-insensitive IOC search
- ✅ `test_search_ioc_case_sensitive` - Test case-sensitive IOC search
- ✅ `test_search_ioc_no_results` - Test search with no matching results
- ✅ `test_search_by_tag` - Test searching IOCs by tag
- ✅ `test_search_partial_match` - Test search finds partial matches

---

### 5. FR-005: Copy to Clipboard
**Description:** Copy IOCs as newline-separated values to clipboard.

**Test Coverage:**
- ✅ `test_copy_to_clipboard` - Test copy to clipboard format

---

### 6. FR-006: Export Results to File
**Description:** Export IOCs to CSV, JSON, or TXT formats with optional tag inclusion.

**Test Coverage:**
- ✅ `test_export_csv_without_tags` - Test CSV export without tags
- ✅ `test_export_csv_with_tags` - Test CSV export with tags
- ✅ `test_export_json_without_tags` - Test JSON export without tags
- ✅ `test_export_json_with_tags` - Test JSON export with tags
- ✅ `test_export_txt_without_tags` - Test TXT export without tags
- ✅ `test_export_txt_with_tags` - Test TXT export with tags
- ✅ `test_export_empty_list` - Test exporting empty IOC list

---

### 7. FR-007: Clear Session
**Description:** Reset application to initial state by clearing all in-memory data.

**Test Coverage:**
- ✅ `test_clear_session` - Test clearing session data

---

### 8. FR-008: Session-Scoped Data Handling
**Description:** Maintain in-memory storage for one session only, no persistent data.

**Test Coverage:**
- ✅ `test_store_iocs` - Test storing IOCs in session
- ✅ `test_get_all_iocs` - Test retrieving all IOCs from session
- ✅ `test_session_scoped_data` - Test that session data is isolated

---

### 9. FR-009: Input Validation & Size Limits
**Description:** Validate input text size (maximum ~100 KB).

**Test Coverage:**
- ✅ `test_input_size_validation_within_limit` - Test input validation accepts valid size
- ✅ `test_input_size_validation_exceeds_limit` - Test input validation rejects oversized input
- ✅ `test_parser_validates_input_size` - Test parser validates input size
- ✅ `test_parser_raises_error_on_oversized_input` - Test parser raises error for oversized input

---

### 10. FR-010: Error Messaging
**Description:** Provide user-friendly error messages for all error conditions.

**Test Coverage:**
- ✅ `test_tag_manager_validates_tag_input` - Test tag manager validates tag input
- ✅ `test_exporter_handles_empty_input` - Test exporter handles empty input gracefully

---

### 11. FR-011: Add Tags to IOCs
**Description:** Assign tags to one or more IOCs for categorization.

**Test Coverage:**
- ✅ `test_add_tag_to_single_ioc` - Test adding tag to a single IOC
- ✅ `test_add_tag_to_multiple_iocs` - Test adding tag to multiple IOCs
- ✅ `test_add_empty_tag_raises_error` - Test adding empty tag raises ValueError
- ✅ `test_add_tag_with_forbidden_chars_raises_error` - Test adding tag with forbidden characters
- ✅ `test_multiple_tags_on_single_ioc` - Test adding multiple tags to a single IOC

---

### 12. FR-012: Manage Tags
**Description:** Rename or delete tags across all associated IOCs.

**Test Coverage:**
- ✅ `test_remove_tag` - Test removing a tag
- ✅ `test_remove_nonexistent_tag` - Test removing non-existent tag returns False
- ✅ `test_rename_tag` - Test renaming a tag
- ✅ `test_rename_nonexistent_tag` - Test renaming non-existent tag returns False
- ✅ `test_rename_tag_to_empty_name_raises_error` - Test renaming tag to empty name raises error
- ✅ `test_get_all_tags` - Test getting all tags

---

### 13. FR-013: Export Tags with IOCs
**Description:** Include tags as additional fields in exported files.

**Test Coverage:**
- ✅ Covered by export tests with `include_tags=True` parameter
- ✅ `test_export_csv_with_tags`
- ✅ `test_export_json_with_tags`
- ✅ `test_export_txt_with_tags`

---

## Integration Tests

### End-to-End Workflows
**Test Coverage:**
- ✅ `test_full_workflow_parse_categorize_tag_export` - Complete workflow from parsing to export
- ✅ `test_search_tagged_iocs` - Search and export tagged IOCs
- ✅ `test_session_with_multiple_operations` - Session manager with multiple operations
- ✅ `test_defang_then_export` - Defang IOCs before export

---

## Test Statistics

**Total Functional Requirements:** 13  
**Total Test Cases:** 60+  
**Test Classes:** 8  
**Integration Tests:** 4  

### Coverage by Component:
- **IOCParser:** 12 tests
- **Categorizer:** 3 tests
- **FangerDefanger:** 5 tests
- **Searcher:** 5 tests
- **Exporter:** 8 tests
- **SessionManager:** 4 tests
- **TagManager:** 13 tests
- **Error Handling:** 4 tests
- **Integration:** 4 tests

---

## Running the Tests

### Prerequisites
```bash
pip install pytest --break-system-packages
```

### Run All Tests
```bash
pytest test_iocreaper.py -v
```

### Run Specific Test Class
```bash
pytest test_iocreaper.py::TestIOCParser -v
```

### Run with Coverage Report
```bash
pip install pytest-cov --break-system-packages
pytest test_iocreaper.py --cov=. --cov-report=html
```

### Run Specific Test
```bash
pytest test_iocreaper.py::TestIOCParser::test_parse_valid_ipv4 -v
```

---

## Test Organization

The test suite is organized by functional requirement and component:

1. **TestIOCParser** - Tests for FR-001 (Parse IOCs)
2. **TestCategorizer** - Tests for FR-002 (Categorize IOCs)
3. **TestFangerDefanger** - Tests for FR-003 (Normalization)
4. **TestSearcher** - Tests for FR-004 (Search)
5. **TestExporter** - Tests for FR-005 & FR-006 (Copy & Export)
6. **TestSessionManager** - Tests for FR-007 & FR-008 (Session Management)
7. **TestTagManager** - Tests for FR-011, FR-012, FR-013 (Tagging)
8. **TestErrorHandling** - Tests for FR-009 & FR-010 (Validation & Errors)
9. **TestIntegrationScenarios** - End-to-end workflow tests

---

## Success Criteria

Each test validates:
- ✅ **Functional correctness** - Does the feature work as specified?
- ✅ **Error handling** - Are errors caught and reported appropriately?
- ✅ **Edge cases** - Empty inputs, invalid inputs, boundary conditions
- ✅ **Integration** - Do components work together correctly?
- ✅ **Data integrity** - Is data preserved and transformed correctly?

---

## Notes

- All tests follow pytest conventions
- Tests are independent and can run in any order
- Mock classes are provided for demonstration
- In actual implementation, import real application modules instead
- Tests cover both happy paths and error scenarios
- Integration tests verify end-to-end functionality
