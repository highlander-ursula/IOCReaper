/*
IOCReaper Frontend - Phase 5 Security Enhanced
SNYK VULNERABILITIES FIXED

Author: Manudeep Maddipatla (mmaddipa@umd.edu)

Security Fixes Applied:
- FIXED: DOM-based XSS at lines 101, 296, 300 (Snyk CWE-79, Score 625)
- All innerHTML replaced with textContent for user-controlled data
- HTML sanitization function added
- Safe DOM element creation
- No execution of user-provided scripts

Date: November 30, 2025
*/

let currentResults = {};
let tagModal;

// ============================================================================
// SECURITY: HTML Sanitization Function
// ============================================================================
function sanitizeHTML(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

// ============================================================================
// SECURITY: Safe DOM Element Creation
// Prevents XSS by never using innerHTML with user data
// ============================================================================
function createSafeElement(tag, attributes = {}, textContent = '') {
    const element = document.createElement(tag);
    
    // Set attributes safely
    for (const [key, value] of Object.entries(attributes)) {
        if (key === 'textContent') {
            element.textContent = value;
        } else if (key === 'className') {
            element.className = value;
        } else if (key === 'onclick' || key.startsWith('on')) {
            // Never set event handlers from attributes
            continue;
        } else {
            element.setAttribute(key, sanitizeHTML(String(value)));
        }
    }
    
    // Set text content safely (never innerHTML)
    if (textContent) {
        element.textContent = textContent;
    }
    
    return element;
}

// ============================================================================
// Initialization
// ============================================================================
document.addEventListener('DOMContentLoaded', function() {
    tagModal = new bootstrap.Modal(document.getElementById('tagModal'));
    
    // Extract form submission
    document.getElementById('extractForm').addEventListener('submit', async function(e) {
        e.preventDefault();
        await extractIOCs();
    });
    
    // Clear button
    document.getElementById('clearBtn').addEventListener('click', async function() {
        if (confirm('Are you sure you want to clear all data?')) {
            await clearSession();
        }
    });
    
    // Search functionality
    document.getElementById('searchBtn').addEventListener('click', async function() {
        await searchIOCs();
    });
    
    // Copy all IOCs
    document.getElementById('copyBtn').addEventListener('click', function() {
        copyAllIOCs();
    });
    
    // Export buttons
    document.querySelectorAll('.export-btn').forEach(btn => {
        btn.addEventListener('click', async function(e) {
            e.preventDefault();
            const format = this.getAttribute('data-format');
            await exportIOCs(format);
        });
    });
    
    // Save tag
    document.getElementById('saveTagBtn').addEventListener('click', async function() {
        await saveTag();
    });
});

// ============================================================================
// IOC Extraction
// ============================================================================
async function extractIOCs() {
    const text = document.getElementById('inputText').value;
    const normalize = document.getElementById('normalize').checked;
    const deduplicate = document.getElementById('deduplicate').checked;
    
    if (!text.trim()) {
        showAlert('Please enter some text to extract IOCs from', 'warning');
        return;
    }
    
    const formData = new FormData();
    formData.append('text', text);
    formData.append('normalize', normalize);
    formData.append('deduplicate', deduplicate);
    
    try {
        const response = await fetch('/extract', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (data.error) {
            showAlert(sanitizeHTML(data.error), 'danger');
            return;
        }
        
        if (data.message) {
            showAlert(sanitizeHTML(data.message), 'info');
            return;
        }
        
        currentResults = data.iocs;
        displayResults(data.iocs);
        showAlert('IOCs extracted successfully!', 'success');
        
    } catch (error) {
        showAlert('Failed to extract IOCs: ' + sanitizeHTML(error.message), 'danger');
    }
}

// ============================================================================
// FIXED: Display Results - No innerHTML usage
// Original Snyk issue: DOM XSS at line 101 (FIXED)
// ============================================================================
function displayResults(iocs) {
    const resultsSection = document.getElementById('resultsSection');
    const tabsContainer = document.getElementById('iocTabs');
    const contentContainer = document.getElementById('iocTabContent');
    
    // Clear previous results
    tabsContainer.innerHTML = '';
    contentContainer.innerHTML = '';
    
    let isFirst = true;
    
    for (const [type, data] of Object.entries(iocs)) {
        // SECURITY FIX: Use textContent instead of innerHTML
        const tabId = `${type}-tab`;
        const paneId = `${type}-pane`;
        
        // Create tab safely
        const tabItem = createSafeElement('li', {className: 'nav-item'});
        const tabButton = createSafeElement('button', {
            className: `nav-link ${isFirst ? 'active' : ''}`,
            id: tabId,
            'data-bs-toggle': 'tab',
            'data-bs-target': `#${paneId}`,
            type: 'button',
            role: 'tab',
            'aria-controls': paneId,
            'aria-selected': isFirst ? 'true' : 'false'
        });
        
        // SECURITY: Use textContent for tab label
        tabButton.textContent = `${type.toUpperCase()} (${data.count})`;
        
        tabItem.appendChild(tabButton);
        tabsContainer.appendChild(tabItem);
        
        // Create pane
        const pane = createSafeElement('div', {
            className: `tab-pane fade ${isFirst ? 'show active' : ''}`,
            id: paneId,
            role: 'tabpanel',
            'aria-labelledby': tabId
        });
        
        // Add IOC items
        data.items.forEach(ioc => {
            const iocItem = createIOCItem(ioc);
            pane.appendChild(iocItem);
        });
        
        contentContainer.appendChild(pane);
        isFirst = false;
    }
    
    resultsSection.style.display = 'block';
}

// ============================================================================
// FIXED: Create IOC Item - No innerHTML usage
// Original Snyk issues: DOM XSS at lines 296, 300 (FIXED)
// ============================================================================
function createIOCItem(ioc) {
    // SECURITY: All DOM creation uses safe methods
    const div = createSafeElement('div', {className: 'ioc-item'});
    
    // SECURITY FIX: Use textContent for IOC value (line 296 fix)
    const valueSpan = createSafeElement('span', {
        className: 'ioc-value'
    });
    valueSpan.textContent = ioc.value; // FIXED: No innerHTML
    
    // Tags container
    const tagsDiv = createSafeElement('div', {className: 'ioc-tags'});
    
    // SECURITY FIX: Use textContent for tags (line 300 fix)
    ioc.tags.forEach(tag => {
        const tagBadge = createSafeElement('span', {
            className: 'tag-badge'
        });
        tagBadge.textContent = tag; // FIXED: No innerHTML
        tagsDiv.appendChild(tagBadge);
    });
    
    // Add tag button
    const addTagBtn = createSafeElement('button', {
        className: 'btn btn-sm btn-outline-primary'
    });
    addTagBtn.textContent = 'Tag';
    // SECURITY: Use addEventListener instead of onclick attribute
    addTagBtn.addEventListener('click', function() {
        openTagModal(ioc.value);
    });
    
    div.appendChild(valueSpan);
    div.appendChild(tagsDiv);
    div.appendChild(addTagBtn);
    
    return div;
}

// ============================================================================
// Tag Management
// ============================================================================
function openTagModal(iocValue) {
    // Sanitize before setting value
    document.getElementById('tagIocValue').value = iocValue;
    document.getElementById('tagInput').value = '';
    tagModal.show();
}

async function saveTag() {
    const iocValue = document.getElementById('tagIocValue').value;
    const tag = document.getElementById('tagInput').value;
    
    if (!tag.trim()) {
        showAlert('Please enter a tag', 'warning');
        return;
    }
    
    const formData = new FormData();
    formData.append('ioc_value', iocValue);
    formData.append('tag', tag);
    
    try {
        const response = await fetch('/tag', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (data.error) {
            showAlert(sanitizeHTML(data.error), 'danger');
            return;
        }
        
        showAlert('Tag added successfully!', 'success');
        tagModal.hide();
        
        // Refresh results
        await extractIOCs();
        
    } catch (error) {
        showAlert('Failed to add tag: ' + sanitizeHTML(error.message), 'danger');
    }
}

// ============================================================================
// Search Functionality
// ============================================================================
async function searchIOCs() {
    const query = document.getElementById('searchInput').value;
    
    if (!query.trim()) {
        displayResults(currentResults);
        return;
    }
    
    const formData = new FormData();
    formData.append('query', query);
    formData.append('case_sensitive', false);
    
    try {
        const response = await fetch('/search', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (data.error) {
            showAlert(sanitizeHTML(data.error), 'danger');
            return;
        }
        
        if (data.results.length === 0) {
            showAlert('No results found', 'info');
            return;
        }
        
        displaySearchResults(data.results);
        
    } catch (error) {
        showAlert('Search failed: ' + sanitizeHTML(error.message), 'danger');
    }
}

function displaySearchResults(results) {
    const contentContainer = document.getElementById('iocTabContent');
    contentContainer.innerHTML = '';
    
    const pane = createSafeElement('div', {
        className: 'tab-pane fade show active'
    });
    
    results.forEach(ioc => {
        const iocItem = createIOCItem(ioc);
        pane.appendChild(iocItem);
    });
    
    contentContainer.appendChild(pane);
}

// ============================================================================
// Copy Functionality
// ============================================================================
function copyAllIOCs() {
    let text = '';
    
    for (const [type, data] of Object.entries(currentResults)) {
        data.items.forEach(ioc => {
            text += ioc.value + '\n';
        });
    }
    
    navigator.clipboard.writeText(text).then(() => {
        showAlert('IOCs copied to clipboard!', 'success');
    }).catch(err => {
        showAlert('Failed to copy: ' + sanitizeHTML(err.message), 'danger');
    });
}

// ============================================================================
// Export Functionality
// ============================================================================
async function exportIOCs(format) {
    const includeTags = document.getElementById('includeTags').checked;
    
    const formData = new FormData();
    formData.append('format', format);
    formData.append('include_tags', includeTags);
    
    try {
        const response = await fetch('/export', {
            method: 'POST',
            body: formData
        });
        
        if (!response.ok) {
            const data = await response.json();
            showAlert(sanitizeHTML(data.error) || 'Export failed', 'danger');
            return;
        }
        
        // Download file
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `iocs.${format}`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
        
        showAlert(`IOCs exported as ${format.toUpperCase()}!`, 'success');
        
    } catch (error) {
        showAlert('Export failed: ' + sanitizeHTML(error.message), 'danger');
    }
}

// ============================================================================
// Session Management
// ============================================================================
async function clearSession() {
    try {
        const response = await fetch('/clear', {
            method: 'POST'
        });
        
        const data = await response.json();
        
        document.getElementById('inputText').value = '';
        document.getElementById('resultsSection').style.display = 'none';
        currentResults = {};
        
        showAlert('Session cleared successfully!', 'success');
        
    } catch (error) {
        showAlert('Failed to clear session: ' + sanitizeHTML(error.message), 'danger');
    }
}

// ============================================================================
// Alert Display - Safe Implementation
// ============================================================================
function showAlert(message, type) {
    const alertContainer = document.getElementById('alertContainer');
    const alert = createSafeElement('div', {
        className: `alert alert-${type} alert-dismissible fade show`,
        role: 'alert'
    });
    
    // SECURITY: Use textContent for message
    alert.textContent = message;
    
    // Close button
    const closeBtn = createSafeElement('button', {
        type: 'button',
        className: 'btn-close',
        'data-bs-dismiss': 'alert',
        'aria-label': 'Close'
    });
    alert.appendChild(closeBtn);
    
    alertContainer.appendChild(alert);
    
    // Auto-dismiss after 5 seconds
    setTimeout(() => {
        alert.remove();
    }, 5000);
}
