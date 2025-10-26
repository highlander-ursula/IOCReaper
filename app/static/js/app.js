let currentResults = {};
let tagModal;

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
            showAlert(data.error, 'danger');
            return;
        }
        
        if (data.message) {
            showAlert(data.message, 'info');
            return;
        }
        
        currentResults = data.iocs;
        displayResults(data.iocs);
        showAlert('IOCs extracted successfully!', 'success');
        
    } catch (error) {
        showAlert('Failed to extract IOCs: ' + error.message, 'danger');
    }
}

function displayResults(iocs) {
    const resultsSection = document.getElementById('resultsSection');
    const tabsContainer = document.getElementById('iocTabs');
    const contentContainer = document.getElementById('iocTabContent');
    
    // Clear previous results
    tabsContainer.innerHTML = '';
    contentContainer.innerHTML = '';
    
    let isFirst = true;
    
    for (const [type, data] of Object.entries(iocs)) {
        // Create tab
        const tabId = `${type}-tab`;
        const paneId = `${type}-pane`;
        
        const tabItem = document.createElement('li');
        tabItem.className = 'nav-item';
        tabItem.innerHTML = `
            <button class="nav-link ${isFirst ? 'active' : ''}" 
                    id="${tabId}" 
                    data-bs-toggle="tab" 
                    data-bs-target="#${paneId}" 
                    type="button">
                ${type.toUpperCase()} (${data.count})
            </button>
        `;
        tabsContainer.appendChild(tabItem);
        
        // Create pane
        const pane = document.createElement('div');
        pane.className = `tab-pane fade ${isFirst ? 'show active' : ''}`;
        pane.id = paneId;
        
        data.items.forEach(ioc => {
            const iocItem = createIOCItem(ioc);
            pane.appendChild(iocItem);
        });
        
        contentContainer.appendChild(pane);
        isFirst = false;
    }
    
    resultsSection.style.display = 'block';
}

function createIOCItem(ioc) {
    const div = document.createElement('div');
    div.className = 'ioc-item';
    
    const valueSpan = document.createElement('span');
    valueSpan.className = 'ioc-value';
    valueSpan.textContent = ioc.value;
    
    const tagsDiv = document.createElement('div');
    tagsDiv.className = 'ioc-tags';
    
    ioc.tags.forEach(tag => {
        const tagBadge = document.createElement('span');
        tagBadge.className = 'tag-badge';
        tagBadge.textContent = tag;
        tagsDiv.appendChild(tagBadge);
    });
    
    const addTagBtn = document.createElement('button');
    addTagBtn.className = 'btn btn-sm btn-outline-primary';
    addTagBtn.textContent = 'Tag';
    addTagBtn.onclick = () => openTagModal(ioc.value);
    
    div.appendChild(valueSpan);
    div.appendChild(tagsDiv);
    div.appendChild(addTagBtn);
    
    return div;
}

function openTagModal(iocValue) {
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
            showAlert(data.error, 'danger');
            return;
        }
        
        showAlert('Tag added successfully!', 'success');
        tagModal.hide();
        
        // Refresh results
        await extractIOCs();
        
    } catch (error) {
        showAlert('Failed to add tag: ' + error.message, 'danger');
    }
}

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
            showAlert(data.error, 'danger');
            return;
        }
        
        if (data.results.length === 0) {
            showAlert('No results found', 'info');
            return;
        }
        
        // Display search results
        displaySearchResults(data.results);
        
    } catch (error) {
        showAlert('Search failed: ' + error.message, 'danger');
    }
}

function displaySearchResults(results) {
    const contentContainer = document.getElementById('iocTabContent');
    contentContainer.innerHTML = '';
    
    const pane = document.createElement('div');
    pane.className = 'tab-pane fade show active';
    
    results.forEach(ioc => {
        const iocItem = createIOCItem(ioc);
        pane.appendChild(iocItem);
    });
    
    contentContainer.appendChild(pane);
}

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
        showAlert('Failed to copy: ' + err.message, 'danger');
    });
}

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
            showAlert(data.error || 'Export failed', 'danger');
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
        showAlert('Export failed: ' + error.message, 'danger');
    }
}

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
        showAlert('Failed to clear session: ' + error.message, 'danger');
    }
}

function showAlert(message, type) {
    const alertContainer = document.getElementById('alertContainer');
    const alert = document.createElement('div');
    alert.className = `alert alert-${type} alert-dismissible fade show`;
    alert.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    alertContainer.appendChild(alert);
    
    setTimeout(() => {
        alert.remove();
    }, 5000);
}