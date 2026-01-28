// JavaScript for Cybersecurity Detection Framework

const API_BASE_URL = '';

// Module selection
function selectModule(module) {
    const module1Section = document.getElementById('module1Section');
    const module2Section = document.getElementById('module2Section');
    const buttons = document.querySelectorAll('.module-button');
    
    if (module === 'module1') {
        module1Section.style.display = 'block';
        module2Section.style.display = 'none';
        buttons[0].classList.add('active');
        buttons[1].classList.remove('active');
    } else if (module === 'module2') {
        module1Section.style.display = 'none';
        module2Section.style.display = 'block';
        buttons[0].classList.remove('active');
        buttons[1].classList.add('active');
    }
}

// Start scan
async function startScan() {
    try {
        // Get selected data types
        const dataTypeCheckboxes = document.querySelectorAll('input[name="dataType"]:checked');
        const dataTypes = Array.from(dataTypeCheckboxes).map(cb => cb.value);
        
        if (dataTypes.length === 0) {
            alert('Please select at least one data type to detect');
            return;
        }
        
        // Get selected file types
        const fileTypeCheckboxes = document.querySelectorAll('input[name="fileType"]:checked');
        const fileTypes = Array.from(fileTypeCheckboxes).map(cb => cb.value);
        
        if (fileTypes.length === 0) {
            alert('Please select at least one file type');
            return;
        }
        
        // Get other parameters
        const domain = document.getElementById('domain').value;
        const maxResults = parseInt(document.getElementById('maxResults').value);
        const sendEmail = document.getElementById('sendEmail').checked;
        
        // Prepare request
        const requestData = {
            data_types: dataTypes,
            file_types: fileTypes,
            domain: domain,
            max_results: maxResults,
            send_email: sendEmail
        };
        
        // Show progress panel
        document.getElementById('progressPanel').style.display = 'block';
        document.getElementById('resultsPanel').style.display = 'none';
        document.getElementById('progressText').textContent = 'Initializing scan...';
        
        // Send request
        const response = await fetch('/api/scan/sensitive-data', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(requestData)
        });
        
        const result = await response.json();
        
        if (response.ok) {
            const scanId = result.scan_id;
            document.getElementById('scanId').textContent = scanId;
            document.getElementById('progressText').textContent = 'Scan in progress... This may take a few minutes.';
            
            // Poll for results
            pollScanStatus(scanId);
        } else {
            alert('Error starting scan: ' + result.detail);
            document.getElementById('progressPanel').style.display = 'none';
        }
        
    } catch (error) {
        console.error('Error:', error);
        alert('Error starting scan: ' + error.message);
        document.getElementById('progressPanel').style.display = 'none';
    }
}

// Poll scan status
let pollInterval;
function pollScanStatus(scanId) {
    let progress = 0;
    
    pollInterval = setInterval(async () => {
        try {
            const response = await fetch(`/api/scan/${scanId}/status`);
            const data = await response.json();
            
            // Update UI
            document.getElementById('scanStatus').textContent = data.status;
            document.getElementById('detectionsCount').textContent = data.results_count;
            
            // Update progress bar
            if (data.status === 'in_progress') {
                progress = Math.min(progress + 10, 90);
                document.getElementById('progressFill').style.width = progress + '%';
            } else if (data.status === 'completed') {
                clearInterval(pollInterval);
                document.getElementById('progressFill').style.width = '100%';
                document.getElementById('progressText').textContent = 'Scan completed!';
                
                // Show results
                setTimeout(() => {
                    displayResults(data);
                }, 1000);
            } else if (data.status === 'failed') {
                clearInterval(pollInterval);
                alert('Scan failed. Please try again.');
                document.getElementById('progressPanel').style.display = 'none';
            }
            
        } catch (error) {
            console.error('Error polling status:', error);
        }
    }, 3000); // Poll every 3 seconds
}

// Display results
function displayResults(data) {
    document.getElementById('progressPanel').style.display = 'none';
    document.getElementById('resultsPanel').style.display = 'block';
    
    const detections = data.detections || [];
    
    // Results summary
    const summary = document.getElementById('resultsSummary');
    summary.innerHTML = `
        <h4>📊 Scan Summary</h4>
        <p><strong>Scan ID:</strong> ${data.scan_id}</p>
        <p><strong>Status:</strong> ${data.status}</p>
        <p><strong>Total Detections:</strong> ${data.results_count}</p>
        <p><strong>Started:</strong> ${new Date(data.start_time).toLocaleString()}</p>
        <p><strong>Completed:</strong> ${new Date(data.end_time).toLocaleString()}</p>
    `;
    
    // Results table
    const tbody = document.getElementById('resultsTableBody');
    tbody.innerHTML = '';
    
    if (detections.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; padding: 40px;">✅ No sensitive data leaks detected!</td></tr>';
    } else {
        detections.forEach(urlItem => {
            // Get all detections for this URL
            const urlDetections = urlItem.detections || [];
            
            if (urlDetections.length === 0) {
                return;
            }
            
            // Consolidate data types
            const dataTypes = urlItem.data_types || [];
            
            // Get highest confidence
            const confidences = urlDetections.map(d => d.confidence).filter(c => c !== undefined && c !== null);
            const maxConfidence = confidences.length > 0 ? Math.max(...confidences) : 0;
            const confidenceClass = maxConfidence >= 80 ? 'confidence-high' : 'confidence-medium';
            
            // Get first evidence for context
            const firstDetection = urlDetections[0];
            let evidence = '';
            try {
                if (typeof firstDetection.evidence === 'string') {
                    evidence = JSON.parse(firstDetection.evidence).context || firstDetection.evidence;
                } else {
                    evidence = firstDetection.evidence || '';
                }
            } catch {
                evidence = firstDetection.evidence || '';
            }
            
            const row = document.createElement('tr');
            const leakIds = urlDetections.map(d => d.leak_id).join(',');
            row.innerHTML = `
                <td><strong>${dataTypes.join(', ').replace(/_/g, ' ').toUpperCase()}</strong></td>
                <td><a href="${urlItem.file_url}" target="_blank" style="color: #000; text-decoration: underline;">${urlItem.file_url.substring(0, 60)}...</a></td>
                <td class="${confidenceClass}">${maxConfidence !== undefined && !isNaN(maxConfidence) ? maxConfidence.toFixed(1) : '0'}%</td>
                <td>${evidence.substring(0, 80)}...</td>
                <td><button class="btn-delete" onclick="deleteDetection('${leakIds}')" title="Delete this detection">🗑️ Delete</button></td>
            `;
            tbody.appendChild(row);
        });
    }
    
    // Load recent scans
    loadRecentScans();
}

// Export results
function exportResults() {
    const table = document.getElementById('resultsTable');
    let csv = [];
    
    // Headers (exclude Action column)
    const headers = Array.from(table.querySelectorAll('thead th'))
        .slice(0, 4)
        .map(th => th.textContent);
    csv.push(headers.join(','));
    
    // Rows (exclude Action column)
    const rows = table.querySelectorAll('tbody tr');
    rows.forEach(row => {
        const cells = Array.from(row.querySelectorAll('td'))
            .slice(0, 4)
            .map(td => `"${td.textContent}"`);
        csv.push(cells.join(','));
    });
    
    // Download
    const csvContent = csv.join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `scan_results_${new Date().getTime()}.csv`;
    a.click();
}

// View full report
function viewFullReport() {
    alert('Full report generation feature coming soon!');
}

// Reset scan
function resetScan() {
    document.getElementById('progressPanel').style.display = 'none';
    document.getElementById('resultsPanel').style.display = 'none';
    document.getElementById('progressFill').style.width = '0%';
    
    // Scroll to top
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

// Load recent scans
async function loadRecentScans() {
    try {
        const response = await fetch('/api/scans/recent?limit=5');
        const data = await response.json();
        
        const scansList = document.getElementById('recentScansList');
        scansList.innerHTML = '';
        
        if (data.scans && data.scans.length > 0) {
            data.scans.forEach(scan => {
                const scanItem = document.createElement('div');
                scanItem.className = 'scan-item';
                scanItem.onclick = () => viewScanDetails(scan.scan_id);
                
                scanItem.innerHTML = `
                    <strong>Scan #${scan.scan_id}</strong> - ${scan.scan_type}<br>
                    Status: ${scan.status} | Results: ${scan.results_count}<br>
                    <small>${new Date(scan.start_time).toLocaleString()}</small>
                `;
                
                scansList.appendChild(scanItem);
            });
        } else {
            scansList.innerHTML = '<p class="empty-state">No recent scans. Start your first scan above.</p>';
        }
    } catch (error) {
        console.error('Error loading recent scans:', error);
    }
}

// View scan details
async function viewScanDetails(scanId) {
    try {
        const response = await fetch(`/api/scan/${scanId}/status`);
        const data = await response.json();
        displayResults(data);
        window.scrollTo({ top: 0, behavior: 'smooth' });
    } catch (error) {
        console.error('Error loading scan details:', error);
    }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    loadRecentScans();
});

// Delete detection
async function deleteDetection(leakIds) {
    if (!confirm('Are you sure you want to delete this detection record?')) {
        return;
    }
    
    try {
        const response = await fetch('/api/detections/delete', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ leak_ids: leakIds.split(',').map(Number) })
        });
        
        if (response.ok) {
            alert('Detection record deleted successfully!');
            // Reload the table
            const currentScanId = document.getElementById('scanId').textContent;
            if (currentScanId && currentScanId !== '-') {
                viewScanDetails(parseInt(currentScanId));
            }
        } else {
            const error = await response.json();
            alert('Error deleting detection: ' + (error.detail || 'Unknown error'));
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Error deleting detection: ' + error.message);
    }
}
// ============ MODULE 2: PHISHING DETECTION ============

// Start phishing scan
async function startPhishingScan() {
    try {
        const domain = "gov.in";  // Fixed domain
        
        const requestData = {
            domain: domain,
            scan_type: "full",
            max_domains: 100
        };
        
        // Show scanning panel
        document.getElementById('scanningPanel').style.display = 'block';
        document.getElementById('phishingResultsPanel').style.display = 'none';
        
        // Send request
        const response = await fetch('/api/scan/phishing', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(requestData)
        });
        
        const result = await response.json();
        
        if (response.ok) {
            const scanId = result.scan_id;
            
            // Poll for results
            pollPhishingScanStatus(scanId);
        } else {
            alert('Error starting scan: ' + result.detail);
            document.getElementById('scanningPanel').style.display = 'none';
        }
        
    } catch (error) {
        console.error('Error:', error);
        alert('Error starting scan: ' + error.message);
        document.getElementById('scanningPanel').style.display = 'none';
    }
}

// Poll phishing scan status
let phishingPollInterval;
function pollPhishingScanStatus(scanId) {
    phishingPollInterval = setInterval(async () => {
        try {
            const response = await fetch(`/api/scan/${scanId}/phishing`);
            const data = await response.json();
            
            // Update scanning status
            let statusText = 'Enumerating subdomains...';
            if (data.status === 'scanning') {
                statusText = 'Analyzing domains for phishing...';
            }
            document.getElementById('scanningStatus').textContent = statusText;
            document.getElementById('scanProgress').textContent = `${data.results_count} domains analyzed`;
            
            if (data.status === 'completed') {
                clearInterval(phishingPollInterval);
                document.getElementById('scanningStatus').textContent = '✅ Scan Complete!';
                
                // Show results after brief delay
                setTimeout(() => {
                    displayPhishingResults(data);
                }, 1000);
            } else if (data.status === 'failed') {
                clearInterval(phishingPollInterval);
                alert('Scan failed. Please check if waybackurls CLI is installed.');
                document.getElementById('scanningPanel').style.display = 'none';
            }
            
        } catch (error) {
            console.error('Error polling status:', error);
        }
    }, 2000);
}

// Display phishing results
function displayPhishingResults(data) {
    document.getElementById('scanningPanel').style.display = 'none';
    document.getElementById('phishingResultsPanel').style.display = 'block';
    
    const results = data.results || [];
    
    // Results summary
    const summary = document.getElementById('phishingResultsSummary');
    const criticalCount = results.filter(r => r.risk_level === 'CRITICAL').length;
    const highCount = results.filter(r => r.risk_level === 'HIGH').length;
    const mediumCount = results.filter(r => r.risk_level === 'MEDIUM').length;
    
    summary.innerHTML = `
        <h4>📊 Detection Summary</h4>
        <p><strong>Scan ID:</strong> ${data.scan_id}</p>
        <p><strong>Total Domains Scanned:</strong> ${data.results_count}</p>
        <div class="risk-breakdown">
            <span class="risk-critical">🔴 Critical: ${criticalCount}</span>
            <span class="risk-high">🟠 High: ${highCount}</span>
            <span class="risk-medium">🟡 Medium: ${mediumCount}</span>
        </div>
    `;
    
    // Store results globally for filtering
    window.allPhishingResults = results;
    
    // Display results
    displayPhishingResultsTable(results);
}

// Display phishing results table
function displayPhishingResultsTable(results) {
    const tbody = document.getElementById('phishingResultsTableBody');
    tbody.innerHTML = '';
    
    if (results.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; padding: 40px;">✅ No phishing indicators detected!</td></tr>';
    } else {
        results.forEach((result, index) => {
            const riskColor = {
                'CRITICAL': '#dc3545',
                'HIGH': '#ff9800',
                'MEDIUM': '#ffc107',
                'LOW': '#28a745'
            }[result.risk_level] || '#666';
            
            const indicatorsText = (result.indicators || []).slice(0, 2).join(' | ') || 'No specific indicators';
            
            const row = document.createElement('tr');
            row.innerHTML = `
                <td><strong>${result.domain || 'N/A'}</strong></td>
                <td style="color: ${riskColor}; font-weight: bold;">${result.risk_level || 'N/A'}</td>
                <td><strong>${result.phishing_percentage || 0}%</strong></td>
                <td><small>${indicatorsText}</small></td>
                <td><button class="btn-info" onclick="showPhishingDetails(${index})">📋 Details</button></td>
            `;
            tbody.appendChild(row);
        });
    }
}

// Show phishing details
function showPhishingDetails(index) {
    const result = window.allPhishingResults[index];
    const details = `
Domain: ${result.domain}
Risk Level: ${result.risk_level}
Phishing Score: ${result.phishing_percentage}%

Indicators Found:
${(result.indicators || []).map((ind, i) => `  ${i+1}. ${ind}`).join('\n')}

Details:
${JSON.stringify(result, null, 2)}
    `;
    alert(details);
}

// Filter phishing results
function filterPhishingResults(level) {
    const filterBtns = document.querySelectorAll('.filter-btn');
    filterBtns.forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');
    
    let filtered = window.allPhishingResults;
    if (level !== 'all') {
        filtered = window.allPhishingResults.filter(r => r.risk_level === level);
    }
    
    displayPhishingResultsTable(filtered);
}

// Export phishing results
function exportPhishingResults() {
    const results = window.allPhishingResults || [];
    let csv = ['Domain,Risk Level,Phishing %,Indicators'];
    
    results.forEach(result => {
        const indicators = (result.indicators || []).join('; ');
        csv.push(`"${result.domain}","${result.risk_level}","${result.phishing_percentage}","${indicators}"`);
    });
    
    const csvContent = csv.join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `phishing_results_${new Date().getTime()}.csv`;
    a.click();
}

// Reset phishing scan
function resetPhishingScan() {
    document.getElementById('scanningPanel').style.display = 'none';
    document.getElementById('phishingResultsPanel').style.display = 'none';
    window.allPhishingResults = [];
    
    // Scroll to top
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    loadRecentScans();
});