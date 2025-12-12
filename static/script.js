// JavaScript for Cybersecurity Detection Framework

const API_BASE_URL = '';

// Module selection
function selectModule(module) {
    const module1Section = document.getElementById('module1Section');
    
    if (module === 'module1') {
        module1Section.style.display = 'block';
    } else {
        module1Section.style.display = 'none';
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
        <p><strong>Total Detections:</strong> ${detections.length}</p>
        <p><strong>Started:</strong> ${new Date(data.start_time).toLocaleString()}</p>
        <p><strong>Completed:</strong> ${new Date(data.end_time).toLocaleString()}</p>
    `;
    
    // Results table
    const tbody = document.getElementById('resultsTableBody');
    tbody.innerHTML = '';
    
    if (detections.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; padding: 40px;">✅ No sensitive data leaks detected!</td></tr>';
    } else {
        // Track URLs to avoid duplicates
        const processedUrls = new Set();
        
        detections.forEach(detection => {
            // Skip if URL already displayed
            if (processedUrls.has(detection.file_url)) {
                return;
            }
            processedUrls.add(detection.file_url);
            
            // Get all detections for this URL
            const urlDetections = detections.filter(d => d.file_url === detection.file_url);
            
            // Consolidate data types
            const dataTypes = urlDetections
                .map(d => d.data_type)
                .filter((type, index, self) => self.indexOf(type) === index); // Remove duplicates
            
            // Get highest confidence
            const maxConfidence = Math.max(...urlDetections.map(d => d.confidence));
            const confidenceClass = maxConfidence >= 80 ? 'confidence-high' : 'confidence-medium';
            
            // Get first evidence for context
            const firstDetection = urlDetections[0];
            let evidence = '';
            try {
                evidence = JSON.parse(firstDetection.evidence).context || firstDetection.evidence;
            } catch {
                evidence = firstDetection.evidence || '';
            }
            
            const row = document.createElement('tr');
            row.innerHTML = `
                <td><strong>${dataTypes.join(', ').replace(/_/g, ' ').toUpperCase()}</strong></td>
                <td><a href="${detection.file_url}" target="_blank" style="color: #000; text-decoration: underline;">${detection.file_url.substring(0, 60)}...</a></td>
                <td class="${confidenceClass}">${maxConfidence.toFixed(1)}%</td>
                <td>${evidence.substring(0, 80)}...</td>
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
    
    // Headers
    const headers = Array.from(table.querySelectorAll('thead th')).map(th => th.textContent);
    csv.push(headers.join(','));
    
    // Rows
    const rows = table.querySelectorAll('tbody tr');
    rows.forEach(row => {
        const cells = Array.from(row.querySelectorAll('td')).map(td => `"${td.textContent}"`);
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
