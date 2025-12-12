# Testing Guide - Module 1

## 🧪 Complete Testing Checklist

### Prerequisites
- [ ] Python 3.8+ installed
- [ ] All dependencies installed (`pip install -r requirements.txt`)
- [ ] `.env` file configured with valid credentials
- [ ] Internet connection active

---

## 1️⃣ Installation Testing

### Test 1.1: Dependency Installation
```bash
cd /Users/omarabdullah/Downloads/mini-project-s6
pip install -r requirements.txt
```

**Expected Output:**
- All packages installed successfully
- No error messages

**Troubleshooting:**
- If errors occur, try: `pip install --upgrade pip`
- Use Python 3.8 or higher

---

### Test 1.2: Database Initialization
```bash
python -c "from database import init_db; init_db()"
```

**Expected Output:**
```
✅ Database initialized successfully!
```

**Verify:**
- File `cybersecurity.db` created in project root

---

## 2️⃣ Configuration Testing

### Test 2.1: Environment Variables
```bash
python -c "from config import settings; print(f'API Keys: {len(settings.google_api_keys)}'); print(f'Email: {settings.smtp_email}')"
```

**Expected Output:**
```
API Keys: 6
Email: your_email@gmail.com
```

---

### Test 2.2: Google API Keys Validation
```bash
python -c "from config import get_next_api_key; api_key, search_id = get_next_api_key(); print(f'API Key: {api_key[:10]}...'); print(f'Search ID: {search_id}')"
```

**Expected Output:**
```
API Key: AIzaSyCdc-...
Search ID: 528bf601158584f50
```

---

## 3️⃣ Backend Testing

### Test 3.1: Start Application
```bash
python main.py
```

**Expected Output:**
```
✅ Database initialized successfully!
🚀 Application started successfully!
INFO:     Started server process [xxxxx]
INFO:     Uvicorn running on http://0.0.0.0:8000
```

**Verify:**
- Server starts without errors
- No import errors
- Port 8000 is available

---

### Test 3.2: Health Check
```bash
curl http://localhost:8000/api/health
```

**Expected Response:**
```json
{
  "status": "healthy",
  "timestamp": "2025-12-12T...",
  "module": "sensitive_data_detection"
}
```

---

### Test 3.3: API Documentation
Open browser: http://localhost:8000/docs

**Verify:**
- Swagger UI loads successfully
- All endpoints visible:
  - POST /api/scan/sensitive-data
  - GET /api/scan/{scan_id}/status
  - GET /api/scans/recent
  - POST /api/test-email

---

## 4️⃣ Email Testing

### Test 4.1: SMTP Configuration
```bash
curl -X POST http://localhost:8000/api/test-email
```

**Expected Response:**
```json
{
  "status": "success",
  "message": "Test email sent successfully"
}
```

**Verify:**
- Check your email inbox
- Test email received
- Subject: "Test Email - Cybersecurity Detection Framework"

**Troubleshooting:**
- Verify Gmail App Password is correct
- Check spam folder
- Ensure 2-Step Verification enabled

---

## 5️⃣ Google Search API Testing

### Test 5.1: Search Functionality
```python
# Create test_google_search.py
from google_search import GoogleSearchAPI

api = GoogleSearchAPI()
results = api.search("site:gov.in ext:pdf test", num_results=5)
print(f"✅ Found {len(results)} results")
for r in results[:3]:
    print(f"  - {r['title']}")
```

**Run:**
```bash
python test_google_search.py
```

**Expected Output:**
```
✅ Found 5 results
  - Document Title 1
  - Document Title 2
  - Document Title 3
```

---

## 6️⃣ Document Processing Testing

### Test 6.1: PDF Processing
```python
# test_document_processing.py
from document_processor import DocumentProcessor

processor = DocumentProcessor()

# Test with a public PDF
url = "https://www.example.gov.in/sample.pdf"
try:
    content, ext = processor.download_file(url)
    text = processor.extract_text(content, ext)
    print(f"✅ Extracted {len(text)} characters")
except Exception as e:
    print(f"Note: {e}")
```

---

## 7️⃣ Pattern Detection Testing

### Test 7.1: Aadhaar Detection
```python
# test_pattern_detection.py
from sensitive_data_detector import SensitiveDataDetector

detector = SensitiveDataDetector()

# Test text with sample Aadhaar pattern
test_text = """
This document contains aadhaar number: 1234 5678 9012
Another reference: PAN card ABCDE1234F
"""

detections = detector.detect_all(test_text)
print(f"✅ Detections: {detections}")
```

**Expected Output:**
```
✅ Detections: {
  'aadhaar': [...],
  'pan': [...]
}
```

---

## 8️⃣ Frontend Testing

### Test 8.1: Page Load
1. Open browser: http://localhost:8000
2. Verify:
   - [ ] Page loads successfully
   - [ ] Black & white design visible
   - [ ] Two module buttons displayed
   - [ ] Module 1 marked as "Active"
   - [ ] Module 2 marked as "Coming Soon"

---

### Test 8.2: Module Selection
1. Click "Module 1" button
2. Verify:
   - [ ] Scan configuration panel visible
   - [ ] Checkboxes for data types
   - [ ] File type selectors
   - [ ] Domain input field
   - [ ] "Start Scan" button

---

## 9️⃣ End-to-End Scan Testing

### Test 9.1: Small Test Scan

**Configuration:**
- Data Types: Aadhaar, PAN
- File Types: PDF
- Domain: gov.in
- Max Results: 5
- Send Email: ✓ (checked)

**Steps:**
1. Open http://localhost:8000
2. Configure as above
3. Click "🚀 Start Scan"
4. Monitor progress panel
5. Wait for completion (2-5 minutes)

**Expected Behavior:**
- [ ] Progress panel appears
- [ ] Scan ID displayed
- [ ] Status updates to "in_progress"
- [ ] Progress bar animates
- [ ] Detections count updates
- [ ] Status changes to "completed"
- [ ] Results panel appears

**Verify Results:**
- [ ] Results table populated
- [ ] Each detection shows:
  - Data type
  - File URL (clickable)
  - Confidence score
  - Evidence excerpt
- [ ] Export button works
- [ ] Recent scans updated

---

### Test 9.2: API-based Scan
```bash
curl -X POST http://localhost:8000/api/scan/sensitive-data \
  -H "Content-Type: application/json" \
  -d '{
    "data_types": ["aadhaar", "pan"],
    "file_types": ["pdf"],
    "domain": "gov.in",
    "max_results": 5,
    "send_email": true
  }'
```

**Expected Response:**
```json
{
  "scan_id": 1,
  "status": "started",
  "message": "Scan initiated successfully. Scan ID: 1"
}
```

**Check Status:**
```bash
curl http://localhost:8000/api/scan/1/status
```

---

## 🔟 Database Testing

### Test 10.1: Verify Scan Records
```bash
sqlite3 cybersecurity.db "SELECT * FROM scans;"
```

**Expected Output:**
- Scan records with timestamps
- Status: completed/in_progress
- Results count

---

### Test 10.2: Verify Detections
```bash
sqlite3 cybersecurity.db "SELECT data_type, confidence, file_url FROM detected_leaks LIMIT 5;"
```

---

## 1️⃣1️⃣ Performance Testing

### Test 11.1: Response Time
```bash
time curl http://localhost:8000/api/health
```

**Expected:** < 100ms

---

### Test 11.2: Concurrent Scans
Open multiple browser tabs and start scans simultaneously

**Verify:**
- [ ] All scans process without errors
- [ ] Unique scan IDs assigned
- [ ] No database conflicts

---

## 1️⃣2️⃣ Error Handling Testing

### Test 12.1: Invalid Data Types
```bash
curl -X POST http://localhost:8000/api/scan/sensitive-data \
  -H "Content-Type: application/json" \
  -d '{"data_types": [], "file_types": ["pdf"]}'
```

**Expected:** 422 Validation Error

---

### Test 12.2: Invalid Scan ID
```bash
curl http://localhost:8000/api/scan/99999/status
```

**Expected:**
```json
{
  "detail": "Scan not found"
}
```

---

## 📋 Test Results Checklist

### Installation & Configuration
- [ ] Dependencies installed
- [ ] Database initialized
- [ ] Environment variables configured
- [ ] Google API keys validated

### Backend
- [ ] Server starts successfully
- [ ] Health check passes
- [ ] API documentation accessible
- [ ] All endpoints responsive

### Email
- [ ] SMTP configured correctly
- [ ] Test email received
- [ ] HTML formatting correct

### Google Search
- [ ] API connection successful
- [ ] Search results returned
- [ ] API key rotation works

### Document Processing
- [ ] PDF extraction works
- [ ] DOCX extraction works
- [ ] HTML extraction works

### Pattern Detection
- [ ] Aadhaar detection accurate
- [ ] PAN detection accurate
- [ ] Confidence scoring works
- [ ] Validation algorithms work

### Frontend
- [ ] Page loads correctly
- [ ] Black & white design renders
- [ ] Module selection works
- [ ] Form inputs functional

### End-to-End
- [ ] Complete scan executes
- [ ] Results display correctly
- [ ] Email report sent
- [ ] Database updated
- [ ] Export function works

### Performance
- [ ] Response times acceptable
- [ ] Concurrent scans supported
- [ ] No memory leaks

### Error Handling
- [ ] Invalid inputs rejected
- [ ] Error messages clear
- [ ] Graceful degradation

---

## 🐛 Common Issues & Solutions

### Issue: Import Errors
**Solution:**
```bash
pip install -r requirements.txt --upgrade
```

### Issue: Port 8000 Already in Use
**Solution:**
```bash
# Find and kill process
lsof -ti:8000 | xargs kill -9

# Or change port in .env
PORT=8080
```

### Issue: Google API Quota Exceeded
**Solution:**
- Wait 24 hours for reset
- Use different API key
- Reduce max_results

### Issue: Email Not Sending
**Solution:**
- Verify Gmail App Password
- Check SMTP settings
- Test with: `curl -X POST http://localhost:8000/api/test-email`

---

## ✅ Final Validation

All tests passed? You're ready to use Module 1!

**Next Steps:**
1. Run small test scan
2. Verify results accuracy
3. Review email report
4. Proceed to production testing

---

**Last Updated:** December 12, 2025  
**Module Status:** ✅ Ready for Testing
