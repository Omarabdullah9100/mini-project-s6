# Setup and Run Instructions

## 📋 Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Internet connection (for Google Search API)
- Gmail account (for email reporting)

## 🚀 Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure Environment Variables

Open the `.env` file and update the following:

```env
# Email Configuration (Required for sending reports)
SMTP_EMAIL=your_email@gmail.com
SMTP_PASSWORD=your_gmail_app_password
```

**How to get Gmail App Password:**
1. Go to Google Account Settings
2. Security → 2-Step Verification (enable if not enabled)
3. App Passwords → Select "Mail" and "Other"
4. Copy the generated 16-character password
5. Paste it in `.env` file as `SMTP_PASSWORD`

### 3. Initialize Database

The database will be automatically created on first run. No manual setup required.

### 4. Run the Application

```bash
python main.py
```

The application will start at: **http://localhost:8000**

## 📊 Usage Guide

### Module 1: Sensitive Data Detection

1. **Open Browser**: Navigate to http://localhost:8000
2. **Select Module 1**: Click on "Sensitive Data Exposure Detection" button
3. **Configure Scan**:
   - Select data types (Aadhaar, PAN, Bank Account, etc.)
   - Select file types (PDF, DOC, DOCX)
   - Set domain scope (default: gov.in)
   - Set max results (recommended: 10 for testing)
   - Enable/disable automatic email reporting
4. **Start Scan**: Click "🚀 Start Scan"
5. **Monitor Progress**: Watch real-time scan progress
6. **View Results**: Detections will appear in a table with confidence scores
7. **Export**: Download results as CSV

### API Endpoints

#### Start Scan
```bash
POST /api/scan/sensitive-data
Content-Type: application/json

{
  "data_types": ["aadhaar", "pan"],
  "file_types": ["pdf", "doc"],
  "domain": "gov.in",
  "max_results": 10,
  "send_email": true
}
```

#### Check Scan Status
```bash
GET /api/scan/{scan_id}/status
```

#### Get Recent Scans
```bash
GET /api/scans/recent?limit=10
```

#### Test Email
```bash
POST /api/test-email
```

## 🔧 Troubleshooting

### Import Errors
If you see import errors, install dependencies:
```bash
pip install -r requirements.txt
```

### Google API Quota Exceeded
The system automatically rotates between multiple API keys. If all keys are exhausted:
- Wait 24 hours for quota reset
- Add more API keys to `.env` file

### Email Sending Failed
- Verify Gmail App Password is correct
- Check if 2-Step Verification is enabled
- Ensure "Less secure app access" is OFF (use App Password instead)

### No Search Results
- Verify Google API keys are active
- Check Search Engine IDs are correct
- Ensure internet connection is stable

## 📁 Project Structure

```
mini-project-s6/
├── main.py                      # FastAPI application
├── config.py                    # Configuration settings
├── models.py                    # Database models
├── database.py                  # Database initialization
├── google_search.py             # Google Search API integration
├── document_processor.py        # Document text extraction
├── sensitive_data_detector.py   # Pattern matching
├── email_reporter.py            # Email reporting
├── requirements.txt             # Python dependencies
├── .env                         # Environment variables
├── .gitignore                   # Git ignore rules
├── raedme.md                    # Project documentation
└── static/                      # Frontend files
    ├── index.html               # Main HTML page
    ├── styles.css               # Black & white design
    └── script.js                # JavaScript logic
```

## 🔐 Security Notes

- Keep `.env` file secure and never commit to Git
- Gmail App Password should be unique and not reused
- API keys should be kept confidential
- This tool is for **authorized security research only**

## 📧 Email Report Format

When detections are found, an automated email is sent to `vdisclose@cert-in.org.in` with:
- Executive summary
- Total files affected
- Detection details with confidence scores
- File URLs with anonymized evidence
- Recommended actions

## 🎯 Testing

### Test Email Configuration
```bash
curl -X POST http://localhost:8000/api/test-email
```

### Test Scan (Small Dataset)
Use `max_results: 5` for quick testing

## 🔄 Next Steps (Module 2 - Coming Soon)

Module 2 will add:
- Phishing website detection
- Domain analysis
- SSL certificate validation
- WHOIS lookup
- Risk scoring

## 📞 Support

For issues or questions:
- Check the troubleshooting section above
- Review API documentation at http://localhost:8000/docs
- Contact: vdisclose@cert-in.org.in

---

**⚠️ Important**: This framework is designed for ethical security research and authorized vulnerability disclosure only.
