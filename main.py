"""
Main FastAPI application - Module 1: Sensitive Data Detection
"""
from fastapi import FastAPI, BackgroundTasks, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
import json
import logging
import time

# Import custom modules
from database import init_db, get_db
from models import Scan, DetectedLeak, EmailReport, AuditLog
from google_search import GoogleSearchAPI
from document_processor import DocumentProcessor
from sensitive_data_detector import SensitiveDataDetector
from email_reporter import EmailReporter
from config import settings

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Cybersecurity Detection Framework - Module 1",
    description="Automated Sensitive Data & Spoofing Detection System",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Initialize components
google_search = GoogleSearchAPI()
doc_processor = DocumentProcessor()
data_detector = SensitiveDataDetector()
email_reporter = EmailReporter()


# Pydantic models for API requests
class ScanRequest(BaseModel):
    data_types: List[str]  # ['aadhaar', 'pan', 'bank_account', etc.]
    file_types: Optional[List[str]] = ['pdf', 'doc', 'docx']
    domain: Optional[str] = 'gov.in'
    max_results: Optional[int] = 10
    send_email: Optional[bool] = True


class ScanResponse(BaseModel):
    scan_id: int
    status: str
    message: str


@app.on_event("startup")
async def startup_event():
    """Initialize database on startup"""
    init_db()
    logger.info("🚀 Application started successfully!")


@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve the main HTML page"""
    with open("static/index.html", "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "module": "sensitive_data_detection"
    }


@app.post("/api/scan/sensitive-data", response_model=ScanResponse)
async def start_sensitive_data_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Start a sensitive data exposure scan
    """
    try:
        # Create scan record
        scan = Scan(
            scan_type="sensitive_data",
            status="in_progress",
            start_time=datetime.utcnow()
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        
        # Log action
        audit = AuditLog(
            action="scan_started",
            details=json.dumps({
                "scan_id": scan.scan_id,
                "data_types": request.data_types,
                "domain": request.domain
            }),
            status="success"
        )
        db.add(audit)
        db.commit()
        
        # Start background task
        background_tasks.add_task(
            execute_sensitive_data_scan,
            scan.scan_id,
            request.data_types,
            request.file_types,
            request.domain,
            request.max_results,
            request.send_email
        )
        
        logger.info(f"✅ Scan {scan.scan_id} started")
        
        return ScanResponse(
            scan_id=scan.scan_id,
            status="started",
            message=f"Scan initiated successfully. Scan ID: {scan.scan_id}"
        )
        
    except Exception as e:
        logger.error(f"❌ Scan start failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/scan/{scan_id}/status")
async def get_scan_status(scan_id: int, db: Session = Depends(get_db)):
    """Get scan status and results with consolidated URLs"""
    scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Get detections
    detections = db.query(DetectedLeak).filter(DetectedLeak.scan_id == scan_id).all()
    
    # Consolidate detections by URL to avoid repetition
    consolidated_results = {}
    for d in detections:
        url = d.file_url
        if url not in consolidated_results:
            consolidated_results[url] = {
                "file_url": url,
                "data_types": [],
                "detections": []
            }
        
        # Add data type if not already present
        if d.data_type not in consolidated_results[url]["data_types"]:
            consolidated_results[url]["data_types"].append(d.data_type)
        
        # Add detection
        consolidated_results[url]["detections"].append({
            "leak_id": d.leak_id,
            "data_type": d.data_type,
            "confidence": d.confidence,
            "evidence": d.evidence,
            "timestamp": d.timestamp.isoformat() if d.timestamp else None
        })
    
    # Convert to list and sort by confidence
    results_list = list(consolidated_results.values())
    
    return {
        "scan_id": scan.scan_id,
        "status": scan.status,
        "start_time": scan.start_time.isoformat() if scan.start_time else None,
        "end_time": scan.end_time.isoformat() if scan.end_time else None,
        "results_count": len(results_list),  # Count unique URLs
        "detections": results_list
    }


@app.get("/api/scans/recent")
async def get_recent_scans(limit: int = 10, db: Session = Depends(get_db)):
    """Get recent scans"""
    scans = db.query(Scan).order_by(Scan.start_time.desc()).limit(limit).all()
    
    return {
        "scans": [
            {
                "scan_id": s.scan_id,
                "scan_type": s.scan_type,
                "status": s.status,
                "start_time": s.start_time.isoformat() if s.start_time else None,
                "results_count": s.results_count
            }
            for s in scans
        ]
    }


@app.post("/api/test-email")
async def test_email():
    """Test email configuration"""
    success = email_reporter.send_test_email()
    
    if success:
        return {"status": "success", "message": "Test email sent successfully"}
    else:
        raise HTTPException(status_code=500, detail="Failed to send test email")


def execute_sensitive_data_scan(
    scan_id: int,
    data_types: List[str],
    file_types: List[str],
    domain: str,
    max_results: int,
    send_email: bool
):
    """
    Execute the sensitive data scan (background task)
    """
    db = next(get_db())
    
    try:
        logger.info(f"🔍 Starting scan {scan_id}...")
        
        # Check if API keys are configured
        if not settings.google_api_keys or not settings.google_search_engine_ids:
            logger.error("❌ Google API keys not configured")
            scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
            scan.status = "failed"
            scan.end_time = datetime.utcnow()
            db.commit()
            return
        
        # Generate dorking queries
        queries = google_search.generate_dork_queries(data_types, domain)
        logger.info(f"📋 Generated {len(queries)} search queries")
        
        all_detections = []
        processed_urls = set()
        url_detections = {}  # Dictionary to consolidate detections by URL
        
        # Execute each query
        for query_info in queries[:max_results]:
            try:
                query = query_info['query']
                query_data_type = query_info['data_type']
                
                # Skip if this data type wasn't selected
                if query_data_type not in data_types:
                    continue
                
                # Search Google - fetch 10 results to get diverse URLs
                results = google_search.search(query, num_results=10)
                logger.info(f"🔎 Query: {query} -> {len(results)} results")
                
                # Process each result
                for result in results:
                    url = result['link']
                    
                    # Skip if already processed
                    if url in processed_urls:
                        continue
                    
                    processed_urls.add(url)
                    
                    # Retry logic for failed URLs
                    max_url_retries = 2
                    url_attempt = 0
                    url_success = False
                    
                    while url_attempt < max_url_retries and not url_success:
                        try:
                            # Download file with timeout and error handling
                            file_content, file_ext = doc_processor.download_file(url)
                            
                            # Extract text
                            text = doc_processor.extract_text(file_content, file_ext)
                            
                            if not text:
                                logger.debug(f"⚠️ No text extracted from {url}")
                                break
                            
                            # Detect sensitive data - only scan for selected data types
                            detections = data_detector.detect_all(text, selected_types=data_types)
                            
                            if detections:
                                # Store consolidated detections by URL
                                if url not in url_detections:
                                    url_detections[url] = {
                                        "data_types": [],
                                        "detections": []
                                    }
                                
                                # Save detections to database and consolidate results
                                for detected_type, matches in detections.items():
                                    if detected_type not in url_detections[url]["data_types"]:
                                        url_detections[url]["data_types"].append(detected_type)
                                    
                                    for match in matches:
                                        leak = DetectedLeak(
                                            scan_id=scan_id,
                                            data_type=detected_type,
                                            file_url=url,
                                            confidence=match['confidence'],
                                            evidence=json.dumps({
                                                "match": match['match'],
                                                "context": match['context']
                                            })
                                        )
                                        db.add(leak)
                                        
                                        url_detections[url]["detections"].append({
                                            "data_type": detected_type,
                                            "match": match['match'],
                                            "confidence": match['confidence'],
                                            "evidence": match['context']
                                        })
                                
                                db.commit()
                            
                            url_success = True
                            logger.info(f"✅ Successfully processed {url}")
                            
                        except Exception as url_error:
                            url_attempt += 1
                            logger.warning(f"⚠️ Error processing {url} (attempt {url_attempt}/{max_url_retries}): {str(url_error)}")
                            
                            if url_attempt < max_url_retries:
                                # Wait before retry
                                time.sleep(1)
                            else:
                                # Skip this URL after max retries
                                logger.error(f"❌ Failed to process {url} after {max_url_retries} attempts. Skipping.")
                                # Remove from processed set so we don't count failed URLs
                                processed_urls.discard(url)
                                continue
                    
            except Exception as e:
                logger.error(f"❌ Query execution failed: {str(e)}")
                continue
        
        # Convert consolidated results to flat list for counting
        for url, url_data in url_detections.items():
            all_detections.append({
                "file_url": url,
                "data_types": url_data["data_types"],
                "detection_count": len(url_data["detections"]),
                "detections": url_data["detections"]
            })
        
        # Update scan status
        scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
        scan.status = "completed"
        scan.end_time = datetime.utcnow()
        scan.results_count = len(url_detections)  # Count unique URLs with detections
        db.commit()
        
        logger.info(f"✅ Scan {scan_id} completed. Found detections in {len(url_detections)} unique URLs.")
        
        # Send email report if requested
        if send_email and url_detections:
            duration = (scan.end_time - scan.start_time).total_seconds()
            scan_results = {
                "scan_id": scan_id,
                "duration": f"{duration:.1f} seconds",
                "total_queries": len(queries),
                "files_processed": len(processed_urls),
                "urls_with_detections": len(url_detections)
            }
            
            success = email_reporter.send_sensitive_data_report(scan_results, all_detections)
            
            # Log email report
            email_report = EmailReport(
                scan_id=scan_id,
                recipient=settings.cert_in_email,
                subject=f"[URGENT] Sensitive Data Exposure Detected - Scan {scan_id}",
                body="Automated report sent",
                status="sent" if success else "failed",
                sent_time=datetime.utcnow() if success else None
            )
            db.add(email_report)
            db.commit()
        
    except Exception as e:
        logger.error(f"❌ Scan {scan_id} failed: {str(e)}")
        
        # Update scan status to failed
        scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
        if scan:
            scan.status = "failed"
            scan.end_time = datetime.utcnow()
            db.commit()
    
    finally:
        db.close()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=settings.host,
        port=settings.port,
        reload=False,  # Disable reload to avoid import string issues
        log_level="info"
    )
