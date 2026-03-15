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
from threading import Lock
from concurrent.futures import ThreadPoolExecutor, as_completed
import math

# Import custom modules
from database import init_db, get_db
from models import Scan, DetectedLeak, EmailReport, AuditLog
from google_search import GoogleSearchAPI
from document_processor import DocumentProcessor
from sensitive_data_detector import SensitiveDataDetector
from email_reporter import EmailReporter
from government_impersonation_detector import GovernmentImersonationDetector
from config import settings, validate_api_config


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Cybersecurity Detection Framework - Module 1 & 2",
    description="Automated Sensitive Data Detection & Government Impersonation Detection System",
    version="2.0.0"
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
gids_detector = GovernmentImersonationDetector()


cancelled_scans = set()
cancelled_scans_lock = Lock()
SUPPORTED_SENSITIVE_TYPES = {"aadhaar", "pan", "voter_id", "passport"}
SUPPORTED_IMPERSONATION_TYPES = {
    "aadhaar_login",
    "pan_verification",
    "voter_registration",
    "passport_services",
    "license_services",
}


def is_scan_cancelled(scan_id: int, db: Session = None) -> bool:
    with cancelled_scans_lock:
        if scan_id in cancelled_scans:
            return True

    if db is not None:
        scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
        if scan and scan.status == "stopped":
            with cancelled_scans_lock:
                cancelled_scans.add(scan_id)
            return True

    return False


def mark_scan_cancelled(scan_id: int):
    with cancelled_scans_lock:
        cancelled_scans.add(scan_id)


def clear_scan_cancelled(scan_id: int):
    with cancelled_scans_lock:
        cancelled_scans.discard(scan_id)


def normalize_sensitive_types(data_types: List[str]) -> List[str]:
    normalized = []
    seen = set()
    aliases = {
        "aadhar": "aadhaar",
        "aadhaar": "aadhaar",
        "pan": "pan",
        "voter": "voter_id",
        "voter_id": "voter_id",
        "passport": "passport",
    }

    for raw_type in data_types or []:
        key = str(raw_type).strip().lower()
        mapped = aliases.get(key, key)
        if mapped in SUPPORTED_SENSITIVE_TYPES and mapped not in seen:
            seen.add(mapped)
            normalized.append(mapped)

    return normalized


def normalize_impersonation_types(impersonation_types: List[str]) -> List[str]:
    normalized = []
    seen = set()

    for raw_type in impersonation_types or []:
        key = str(raw_type).strip().lower().replace(" ", "_")
        if key in SUPPORTED_IMPERSONATION_TYPES and key not in seen:
            seen.add(key)
            normalized.append(key)

    return normalized


def get_scan_detections_query(scan: Scan, db: Session):
    query = db.query(DetectedLeak).filter(DetectedLeak.scan_id == scan.scan_id)

    if scan.start_time:
        query = query.filter(DetectedLeak.timestamp >= scan.start_time)
    if scan.end_time:
        query = query.filter(DetectedLeak.timestamp <= scan.end_time)

    return query


# Pydantic models for API requests
class ScanRequest(BaseModel):
    data_types: List[str]  # ['aadhaar', 'pan', 'bank_account', etc.]
    file_types: Optional[List[str]] = ['pdf', 'doc', 'docx']
    domain: Optional[str] = 'gov.in'
    max_results: Optional[int] = 10


class GovernmentImersonationScanRequest(BaseModel):
    impersonation_types: Optional[List[str]] = ['aadhaar_login', 'pan_verification', 'voter_registration']


class ScanResponse(BaseModel):
    scan_id: int
    status: str
    message: str


class SendReportRequest(BaseModel):
    scan_id: int
    selected_urls: List[str]


class SendVulnerabilityReportRequest(BaseModel):
    scan_id: int
    data_type: str  # 'aadhaar', 'pan', 'voter_id', 'passport'


class SendAbuseReportRequest(BaseModel):
    scan_id: int
    impersonation_type: str  # 'aadhaar_login', 'pan_verification', etc.
    selected_domains: Optional[List[str]] = None  # Optional list of selected domains to filter results


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


@app.get("/api/config/status")
async def config_status():
    """Check whether Google API keys are properly configured"""
    info = validate_api_config()
    return {
        "configured": info["configured"],
        "api_keys_count": info["api_keys_count"],
        "search_engine_ids_count": info["search_engine_ids_count"],
        "usable_pairs": info["usable_pairs"],
        "mismatched": info["mismatched"],
        "message": info["message"],
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
        normalized_data_types = normalize_sensitive_types(request.data_types)
        if not normalized_data_types:
            raise HTTPException(status_code=400, detail="Please select at least one valid data type")

        # Pre-flight: reject immediately if SerpAPI key is not configured
        api_info = validate_api_config()
        if not api_info["configured"]:
            raise HTTPException(
                status_code=400,
                detail="SerpAPI key is not configured. Set SERPAPI_KEY in .env, then restart the server."
            )

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
                "data_types": normalized_data_types,
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
            normalized_data_types,
            request.file_types,
            request.domain,
            request.max_results
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
    
    # Get detections only from the current scan window
    detections = get_scan_detections_query(scan, db).all()
    
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


@app.delete("/api/scan/{scan_id}")
async def delete_scan(scan_id: int, db: Session = Depends(get_db)):
    """Delete a scan and its associated data"""
    try:
        # Get the scan
        scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
        
        # Delete all detections associated with this scan
        db.query(DetectedLeak).filter(DetectedLeak.scan_id == scan_id).delete()
        
        # Delete the scan itself
        db.delete(scan)
        db.commit()
        
        logger.info(f"✅ Scan {scan_id} deleted successfully")
        return {"message": f"Scan {scan_id} deleted successfully"}
    except Exception as e:
        db.rollback()
        logger.error(f"Error deleting scan {scan_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error deleting scan: {str(e)}")


@app.post("/api/scan/{scan_id}/stop")
async def stop_scan(scan_id: int, db: Session = Depends(get_db)):
    """Stop an in-progress scan"""
    try:
        scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        if scan.status not in ["in_progress", "started"]:
            raise HTTPException(status_code=400, detail=f"Scan cannot be stopped in '{scan.status}' state")

        scan.status = "stopped"
        scan.end_time = datetime.utcnow()
        db.commit()
        mark_scan_cancelled(scan_id)

        logger.info(f"⏹️ Scan {scan_id} stopped by user")
        return {
            "status": "success",
            "message": f"Scan {scan_id} has been stopped",
            "scan_id": scan_id
        }
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"Error stopping scan {scan_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error stopping scan: {str(e)}")


@app.post("/api/test-email")
async def test_email():
    """Test email configuration"""
    success = email_reporter.send_test_email()
    
    if success:
        return {"status": "success", "message": "Test email sent successfully"}
    else:
        raise HTTPException(status_code=500, detail=email_reporter.last_error or "Failed to send test email")


@app.post("/api/detections/delete")
async def delete_detections(request: dict, db: Session = Depends(get_db)):
    """Delete detection records by leak IDs"""
    try:
        leak_ids = request.get('leak_ids', [])
        
        if not leak_ids:
            raise HTTPException(status_code=400, detail="No leak IDs provided")
        
        # Delete the records
        deleted_count = db.query(DetectedLeak).filter(
            DetectedLeak.leak_id.in_(leak_ids)
        ).delete()
        
        db.commit()
        
        logger.info(f"🗑️ Deleted {deleted_count} detection records")
        
        return {
            "status": "success",
            "message": f"Successfully deleted {deleted_count} detection record(s)",
            "deleted_count": deleted_count
        }
    except Exception as e:
        logger.error(f"❌ Error deleting detections: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/scan/send-report")
async def send_scan_report(
    request: SendReportRequest,
    db: Session = Depends(get_db)
):
    """Send a report with selected detected URLs to CERT-In"""
    try:
        scan_id = request.scan_id
        selected_urls = request.selected_urls
        
        if not selected_urls:
            raise HTTPException(status_code=400, detail="No URLs selected for report")
        
        # Get scan details
        scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Get detections for selected URLs
        detections = get_scan_detections_query(scan, db).filter(
            DetectedLeak.file_url.in_(selected_urls)
        ).all()
        
        if not detections:
            raise HTTPException(status_code=400, detail="No detections found for selected URLs")
        
        # Format detection data for email
        detection_data = []
        for detection in detections:
            evidence = {}
            try:
                evidence = json.loads(detection.evidence) if detection.evidence else {}
            except:
                pass
            
            detection_data.append({
                "file_url": detection.file_url,
                "data_type": detection.data_type,
                "confidence": detection.confidence,
                "evidence": evidence.get("context", "") or evidence.get("match", "")
            })
        
        # Send the email report
        duration = (scan.end_time - scan.start_time).total_seconds() if scan.end_time else 0
        scan_results = {
            "scan_id": scan_id,
            "duration": f"{duration:.1f} seconds",
            "total_urls_selected": len(selected_urls),
            "detections_reported": len(detections)
        }
        
        success = email_reporter.send_sensitive_data_report(scan_results, detection_data)
        
        # Log the email report
        email_report = EmailReport(
            scan_id=scan_id,
            recipient=settings.cert_in_email,
            subject=f"[URGENT] Sensitive Data Exposure Detected - Scan {scan_id} (Manual Report)",
            body=f"Manual report with {len(selected_urls)} selected URL(s)",
            status="sent" if success else "failed",
            sent_time=datetime.utcnow() if success else None
        )
        db.add(email_report)
        db.commit()
        
        if not success:
            error_detail = email_reporter.last_error or "Failed to send email report"
            raise HTTPException(status_code=500, detail=error_detail)
        
        logger.info(f"📧 Sent manual report for scan {scan_id} with {len(selected_urls)} selected URL(s) to {settings.cert_in_email}")
        
        return {
            "status": "success",
            "message": f"Report sent successfully to CERT-In",
            "recipient": settings.cert_in_email,
            "urls_reported": len(selected_urls),
            "detections_reported": len(detections)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error sending report: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/scan/send-vulnerability-report")
async def send_vulnerability_report(
    request: SendVulnerabilityReportRequest,
    db: Session = Depends(get_db)
):
    """
    Send vulnerability report for Module 1 (Information Disclosure)
    Groups detections by data type and sends a single report email
    """
    try:
        scan_id = request.scan_id
        data_type = normalize_sensitive_types([request.data_type])
        if not data_type:
            raise HTTPException(status_code=400, detail="Unsupported data type for vulnerability report")
        data_type = data_type[0]
        
        # Get scan
        scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Get all detections for this data type
        detections = get_scan_detections_query(scan, db).filter(
            DetectedLeak.data_type == data_type
        ).all()
        
        if not detections:
            raise HTTPException(status_code=400, detail=f"No detections found for {data_type}")
        
        # Format detections
        detection_data = []
        for detection in detections:
            evidence = {}
            try:
                evidence = json.loads(detection.evidence) if detection.evidence else {}
            except:
                pass
            
            detection_data.append({
                "file_url": detection.file_url,
                "data_type": detection.data_type,
                "confidence": detection.confidence,
                "evidence": evidence.get("context", "")
            })
        
        # Send vulnerability report
        success = email_reporter.send_vulnerability_report(data_type, detection_data, scan_id)
        
        if not success:
            error_detail = email_reporter.last_error or "Failed to send vulnerability report"
            raise HTTPException(status_code=500, detail=error_detail)
        
        # Log the email report
        email_report = EmailReport(
            scan_id=scan_id,
            recipient=settings.cert_in_email,
            subject=f"Information Disclosure - {data_type.upper()} - Vulnerability Report",
            body=f"Vulnerability report for {data_type} with {len(detections)} instances",
            status="sent",
            sent_time=datetime.utcnow()
        )
        db.add(email_report)
        db.commit()
        
        logger.info(f"📧 Vulnerability report sent for {data_type} (scan {scan_id}) to {settings.cert_in_email}")
        
        return {
            "status": "success",
            "message": f"Vulnerability report sent successfully",
            "data_type": data_type,
            "recipient": settings.cert_in_email,
            "detections_reported": len(detections),
            "report_type": "Information Disclosure"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error sending vulnerability report: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


def execute_sensitive_data_scan(
    scan_id: int,
    data_types: List[str],
    file_types: List[str],
    domain: str,
    max_results: int
):
    """
    Execute the sensitive data scan (background task)
    """
    db = next(get_db())
    
    try:
        logger.info(f"🔍 Starting scan {scan_id}...")
        clear_scan_cancelled(scan_id)
        selected_data_types = normalize_sensitive_types(data_types)
        selected_file_types = [
            str(file_type).strip().lower() for file_type in (file_types or ["pdf"]) if str(file_type).strip()
        ]
        if not selected_file_types:
            selected_file_types = ["pdf"]

        effective_max_results = max(1, int(max_results or 1))
        parallel_workers = max(1, min(settings.max_parallel_url_workers, effective_max_results))

        if not selected_data_types:
            logger.error(f"❌ Scan {scan_id} has no valid selected data types")
            scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
            scan.status = "failed"
            scan.end_time = datetime.utcnow()
            db.commit()
            return
        
        # Check if SerpAPI key is configured
        if not settings.serpapi_key:
            logger.error("❌ SerpAPI key not configured")
            scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
            scan.status = "failed"
            scan.end_time = datetime.utcnow()
            db.commit()
            return
        
        # Generate dorking queries
        queries = google_search.generate_dork_queries(selected_data_types, domain)
        logger.info(f"📋 Generated {len(queries)} search queries")

        if not queries:
            scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
            scan.status = "completed"
            scan.end_time = datetime.utcnow()
            scan.results_count = 0
            db.commit()
            return
        
        processed_urls = set()
        url_detections = {}  # Dictionary to consolidate detections by URL

        candidate_urls = []

        # Collect candidate URLs first (strictly bounded)
        for query_info in queries:
            if is_scan_cancelled(scan_id, db):
                logger.info(f"⏹️ Scan {scan_id} cancellation detected. Stopping execution.")
                break

            try:
                query = query_info['query']
                query_data_type = query_info['data_type']
                
                # Skip if this data type wasn't selected
                if query_data_type not in selected_data_types:
                    continue
                
                pages_needed = min(
                    settings.max_search_pages_per_query,
                    max(1, math.ceil(effective_max_results / 10))
                )
                results = google_search.search(
                    query,
                    num_results=10,
                    max_pages=pages_needed,
                    should_stop=lambda: is_scan_cancelled(scan_id, db)
                )
                logger.info(f"🔎 Query: {query} -> {len(results)} results")
                
                for result in results:
                    if is_scan_cancelled(scan_id, db):
                        logger.info(f"⏹️ Scan {scan_id} cancellation detected while processing URLs.")
                        break

                    url = result.get('link')
                    if not url:
                        continue
                    
                    # Skip if already processed
                    if url in processed_urls:
                        continue
                    
                    processed_urls.add(url)

                    candidate_urls.append((url, query_data_type))
                    if len(candidate_urls) >= effective_max_results:
                        break
                
                if len(candidate_urls) >= effective_max_results:
                    break
                    
            except Exception as e:
                logger.error(f"❌ Query execution failed: {str(e)}")
                continue

        def process_single_url(url: str, query_data_type: str):
            max_url_retries = 2

            for url_attempt in range(max_url_retries):
                if is_scan_cancelled(scan_id):
                    return None

                try:
                    file_content, file_ext = doc_processor.download_file(url)
                    if file_ext and file_ext.lower() not in selected_file_types:
                        return None

                    text = doc_processor.extract_text(file_content, file_ext)
                    if not text:
                        return None

                    detections = data_detector.detect_all(text, selected_types=[query_data_type])
                    matches = detections.get(query_data_type, [])
                    if not matches:
                        return None

                    return {
                        "url": url,
                        "data_type": query_data_type,
                        "matches": matches,
                    }
                except Exception as url_error:
                    logger.warning(
                        f"⚠️ Error processing {url} (attempt {url_attempt + 1}/{max_url_retries}): {str(url_error)}"
                    )
                    if url_attempt < max_url_retries - 1:
                        time.sleep(0.4)

            logger.error(f"❌ Failed to process {url} after {max_url_retries} attempts. Skipping.")
            return None

        # Process URLs in parallel
        if candidate_urls and not is_scan_cancelled(scan_id, db):
            with ThreadPoolExecutor(max_workers=parallel_workers) as executor:
                futures = [
                    executor.submit(process_single_url, url, query_data_type)
                    for url, query_data_type in candidate_urls
                ]

                for future in as_completed(futures):
                    if is_scan_cancelled(scan_id, db):
                        for pending in futures:
                            pending.cancel()
                        logger.info(f"⏹️ Scan {scan_id} cancelled while processing URL workers.")
                        break

                    result = future.result()
                    if not result:
                        continue

                    url = result["url"]
                    detected_type = result["data_type"]
                    matches = result["matches"]

                    if url not in url_detections:
                        url_detections[url] = {
                            "data_types": [],
                            "detections": []
                        }

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
                    logger.info(f"✅ Successfully processed {url}")
        
        # Update scan status
        stopped = is_scan_cancelled(scan_id, db)
        db.expire_all()
        scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
        if stopped:
            scan.status = "stopped"
        elif scan.status != "stopped":
            scan.status = "completed"
        scan.end_time = datetime.utcnow()
        scan.results_count = len(url_detections)  # Count unique URLs with detections
        db.commit()
        
        logger.info(f"✅ Scan {scan_id} completed. Found detections in {len(url_detections)} unique URLs.")
        
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


# ============ MODULE 2: GOVERNMENT IMPERSONATION DETECTION SYSTEM (GIDS) ============

@app.post("/api/scan/government-impersonation", response_model=ScanResponse)
async def start_government_impersonation_scan(
    request: GovernmentImersonationScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Module 2: Start Government Impersonation Detection System (GIDS) scan
    Uses Google dorks to find websites impersonating Indian government services
    Primary dork: intitle:"aadhaar login" -site:gov.in
    """
    try:
        selected_types = normalize_impersonation_types(request.impersonation_types)
        if not selected_types:
            raise HTTPException(status_code=400, detail="Please select at least one valid service type")

        # Pre-flight: reject immediately if SerpAPI key is not configured
        api_info = validate_api_config()
        if not api_info["configured"]:
            raise HTTPException(
                status_code=400,
                detail="SerpAPI key is not configured. Set SERPAPI_KEY in .env, then restart the server."
            )

        # Create scan record
        scan = Scan(
            scan_type="government_impersonation",
            status="in_progress",
            start_time=datetime.utcnow()
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        
        # Log action
        audit = AuditLog(
            action="gids_scan_started",
            details=json.dumps({
                "scan_id": scan.scan_id,
                "impersonation_types": selected_types
            }),
            status="success"
        )
        db.add(audit)
        db.commit()
        
        # Start background task
        background_tasks.add_task(
            execute_government_impersonation_scan,
            scan.scan_id,
            selected_types
        )
        
        logger.info(f"✅ GIDS scan {scan.scan_id} started")
        
        return ScanResponse(
            scan_id=scan.scan_id,
            status="in_progress",
            message=f"Government Impersonation Detection System scan initiated. Scan ID: {scan.scan_id}"
        )
    
    except Exception as e:
        logger.error(f"Error starting GIDS scan: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/scan/{scan_id}/government-impersonation")
async def get_government_impersonation_scan_status(scan_id: int, db: Session = Depends(get_db)):
    """Get Government Impersonation Detection System scan status and results"""
    try:
        scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
        
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        results = get_scan_detections_query(scan, db).all()
        
        # Parse results
        findings = []
        for result in results:
            try:
                evidence = json.loads(result.evidence) if result.evidence else {}
                findings.append({
                    "leak_id": result.leak_id,
                    "url": result.file_url,
                    "domain": evidence.get("domain", ""),
                    "impersonation_type": result.data_type,
                    "confidence": result.confidence,
                    "risk_level": evidence.get("risk_level", "MEDIUM"),
                    "title": evidence.get("title", ""),
                    "snippet": evidence.get("snippet", ""),
                    "indicators": evidence.get("indicators", []),
                    "is_legitimate_gov": evidence.get("is_legitimate_gov", False),
                    "threat_details": evidence.get("threat_details", "")
                })
            except Exception as e:
                logger.warning(f"Error parsing result: {e}")
                continue
        
        # Calculate risk breakdown
        risk_breakdown = {
            "CRITICAL": len([f for f in findings if f["risk_level"] == "CRITICAL"]),
            "HIGH": len([f for f in findings if f["risk_level"] == "HIGH"]),
            "MEDIUM": len([f for f in findings if f["risk_level"] == "MEDIUM"]),
            "LOW": len([f for f in findings if f["risk_level"] == "LOW"])
        }
        
        return {
            "scan_id": scan_id,
            "status": scan.status,
            "module": "government_impersonation_detection",
            "start_time": scan.start_time.isoformat() if scan.start_time else None,
            "end_time": scan.end_time.isoformat() if scan.end_time else None,
            "results_count": len(findings),
            "risk_breakdown": risk_breakdown,
            "findings": findings
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting GIDS scan status: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/scan/send-abuse-report")
async def send_abuse_report(
    request: SendAbuseReportRequest,
    db: Session = Depends(get_db)
):
    """
    Send Abuse Report for Module 2 (Government Impersonation)
    Groups findings by impersonation type
    Optionally filters by selected_domains if provided
    """
    try:
        scan_id = request.scan_id
        selected_domains = request.selected_domains or []
        normalized_types = normalize_impersonation_types([request.impersonation_type])
        if normalized_types:
            impersonation_type = normalized_types[0]
        else:
            impersonation_type = str(request.impersonation_type).strip()
        
        # Get scan
        scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Get all findings for this impersonation type
        findings = get_scan_detections_query(scan, db).filter(
            DetectedLeak.data_type.in_({impersonation_type, impersonation_type.replace("_", " ").title()})
        ).all()
        
        # Filter by selected domains if provided
        if selected_domains:
            findings = [f for f in findings if any(domain in f.file_url for domain in selected_domains)]
        
        if not findings:
            raise HTTPException(status_code=400, detail=f"No findings found for {impersonation_type}")
        
        # Format findings for abuse report
        finding_data = []
        for finding in findings:
            evidence = {}
            try:
                evidence = json.loads(finding.evidence) if finding.evidence else {}
            except:
                pass
            
            finding_data.append({
                "url": finding.file_url,
                "impersonation_type": finding.data_type,
                "confidence": finding.confidence,
                "domain": evidence.get("domain", ""),
                "title": evidence.get("title", ""),
                "risk_level": evidence.get("risk_level", "MEDIUM"),
                "severity": "CRITICAL" if finding.confidence >= 80 else "HIGH"
            })
        
        # Send abuse report
        success = email_reporter.send_abuse_report(impersonation_type, finding_data, scan_id)
        
        if not success:
            error_detail = email_reporter.last_error or "Failed to send abuse report"
            raise HTTPException(status_code=500, detail=error_detail)
        
        # Log the email report
        email_report = EmailReport(
            scan_id=scan_id,
            recipient=settings.cert_in_email,
            subject=f"ABUSE REPORT - Government Impersonation - {impersonation_type.upper()}",
            body=f"Abuse report for {impersonation_type} with {len(findings)} suspicious sites",
            status="sent",
            sent_time=datetime.utcnow()
        )
        db.add(email_report)
        db.commit()
        
        logger.info(f"📧 Abuse report sent for {impersonation_type} (scan {scan_id}) with {len(findings)} findings to {settings.cert_in_email}")
        
        return {
            "status": "success",
            "message": f"Abuse report sent successfully",
            "impersonation_type": impersonation_type,
            "recipient": settings.cert_in_email,
            "findings_reported": len(findings),
            "report_type": "Government Impersonation - Abuse"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error sending abuse report: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


async def execute_government_impersonation_scan(
    scan_id: int,
    impersonation_types: List[str] = None
):
    """Background task: Execute Government Impersonation Detection System (GIDS) scan"""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    
    db_engine = create_engine(settings.database_url)
    SessionLocal = sessionmaker(bind=db_engine)
    db = SessionLocal()
    
    try:
        # Update status
        scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
        scan.status = "in_progress"
        db.commit()
        clear_scan_cancelled(scan_id)
        
        logger.info(f"Starting Government Impersonation Detection System scan")
        
        if not impersonation_types:
            impersonation_types = ['aadhaar_login', 'pan_verification', 'voter_registration', 'passport_services', 'license_services']
        
        # Run GIDS detection
        if is_scan_cancelled(scan_id, db):
            logger.info(f"⏹️ GIDS scan {scan_id} cancelled before execution")
            return

        scan_results = await gids_detector.scan_for_impersonation(
            impersonation_types,
            should_stop=lambda: is_scan_cancelled(scan_id, db)
        )
        
        # Store findings in database
        findings = scan_results.get("findings", [])
        
        for finding in findings:
            try:
                leak = DetectedLeak(
                    scan_id=scan_id,
                    data_type=finding.get("impersonation_type", "unknown"),
                    file_url=finding.get("url", ""),
                    confidence=finding.get("confidence", 0),
                    evidence=json.dumps({
                        "domain": finding.get("domain", ""),
                        "title": finding.get("title", ""),
                        "snippet": finding.get("snippet", ""),
                        "risk_level": finding.get("risk_level", "MEDIUM"),
                        "indicators": finding.get("indicators", []),
                        "is_legitimate_gov": finding.get("is_legitimate_gov", False),
                        "threat_details": finding.get("threat_details", "")
                    })
                )
                db.add(leak)
                db.commit()
            except Exception as e:
                logger.error(f"Error storing finding: {e}")
                continue
        
        # Mark scan as completed
        stopped = is_scan_cancelled(scan_id, db)
        db.expire_all()
        if scan.status != "stopped":
            scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
            if stopped:
                scan.status = "stopped"
            else:
                scan.status = "completed"
        scan.end_time = datetime.utcnow()
        scan.results_count = len(findings)
        db.commit()
        
        logger.info(f"✅ GIDS scan {scan_id} completed. Found {len(findings)} government impersonation websites.")
    
    except Exception as e:
        logger.error(f"❌ GIDS scan {scan_id} failed: {str(e)}")
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
