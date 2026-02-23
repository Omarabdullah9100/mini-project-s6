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


# Pydantic models for API requests
class ScanRequest(BaseModel):
    data_types: List[str]  # ['aadhaar', 'pan', 'bank_account', etc.]
    file_types: Optional[List[str]] = ['pdf', 'doc', 'docx']
    domain: Optional[str] = 'gov.in'
    max_results: Optional[int] = 10
    send_email: Optional[bool] = True


class GovernmentImersonationScanRequest(BaseModel):
    impersonation_types: Optional[List[str]] = ['aadhaar_login', 'pan_verification', 'voter_registration']


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
        
        # Check if SerpAPI key is configured
        if not settings.serpapi_key:
            logger.error("❌ SerpAPI key not configured")
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
                
                # Search Google with pagination - fetch up to 100 results (10 pages) per query
                # Calculate max_pages based on remaining max_results
                pages_needed = min(10, max(1, max_results // len(queries)))
                results = google_search.search(query, num_results=10, max_pages=pages_needed)
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
                "impersonation_types": request.impersonation_types
            }),
            status="success"
        )
        db.add(audit)
        db.commit()
        
        # Start background task
        background_tasks.add_task(
            execute_government_impersonation_scan,
            scan.scan_id,
            request.impersonation_types
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
        
        results = db.query(DetectedLeak).filter(
            DetectedLeak.scan_id == scan_id
        ).all()
        
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
        
        logger.info(f"Starting Government Impersonation Detection System scan")
        
        if not impersonation_types:
            impersonation_types = ['aadhaar_login', 'pan_verification', 'voter_registration', 'passport_services', 'license_services']
        
        # Run GIDS detection
        scan_results = await gids_detector.scan_for_impersonation(impersonation_types)
        
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
