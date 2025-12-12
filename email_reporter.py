"""
Email reporting module for sending alerts to CERT-In
"""
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from datetime import datetime
from typing import List, Dict
import logging
from config import settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class EmailReporter:
    """Send email reports to CERT-In"""
    
    def __init__(self):
        self.smtp_server = settings.smtp_server
        self.smtp_port = settings.smtp_port
        self.sender_email = settings.smtp_email
        self.sender_password = settings.smtp_password
        self.cert_in_email = settings.cert_in_email
    
    def send_sensitive_data_report(self, scan_results: Dict, detections: List[Dict]) -> bool:
        """
        Send sensitive data exposure report to CERT-In
        
        Args:
            scan_results: Scan metadata
            detections: List of detected leaks
        
        Returns:
            True if email sent successfully, False otherwise
        """
        try:
            # Create email
            msg = MIMEMultipart()
            msg['From'] = self.sender_email
            msg['To'] = self.cert_in_email
            msg['Subject'] = f"[URGENT] Sensitive Data Exposure Detected on .gov.in Domain - {datetime.now().strftime('%Y-%m-%d')}"
            
            # Create email body
            body = self._create_sensitive_data_email_body(scan_results, detections)
            msg.attach(MIMEText(body, 'html'))
            
            # Send email
            logger.info(f"📧 Sending report to {self.cert_in_email}...")
            self._send_email(msg)
            logger.info("✅ Email sent successfully!")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Email sending failed: {str(e)}")
            return False
    
    def _create_sensitive_data_email_body(self, scan_results: Dict, detections: List[Dict]) -> str:
        """Create HTML email body for sensitive data report"""
        
        # Group detections by data type
        grouped = {}
        for detection in detections:
            data_type = detection['data_type']
            if data_type not in grouped:
                grouped[data_type] = []
            grouped[data_type].append(detection)
        
        # Calculate statistics
        total_files = len(set(d['file_url'] for d in detections))
        total_detections = len(detections)
        avg_confidence = sum(d['confidence'] for d in detections) / len(detections) if detections else 0
        
        html = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .header {{ background-color: #d32f2f; color: white; padding: 20px; }}
                .content {{ padding: 20px; }}
                .alert {{ background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; }}
                .stats {{ background-color: #f5f5f5; padding: 15px; margin: 20px 0; }}
                .detection {{ background-color: #ffffff; border: 1px solid #ddd; padding: 10px; margin: 10px 0; }}
                table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
                th {{ background-color: #f5f5f5; font-weight: bold; }}
                .high-confidence {{ color: #d32f2f; font-weight: bold; }}
                .medium-confidence {{ color: #ff9800; }}
                .footer {{ background-color: #f5f5f5; padding: 20px; margin-top: 30px; font-size: 12px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🚨 URGENT: Sensitive Data Exposure Detected</h1>
                <p>Automated Security Scan Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="content">
                <div class="alert">
                    <strong>⚠️ CRITICAL SECURITY INCIDENT</strong><br>
                    Our automated scanning system has detected sensitive personal data publicly exposed on Indian government (.gov.in) domains.
                    Immediate action is required to protect citizen privacy and prevent potential misuse.
                </div>
                
                <div class="stats">
                    <h2>📊 Executive Summary</h2>
                    <ul>
                        <li><strong>Total Files Affected:</strong> {total_files}</li>
                        <li><strong>Total Data Instances Detected:</strong> {total_detections}</li>
                        <li><strong>Average Confidence Score:</strong> {avg_confidence:.1f}%</li>
                        <li><strong>Scan Duration:</strong> {scan_results.get('duration', 'N/A')}</li>
                        <li><strong>Detection Method:</strong> Automated Google Dorking + Pattern Matching</li>
                    </ul>
                </div>
                
                <h2>🔍 Detailed Findings</h2>
        """
        
        # Add detections grouped by type
        for data_type, items in grouped.items():
            data_type_name = data_type.replace('_', ' ').title()
            html += f"""
                <h3>📌 {data_type_name} ({len(items)} instances)</h3>
                <table>
                    <tr>
                        <th>File URL</th>
                        <th>Confidence</th>
                        <th>Evidence (Anonymized)</th>
                    </tr>
            """
            
            for item in items[:10]:  # Limit to first 10 per type
                confidence_class = "high-confidence" if item['confidence'] >= 80 else "medium-confidence"
                html += f"""
                    <tr>
                        <td><a href="{item['file_url']}">{item['file_url'][:80]}...</a></td>
                        <td class="{confidence_class}">{item['confidence']:.1f}%</td>
                        <td>{item['evidence'][:100]}...</td>
                    </tr>
                """
            
            if len(items) > 10:
                html += f"<tr><td colspan='3'><em>... and {len(items) - 10} more instances</em></td></tr>"
            
            html += "</table>"
        
        # Add recommendations
        html += """
                <h2>✅ Recommended Actions</h2>
                <ol>
                    <li><strong>Immediate:</strong> Take down or restrict access to affected files</li>
                    <li><strong>Short-term:</strong> Notify affected individuals and organizations</li>
                    <li><strong>Long-term:</strong> Implement automated scanning and data protection policies</li>
                    <li><strong>Prevention:</strong> Conduct security awareness training for content publishers</li>
                </ol>
                
                <div class="alert">
                    <strong>⏰ URGENCY LEVEL: HIGH</strong><br>
                    This data is currently indexed by search engines and publicly accessible. 
                    Immediate remediation is critical to prevent identity theft and fraud.
                </div>
            </div>
            
            <div class="footer">
                <p><strong>Report Generated By:</strong> Automated Sensitive Data & Spoofing Detection Framework</p>
                <p><strong>Detection Methodology:</strong> Google Custom Search API + Multi-stage Pattern Validation</p>
                <p><strong>Compliance:</strong> Responsible Disclosure Guidelines, Indian Cybersecurity Laws</p>
                <p><em>This is an automated report. For questions or clarifications, please contact the system administrator.</em></p>
            </div>
        </body>
        </html>
        """
        
        return html
    
    def _send_email(self, msg: MIMEMultipart):
        """Send email via SMTP"""
        with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
            server.starttls()
            server.login(self.sender_email, self.sender_password)
            server.send_message(msg)
    
    def send_test_email(self) -> bool:
        """Send a test email to verify configuration"""
        try:
            msg = MIMEMultipart()
            msg['From'] = self.sender_email
            msg['To'] = self.sender_email  # Send to self
            msg['Subject'] = "Test Email - Cybersecurity Detection Framework"
            
            body = """
            <html>
            <body>
                <h2>✅ Email Configuration Test</h2>
                <p>This is a test email from the Automated Sensitive Data & Spoofing Detection Framework.</p>
                <p>If you received this email, your SMTP configuration is working correctly.</p>
            </body>
            </html>
            """
            
            msg.attach(MIMEText(body, 'html'))
            self._send_email(msg)
            
            logger.info("✅ Test email sent successfully!")
            return True
            
        except Exception as e:
            logger.error(f"❌ Test email failed: {str(e)}")
            return False
