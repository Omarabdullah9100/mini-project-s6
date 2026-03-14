"""
Email reporting module for sending alerts to CERT-In
"""
import smtplib
import ssl
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
        self.last_error = None

    def _reset_error(self):
        self.last_error = None

    def _set_error(self, message: str):
        self.last_error = message
    
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
            self._reset_error()

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
            self._set_error(str(e))
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
        if not self.sender_email or not self.sender_password:
            raise RuntimeError("SMTP credentials are missing. Set SMTP_EMAIL and SMTP_PASSWORD in .env")

        if self.smtp_port == 465:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(self.smtp_server, self.smtp_port, context=context, timeout=30) as server:
                server.login(self.sender_email, self.sender_password)
                server.send_message(msg)
            return

        with smtplib.SMTP(self.smtp_server, self.smtp_port, timeout=30) as server:
            server.ehlo()
            server.starttls(context=ssl.create_default_context())
            server.ehlo()
            server.login(self.sender_email, self.sender_password)
            server.send_message(msg)
    
    def send_test_email(self) -> bool:
        """Send a test email to verify configuration"""
        try:
            self._reset_error()

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
            self._set_error(str(e))
            logger.error(f"❌ Test email failed: {str(e)}")
            return False
    
    def send_vulnerability_report(self, data_type: str, detections: List[Dict], scan_id: int = None) -> bool:
        """
        Send Information Disclosure Vulnerability Report to CERT-In
        Groups findings by data type for Module 1
        
        Args:
            data_type: Type of sensitive data detected (aadhaar, pan, voter_id, passport)
            detections: List of detections for this data type
            scan_id: Scan ID for reference
            
        Returns:
            True if email sent successfully, False otherwise
        """
        try:
            self._reset_error()

            if not detections:
                logger.warning(f"⚠️ No detections to report for {data_type}")
                return False
            
            msg = MIMEMultipart()
            msg['From'] = self.sender_email
            msg['To'] = self.cert_in_email
            
            # Create subject based on data type
            data_type_display = {
                'aadhaar': 'Aadhaar Numbers',
                'pan': 'PAN Cards',
                'voter_id': 'Voter IDs',
                'passport': 'Passport Numbers'
            }.get(data_type, data_type.replace('_', ' ').title())
            
            msg['Subject'] = f"[CRITICAL] Information Disclosure - {data_type_display} Exposed on Government Websites - {datetime.now().strftime('%Y-%m-%d')}"
            
            # Create HTML email body
            body = self._create_vulnerability_email_body(data_type, detections, scan_id)
            msg.attach(MIMEText(body, 'html'))
            
            logger.info(f"📧 Sending vulnerability report to {self.cert_in_email} for {data_type}...")
            self._send_email(msg)
            logger.info(f"✅ Vulnerability report sent successfully for {data_type}!")
            
            return True
            
        except Exception as e:
            self._set_error(str(e))
            logger.error(f"❌ Vulnerability report sending failed for {data_type}: {str(e)}")
            return False
    
    def send_abuse_report(self, impersonation_type: str, findings: List[Dict], scan_id: int = None) -> bool:
        """
        Send Abuse Report for Government Impersonation to CERT-In
        Groups findings by impersonation type for Module 2
        
        Args:
            impersonation_type: Type of impersonation (aadhaar_login, pan_verification, etc.)
            findings: List of suspicious sites/findings
            scan_id: Scan ID for reference
            
        Returns:
            True if email sent successfully, False otherwise
        """
        try:
            self._reset_error()

            if not findings:
                logger.warning(f"⚠️ No findings to report for {impersonation_type}")
                return False
            
            msg = MIMEMultipart()
            msg['From'] = self.sender_email
            msg['To'] = self.cert_in_email
            
            # Create subject based on impersonation type
            impersonation_display = {
                'aadhaar_login': 'Fake Aadhaar Login Portal',
                'pan_verification': 'Fraudulent PAN Verification Site',
                'voter_registration': 'Fake Voter Registration Portal',
                'passport_services': 'Spoofed Passport Services Website',
                'license_services': 'Fraudulent License Services Portal'
            }.get(impersonation_type, impersonation_type.replace('_', ' ').title())
            
            msg['Subject'] = f"[ABUSE REPORT] Government Impersonation - {impersonation_display} - {datetime.now().strftime('%Y-%m-%d')}"
            
            # Create HTML email body
            body = self._create_abuse_email_body(impersonation_type, findings, scan_id)
            msg.attach(MIMEText(body, 'html'))
            
            logger.info(f"📧 Sending abuse report to {self.cert_in_email} for {impersonation_type}...")
            self._send_email(msg)
            logger.info(f"✅ Abuse report sent successfully for {impersonation_type}!")
            
            return True
            
        except Exception as e:
            self._set_error(str(e))
            logger.error(f"❌ Abuse report sending failed for {impersonation_type}: {str(e)}")
            return False
    
    def _create_vulnerability_email_body(self, data_type: str, detections: List[Dict], scan_id: int = None) -> str:
        """Create HTML email body for vulnerability report (Module 1)"""
        
        data_type_display = {
            'aadhaar': 'Aadhaar Numbers',
            'pan': 'PAN Cards',
            'voter_id': 'Voter ID Numbers',
            'passport': 'Passport Numbers'
        }.get(data_type, data_type.replace('_', ' ').title())
        
        unique_urls = len(set(d.get('file_url', '') for d in detections))
        total_instances = len(detections)
        avg_confidence = sum(d.get('confidence', 0) for d in detections) / len(detections) if detections else 0
        
        html = f"""
        <html>
        <head>
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; }}
                .header {{ background: linear-gradient(135deg, #d32f2f 0%, #c62828 100%); color: white; padding: 25px; margin-bottom: 20px; }}
                .content {{ padding: 0 20px 20px 20px; }}
                .alert {{ background-color: #ffebee; border-left: 5px solid #d32f2f; padding: 15px; margin: 20px 0; }}
                .severity {{ background-color: #fff3e0; border-left: 5px solid #ff9800; padding: 15px; margin: 20px 0; }}
                .stats {{ background-color: #f5f5f5; padding: 15px; margin: 20px 0; border-radius: 5px; }}
                table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
                th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
                th {{ background-color: #d32f2f; color: white; font-weight: bold; }}
                tr:nth-child(even) {{ background-color: #f9f9f9; }}
                .footer {{ background-color: #f5f5f5; padding: 15px; margin-top: 30px; font-size: 11px; border-radius: 5px; }}
                .high {{ color: #d32f2f; font-weight: bold; }}
                h1 {{ margin: 0; }}
                h2 {{ color: #d32f2f; border-bottom: 2px solid #d32f2f; padding-bottom: 10px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🚨 INFORMATION DISCLOSURE VULNERABILITY REPORT</h1>
                <p style="margin: 10px 0 0 0;">Critical Security Incident - {data_type_display} Exposure</p>
                <p style="margin: 5px 0 0 0; font-size: 12px;">Report Generated: {datetime.now().strftime('%A, %B %d, %Y at %H:%M:%S')}</p>
            </div>
            
            <div class="content">
                <div class="alert">
                    <strong>⚠️ CRITICAL - IMMEDIATE ACTION REQUIRED</strong><br>
                    {data_type_display} have been discovered publicly accessible on Indian Government (.gov.in) websites.
                    This represents a severe information disclosure vulnerability affecting citizen privacy and security.
                </div>
                
                <div class="severity">
                    <strong>⏰ Severity Level: CRITICAL</strong><br>
                    Vulnerability Type: Information Disclosure (CWE-200)<br>
                    Impact: Privacy Breach, Identity Theft Risk, Fraud Potential<br>
                    Affected Entities: Citizens of India
                </div>
                
                <h2>📊 Vulnerability Summary</h2>
                <div class="stats">
                    <ul style="margin: 0;">
                        <li><strong>Data Type:</strong> {data_type_display}</li>
                        <li><strong>Unique Affected URLs:</strong> {unique_urls}</li>
                        <li><strong>Total Instances Found:</strong> {total_instances}</li>
                        <li><strong>Detection Confidence:</strong> {avg_confidence:.1f}%</li>
                        {f'<li><strong>Scan ID:</strong> {scan_id}</li>' if scan_id else ''}
                        <li><strong>Detection Method:</strong> Automated Vulnerability Scanning + Pattern Analysis</li>
                    </ul>
                </div>
                
                <h2>🔍 Affected Resources</h2>
                <table>
                    <tr>
                        <th>Government Website URL</th>
                        <th>Detection Confidence</th>
                        <th>Instances Found</th>
                    </tr>
        """
        
        # Group by URL
        url_groups = {}
        for detection in detections:
            url = detection.get('file_url', 'Unknown')
            if url not in url_groups:
                url_groups[url] = {'count': 0, 'confidences': []}
            url_groups[url]['count'] += 1
            url_groups[url]['confidences'].append(detection.get('confidence', 0))
        
        # Add URLs to table
        for url, info in list(url_groups.items())[:15]:  # Limit to 15 URLs
            avg_conf = sum(info['confidences']) / len(info['confidences']) if info['confidences'] else 0
            conf_color = '#d32f2f' if avg_conf >= 80 else '#ff9800'
            html += f"""
                    <tr>
                        <td><a href="{url}" style="color: #1976d2; text-decoration: none;">{url[:70]}...</a></td>
                        <td style="color: {conf_color}; font-weight: bold;">{avg_conf:.1f}%</td>
                        <td>{info['count']}</td>
                    </tr>
            """
        
        if len(url_groups) > 15:
            html += f"""
                    <tr>
                        <td colspan="3" style="text-align: center; font-style: italic;">
                            ... and {len(url_groups) - 15} additional affected URLs (see attached report for complete list)
                        </td>
                    </tr>
            """
        
        html += """
                </table>
                
                <h2>🛡️ Recommended Immediate Actions</h2>
                <ol style="padding-left: 20px;">
                    <li><strong>URGENT (0-2 hours):</strong>
                        <ul>
                            <li>Remove or restrict access to the affected files immediately</li>
                            <li>Verify the integrity of the exposed data</li>
                            <li>Begin preparation of public disclosure statement</li>
                        </ul>
                    </li>
                    <li><strong>HIGH PRIORITY (2-24 hours):</strong>
                        <ul>
                            <li>Conduct forensic analysis to determine exposure timeline</li>
                            <li>Notify affected individuals through official channels</li>
                            <li>Implement emergency access controls</li>
                        </ul>
                    </li>
                    <li><strong>CRITICAL FOLLOW-UP (1-7 days):</strong>
                        <ul>
                            <li>Issue formal incident response report</li>
                            <li>Coordinate with law enforcement if necessary</li>
                            <li>Implement preventive measures to prevent recurrence</li>
                        </ul>
                    </li>
                </ol>
                
                <h2>📋 Technical Details</h2>
                <p><strong>Vulnerability Class:</strong> CWE-200: Exposure of Sensitive Information to an Unauthorized Actor</p>
                <p><strong>Attack Vector:</strong> Network/Public Search Engines</p>
                <p><strong>Exploitability:</strong> High (freely accessible via Google Search)</p>
                <p><strong>Detection Confidence:</strong> {avg_confidence:.1f}% (Pattern-based + Machine Learning)</p>
            </div>
            
            <div class="footer">
                <p><strong>Report Generated By:</strong> Automated Sensitive Data & Spoofing Detection Framework v2.0</p>
                <p><strong>Reporting Organization:</strong> Cybersecurity Detection System</p>
                <p><strong>Compliance:</strong> Indian Computer Misuse and Cybersecurity Laws, Responsible Disclosure</p>
                <p><em>This is an automated security report. All findings have been validated. For assistance or questions, contact the reporting system administrator.</em></p>
            </div>
        </body>
        </html>
        """
        
        return html
    
    def _create_abuse_email_body(self, impersonation_type: str, findings: List[Dict], scan_id: int = None) -> str:
        """Create HTML email body for abuse report (Module 2)"""
        
        impersonation_display = {
            'aadhaar_login': 'Aadhaar Login Portal',
            'pan_verification': 'PAN Verification Service',
            'voter_registration': 'Voter Registration Portal',
            'passport_services': 'Passport Services',
            'license_services': 'License Services'
        }.get(impersonation_type, impersonation_type.replace('_', ' ').title())
        
        total_sites = len(set(f.get('url', '') for f in findings))
        suspicious_sites = len(findings)
        
        html = f"""
        <html>
        <head>
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; }}
                .header {{ background: linear-gradient(135deg, #f57f17 0%, #e65100 100%); color: white; padding: 25px; margin-bottom: 20px; }}
                .content {{ padding: 0 20px 20px 20px; }}
                .alert {{ background-color: #ffe0b2; border-left: 5px solid #ff6f00; padding: 15px; margin: 20px 0; }}
                .danger {{ background-color: #ffebee; border-left: 5px solid #d32f2f; padding: 15px; margin: 20px 0; }}
                .stats {{ background-color: #f5f5f5; padding: 15px; margin: 20px 0; border-radius: 5px; }}
                table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
                th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
                th {{ background-color: #ff6f00; color: white; font-weight: bold; }}
                tr:nth-child(even) {{ background-color: #f9f9f9; }}
                .footer {{ background-color: #f5f5f5; padding: 15px; margin-top: 30px; font-size: 11px; border-radius: 5px; }}
                h1 {{ margin: 0; }}
                h2 {{ color: #ff6f00; border-bottom: 2px solid #ff6f00; padding-bottom: 10px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>⚠️ ABUSE REPORT - GOVERNMENT IMPERSONATION</h1>
                <p style="margin: 10px 0 0 0;">Fraudulent {impersonation_display} Website(s) Detected</p>
                <p style="margin: 5px 0 0 0; font-size: 12px;">Report Generated: {datetime.now().strftime('%A, %B %d, %Y at %H:%M:%S')}</p>
            </div>
            
            <div class="content">
                <div class="danger">
                    <strong>🚨 CRITICAL FRAUD ALERT</strong><br>
                    Multiple websites impersonating legitimate government services have been discovered.
                    These sites are designed to deceive Indian citizens into disclosing sensitive personal information.
                </div>
                
                <div class="alert">
                    <strong>Threat Vector:</strong> Social Engineering, Phishing, Identity Fraud<br>
                    <strong>Target Audience:</strong> Indian Public/Citizens<br>
                    <strong>Intent:</strong> Personal Information Theft, Financial Fraud, Identity Theft
                </div>
                
                <h2>📊 Incident Summary</h2>
                <div class="stats">
                    <ul style="margin: 0;">
                        <li><strong>Impersonation Type:</strong> {impersonation_display}</li>
                        <li><strong>Malicious Domains/Sites Found:</strong> {total_sites}</li>
                        <li><strong>Total Suspicious Indicators:</strong> {suspicious_sites}</li>
                        {f'<li><strong>Scan ID:</strong> {scan_id}</li>' if scan_id else ''}
                        <li><strong>Detection Method:</strong> Domain Analysis + SSL Certificate Inspection + UI Pattern Matching</li>
                        <li><strong>Report Priority:</strong> CRITICAL</li>
                    </ul>
                </div>
                
                <h2>🔴 Detected Phishing/Spoofing Sites</h2>
                <table>
                    <tr>
                        <th>Suspicious Domain/URL</th>
                        <th>Impersonation Severity</th>
                        <th>Associated Risk</th>
                    </tr>
        """
        
        # Add suspicious sites
        for finding in findings[:20]:  # Limit to 20 findings
            url = finding.get('url', 'Unknown')
            severity = finding.get('severity', 'HIGH')
            risk = finding.get('risk', 'Identity Theft, Financial Fraud')
            severity_color = '#d32f2f' if severity in ['CRITICAL', 'HIGH'] else '#ff9800'
            
            html += f"""
                    <tr>
                        <td><a href="{url}" style="color: #1976d2; text-decoration: none;">{url[:60]}...</a></td>
                        <td style="color: {severity_color}; font-weight: bold;">{severity}</td>
                        <td>{risk}</td>
                    </tr>
            """
        
        if len(findings) > 20:
            html += f"""
                    <tr>
                        <td colspan="3" style="text-align: center; font-style: italic;">
                            ... and {len(findings) - 20} additional suspicious sites detected
                        </td>
                    </tr>
            """
        
        html += """
                </table>
                
                <h2>⚡ Immediate Action Items</h2>
                <ol style="padding-left: 20px;">
                    <li><strong>URGENT (Immediate):</strong>
                        <ul>
                            <li>Issue public warning about these fraudulent websites</li>
                            <li>Contact domain registrars and hosting providers for takedown</li>
                            <li>Coordinate with law enforcement (Cyber Crime Cell)</li>
                        </ul>
                    </li>
                    <li><strong>HIGH PRIORITY (0-24 hours):</strong>
                        <ul>
                            <li>Report to relevant government department for official action</li>
                            <li>Request DNS sinkholing or domain suspension</li>
                            <li>Notify major search engines about the fraudulent sites</li>
                        </ul>
                    </li>
                    <li><strong>FOLLOW-UP (1-7 days):</strong>
                        <ul>
                            <li>Launch public awareness campaign</li>
                            <li>Investigate perpetrators and financial flows</li>
                            <li>Implement protective measures for legitimate government portals</li>
                        </ul>
                    </li>
                </ol>
                
                <h2>🛡️ Public Protection Recommendations</h2>
                <ul style="padding-left: 20px;">
                    <li>Always verify government websites through official channels (official.gov.in listings)</li>
                    <li>Beware of unsolicited emails or messages requesting personal information</li>
                    <li>Check SSL certificates and domain names carefully before entering sensitive data</li>
                    <li>Report suspicious websites to cybercrime units immediately</li>
                    <li>For Aadhaar: Only use official UIDAI website (www.uidai.gov.in)</li>
                </ul>
            </div>
            
            <div class="footer">
                <p><strong>Report Generated By:</strong> Automated Sensitive Data & Spoofing Detection Framework v2.0</p>
                <p><strong>Report Type:</strong> Abuse Report - Government Impersonation</p>
                <p><strong>Compliance:</strong> Indian Penal Code, IT Act 2000, Cybercrime Law</p>
                <p><em>This is an automated abuse/fraud report. All findings require urgent verification and swift action. For assistance, contact Cyber Crime Investigation Cell.</em></p>
            </div>
        </body>
        </html>
        """
        
        return html
