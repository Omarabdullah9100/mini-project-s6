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
        report_date = datetime.now().strftime('%d %B %Y, %H:%M UTC')
        scan_id = scan_results.get('scan_id', 'N/A')

        # Build per-type findings rows
        findings_html = ''
        for data_type, items in grouped.items():
            data_type_name = data_type.replace('_', ' ').title()
            badge_color = '#ff4d6a' if data_type == 'aadhaar' else '#ff9f43' if data_type == 'pan' else '#339af0' if data_type == 'voter_id' else '#c084fc'
            findings_html += f'''
            <tr>
              <td colspan="3" style="background:#1c1f2e;padding:10px 16px 6px;">
                <span style="display:inline-block;background:{badge_color}22;color:{badge_color};border:1px solid {badge_color}44;
                      font-size:11px;font-weight:700;padding:2px 10px;border-radius:20px;letter-spacing:.5px;">
                  {data_type_name.upper()}
                </span>
              </td>
            </tr>'''
            for item in items[:10]:
                conf = item['confidence']
                conf_color = '#ff4d6a' if conf >= 80 else '#ff9f43' if conf >= 60 else '#51cf66'
                url_display = item['file_url'][:70] + ('…' if len(item['file_url']) > 70 else '')
                evidence_display = str(item.get('evidence', ''))[:90] + '…'
                findings_html += f'''
            <tr style="border-bottom:1px solid #2a2d3e;">
              <td style="padding:10px 16px;color:#8b8fa7;font-size:12px;word-break:break-all;max-width:340px;">
                <a href="{item['file_url']}" style="color:#00d4aa;text-decoration:none;">{url_display}</a>
              </td>
              <td style="padding:10px 16px;white-space:nowrap;">
                <span style="color:{conf_color};font-weight:700;font-size:13px;">{conf:.0f}%</span>
              </td>
              <td style="padding:10px 16px;color:#8b8fa7;font-size:12px;">{evidence_display}</td>
            </tr>'''
            if len(items) > 10:
                findings_html += f'''
            <tr><td colspan="3" style="padding:8px 16px;color:#5c6078;font-size:12px;font-style:italic;">
              + {len(items) - 10} more {data_type_name} instances detected
            </td></tr>'''

        html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CyberShield Security Alert</title>
</head>
<body style="margin:0;padding:0;background:#0d0f1a;font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;color:#e2e4ed;">

<!-- Wrapper -->
<table width="100%" cellpadding="0" cellspacing="0" style="background:#0d0f1a;padding:32px 16px;">
<tr><td align="center">
<table width="640" cellpadding="0" cellspacing="0" style="max-width:640px;width:100%">

  <!-- Header -->
  <tr>
    <td style="background:linear-gradient(135deg,#0d1f1b 0%,#0a1628 100%);border:1px solid #00d4aa44;
               border-radius:12px 12px 0 0;padding:32px 36px;">
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td style="vertical-align:top;">
            <h1 style="margin:0 0 6px;font-size:22px;font-weight:800;color:#e2e4ed;line-height:1.2;">
              Sensitive Data Exposure Detected
            </h1>
            <p style="margin:0;font-size:12px;color:#5c6078;">{report_date} &nbsp;&#8226;&nbsp; Scan ID: {scan_id}</p>
          </td>
          <td align="right" valign="top">
            <span style="display:inline-block;background:#ff4d6a18;color:#ff4d6a;border:1px solid #ff4d6a44;
                         font-size:10px;font-weight:700;padding:4px 12px;border-radius:20px;letter-spacing:1px;">CRITICAL</span>
          </td>
        </tr>
      </table>
    </td>
  </tr>

  <!-- Red Alert Banner -->
  <tr>
    <td style="background:#ff4d6a18;border-left:4px solid #ff4d6a;border-right:1px solid #2a2d3e;
               border-bottom:1px solid #2a2d3e;padding:14px 36px;">
      <p style="margin:0;font-size:13px;font-weight:600;color:#ff4d6a;">CRITICAL SECURITY INCIDENT</p>
      <p style="margin:4px 0 0;font-size:12px;color:#8b8fa7;">Sensitive personal data has been found publicly exposed on Indian Government (.gov.in) domains. Immediate remediation is required to safeguard citizen privacy.</p>
    </td>
  </tr>

  <!-- Stats Row -->
  <tr>
    <td style="background:#161822;border:1px solid #2a2d3e;border-top:none;padding:24px 36px;">
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td align="center" style="background:#1c1f2e;border:1px solid #2a2d3e;border-radius:8px;padding:16px;width:30%;">
            <p style="margin:0;font-size:26px;font-weight:800;color:#ff4d6a;">{total_files}</p>
            <p style="margin:4px 0 0;font-size:11px;color:#5c6078;font-weight:600;letter-spacing:.5px;text-transform:uppercase;">Files Affected</p>
          </td>
          <td width="16"></td>
          <td align="center" style="background:#1c1f2e;border:1px solid #2a2d3e;border-radius:8px;padding:16px;width:30%;">
            <p style="margin:0;font-size:26px;font-weight:800;color:#ff9f43;">{total_detections}</p>
            <p style="margin:4px 0 0;font-size:11px;color:#5c6078;font-weight:600;letter-spacing:.5px;text-transform:uppercase;">Data Instances</p>
          </td>
          <td width="16"></td>
          <td align="center" style="background:#1c1f2e;border:1px solid #2a2d3e;border-radius:8px;padding:16px;width:30%;">
            <p style="margin:0;font-size:26px;font-weight:800;color:#00d4aa;">{avg_confidence:.0f}%</p>
            <p style="margin:4px 0 0;font-size:11px;color:#5c6078;font-weight:600;letter-spacing:.5px;text-transform:uppercase;">Avg Confidence</p>
          </td>
        </tr>
      </table>
    </td>
  </tr>

  <!-- Section: Detailed Findings -->
  <tr>
    <td style="background:#161822;border:1px solid #2a2d3e;border-top:none;padding:0 36px 8px;">
      <p style="margin:0 0 12px;font-size:11px;font-weight:700;color:#00d4aa;letter-spacing:2px;text-transform:uppercase;
                border-top:1px solid #2a2d3e;padding-top:20px;">
        Detailed Findings
      </p>
      <table width="100%" cellpadding="0" cellspacing="0"
             style="border:1px solid #2a2d3e;border-radius:8px;overflow:hidden;font-size:12px;">
        <tr style="background:#1c1f2e;">
          <th style="padding:10px 16px;text-align:left;color:#5c6078;font-size:11px;font-weight:600;
                     letter-spacing:.8px;text-transform:uppercase;border-bottom:1px solid #2a2d3e;">File URL</th>
          <th style="padding:10px 16px;text-align:left;color:#5c6078;font-size:11px;font-weight:600;
                     letter-spacing:.8px;text-transform:uppercase;border-bottom:1px solid #2a2d3e;white-space:nowrap;">Confidence</th>
          <th style="padding:10px 16px;text-align:left;color:#5c6078;font-size:11px;font-weight:600;
                     letter-spacing:.8px;text-transform:uppercase;border-bottom:1px solid #2a2d3e;">Evidence</th>
        </tr>
        {findings_html}
      </table>
    </td>
  </tr>

  <!-- Section: Recommended Actions -->
  <tr>
    <td style="background:#161822;border:1px solid #2a2d3e;border-top:none;padding:20px 36px 8px;">
      <p style="margin:0 0 12px;font-size:11px;font-weight:700;color:#00d4aa;letter-spacing:2px;text-transform:uppercase;
                border-top:1px solid #2a2d3e;padding-top:20px;">
        Recommended Actions
      </p>
      <table cellpadding="0" cellspacing="0" width="100%">
        <tr>
          <td style="background:#1c1f2e;border:1px solid #2a2d3e;border-left:3px solid #ff4d6a;
                     border-radius:6px;padding:12px 16px;margin-bottom:8px;display:block;">
            <p style="margin:0 0 4px;font-size:12px;font-weight:700;color:#ff4d6a;">URGENT &mdash; 0–2 hours</p>
            <p style="margin:0;font-size:12px;color:#8b8fa7;">Remove or restrict access to the affected files immediately. Assess the full scope of exposure.</p>
          </td>
        </tr>
        <tr><td height="8"></td></tr>
        <tr>
          <td style="background:#1c1f2e;border:1px solid #2a2d3e;border-left:3px solid #ff9f43;
                     border-radius:6px;padding:12px 16px;">
            <p style="margin:0 0 4px;font-size:12px;font-weight:700;color:#ff9f43;">HIGH PRIORITY &mdash; 2–24 hours</p>
            <p style="margin:0;font-size:12px;color:#8b8fa7;">Notify affected individuals. Conduct forensic analysis to determine data exposure timeline.</p>
          </td>
        </tr>
        <tr><td height="8"></td></tr>
        <tr>
          <td style="background:#1c1f2e;border:1px solid #2a2d3e;border-left:3px solid #00d4aa;
                     border-radius:6px;padding:12px 16px;">
            <p style="margin:0 0 4px;font-size:12px;font-weight:700;color:#00d4aa;">FOLLOW-UP &mdash; 1–7 days</p>
            <p style="margin:0;font-size:12px;color:#8b8fa7;">Issue formal incident report, coordinate with law enforcement if required, implement preventive measures and publish policies.</p>
          </td>
        </tr>
      </table>
    </td>
  </tr>

</table>
</td></tr>
</table>

</body>
</html>"""

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
            msg['Subject'] = "[CyberShield] Email Configuration Verified"

            report_date = datetime.now().strftime('%d %B %Y, %H:%M UTC')
            body = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>CyberShield — Test Email</title></head>
<body style="margin:0;padding:0;background:#0d0f1a;font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;color:#e2e4ed;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#0d0f1a;padding:32px 16px;">
<tr><td align="center">
<table width="580" cellpadding="0" cellspacing="0" style="max-width:580px;width:100%;">
  <tr>
    <td style="background:linear-gradient(135deg,#0d1f1b 0%,#0a1628 100%);border:1px solid #00d4aa44;
               border-radius:12px 12px 0 0;padding:28px 32px;">
      <h1 style="margin:0;font-size:20px;font-weight:800;color:#e2e4ed;">Email Configuration Verified</h1>
      <p style="margin:6px 0 0;font-size:12px;color:#5c6078;">{report_date}</p>
    </td>
  </tr>
  <tr>
    <td style="background:#161822;border:1px solid #2a2d3e;border-top:none;padding:28px 32px;">
      <p style="margin:0 0 8px;font-size:14px;font-weight:700;color:#51cf66;">SMTP Connection Successful</p>
      <p style="margin:0;font-size:13px;color:#8b8fa7;line-height:1.6;">
        Your email configuration is working correctly.<br>
        The Automated Sensitive Data &amp; Spoofing Detection Framework is ready to deliver security alerts.
      </p>
    </td>
  </tr>
</table>
</td></tr>
</table>
</body>
</html>"""

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
      Send spoofing website report for impersonation to CERT-In
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
            
            msg['Subject'] = f"[SPOOFING ALERT] Government Website Spoofing Detected - {impersonation_display} - {datetime.now().strftime('%Y-%m-%d')}"
            
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

        dt_badge_color = {
            'aadhaar': '#ff4d6a', 'pan': '#ff9f43', 'voter_id': '#339af0', 'passport': '#c084fc'
        }.get(data_type, '#00d4aa')

        unique_urls = len(set(d.get('file_url', '') for d in detections))
        total_instances = len(detections)
        avg_confidence = sum(d.get('confidence', 0) for d in detections) / len(detections) if detections else 0
        report_date = datetime.now().strftime('%d %B %Y, %H:%M UTC')

        # Group by URL
        url_groups = {}
        for detection in detections:
            url = detection.get('file_url', 'Unknown')
            if url not in url_groups:
                url_groups[url] = {'count': 0, 'confidences': []}
            url_groups[url]['count'] += 1
            url_groups[url]['confidences'].append(detection.get('confidence', 0))

        url_rows = ''
        for url, info in list(url_groups.items())[:15]:
            avg_conf = sum(info['confidences']) / len(info['confidences']) if info['confidences'] else 0
            conf_color = '#ff4d6a' if avg_conf >= 80 else '#ff9f43' if avg_conf >= 60 else '#51cf66'
            url_display = url[:68] + ('…' if len(url) > 68 else '')
            url_rows += f'''
            <tr style="border-bottom:1px solid #2a2d3e;">
              <td style="padding:10px 16px;font-size:12px;word-break:break-all;max-width:360px;">
                <a href="{url}" style="color:#00d4aa;text-decoration:none;">{url_display}</a>
              </td>
              <td style="padding:10px 16px;white-space:nowrap;">
                <span style="color:{conf_color};font-weight:700;font-size:13px;">{avg_conf:.0f}%</span>
              </td>
              <td style="padding:10px 16px;text-align:center;color:#e2e4ed;font-size:13px;font-weight:600;">{info["count"]}</td>
            </tr>'''
        if len(url_groups) > 15:
            url_rows += f'''
            <tr><td colspan="3" style="padding:8px 16px;color:#5c6078;font-size:12px;font-style:italic;text-align:center;">
              + {len(url_groups) - 15} additional affected URLs
            </td></tr>'''

        html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>CyberShield — Vulnerability Report</title></head>
<body style="margin:0;padding:0;background:#0d0f1a;font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;color:#e2e4ed;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#0d0f1a;padding:32px 16px;">
<tr><td align="center">
<table width="640" cellpadding="0" cellspacing="0" style="max-width:640px;width:100%;">

  <!-- Header -->
  <tr>
    <td style="background:linear-gradient(135deg,#0d1f1b 0%,#0a1628 100%);border:1px solid #00d4aa44;
               border-radius:12px 12px 0 0;padding:32px 36px;">
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td style="vertical-align:top;">
            <h1 style="margin:0 0 4px;font-size:21px;font-weight:800;color:#e2e4ed;line-height:1.2;">
              Sensitive Data Exposure Detected
            </h1>
            <p style="margin:0;font-size:12px;color:#5c6078;">{report_date}{f' &nbsp;&#8226;&nbsp; Scan ID: {scan_id}' if scan_id else ''}</p>
          </td>
          <td align="right" valign="top">
            <span style="display:inline-block;background:{dt_badge_color}18;color:{dt_badge_color};border:1px solid {dt_badge_color}44;
                         font-size:10px;font-weight:700;padding:4px 12px;border-radius:20px;letter-spacing:1px;">CRITICAL</span>
          </td>
        </tr>
      </table>
    </td>
  </tr>

  <!-- Alert Banner -->
  <tr>
    <td style="background:#ff4d6a14;border-left:4px solid #ff4d6a;border-right:1px solid #2a2d3e;
               border-bottom:1px solid #2a2d3e;padding:14px 36px;">
      <p style="margin:0 0 4px;font-size:13px;font-weight:700;color:#ff4d6a;">IMMEDIATE ACTION REQUIRED</p>
      <p style="margin:0;font-size:12px;color:#8b8fa7;">{data_type_display} have been found publicly accessible on Indian Government (.gov.in) websites — a severe CWE-200 Information Disclosure vulnerability with direct risk of identity theft and financial fraud.</p>
    </td>
  </tr>

  <!-- Severity Meta -->
  <tr>
    <td style="background:#ff9f4314;border-left:4px solid #ff9f43;border-right:1px solid #2a2d3e;
               border-bottom:1px solid #2a2d3e;padding:12px 36px;">
      <table cellpadding="0" cellspacing="6" style="font-size:12px;color:#8b8fa7;">
        <tr>
          <td style="padding-right:24px;"><span style="color:#ff9f43;font-weight:700;">Vulnerability Class</span><br>CWE-200: Exposure of Sensitive Information</td>
          <td style="padding-right:24px;"><span style="color:#ff9f43;font-weight:700;">Attack Vector</span><br>Network / Public Search Engines</td>
          <td><span style="color:#ff9f43;font-weight:700;">Exploitability</span><br>High — freely indexed by Google</td>
        </tr>
      </table>
    </td>
  </tr>

  <!-- Stats Row -->
  <tr>
    <td style="background:#161822;border:1px solid #2a2d3e;border-top:none;padding:24px 36px;">
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td align="center" style="background:#1c1f2e;border:1px solid #2a2d3e;border-radius:8px;padding:16px;width:30%;">
            <p style="margin:0;font-size:26px;font-weight:800;color:{dt_badge_color};">{unique_urls}</p>
            <p style="margin:4px 0 0;font-size:11px;color:#5c6078;font-weight:600;letter-spacing:.5px;text-transform:uppercase;">Affected URLs</p>
          </td>
          <td width="16"></td>
          <td align="center" style="background:#1c1f2e;border:1px solid #2a2d3e;border-radius:8px;padding:16px;width:30%;">
            <p style="margin:0;font-size:26px;font-weight:800;color:#ff9f43;">{total_instances}</p>
            <p style="margin:4px 0 0;font-size:11px;color:#5c6078;font-weight:600;letter-spacing:.5px;text-transform:uppercase;">Total Instances</p>
          </td>
          <td width="16"></td>
          <td align="center" style="background:#1c1f2e;border:1px solid #2a2d3e;border-radius:8px;padding:16px;width:30%;">
            <p style="margin:0;font-size:26px;font-weight:800;color:#00d4aa;">{avg_confidence:.0f}%</p>
            <p style="margin:4px 0 0;font-size:11px;color:#5c6078;font-weight:600;letter-spacing:.5px;text-transform:uppercase;">Avg Confidence</p>
          </td>
        </tr>
      </table>
    </td>
  </tr>

  <!-- Affected Resources Table -->
  <tr>
    <td style="background:#161822;border:1px solid #2a2d3e;border-top:none;padding:0 36px 8px;">
      <p style="margin:0 0 12px;font-size:11px;font-weight:700;color:#00d4aa;letter-spacing:2px;text-transform:uppercase;
                border-top:1px solid #2a2d3e;padding-top:20px;">Affected Government Resources</p>
      <table width="100%" cellpadding="0" cellspacing="0"
             style="border:1px solid #2a2d3e;border-radius:8px;overflow:hidden;font-size:12px;">
        <tr style="background:#1c1f2e;">
          <th style="padding:10px 16px;text-align:left;color:#5c6078;font-size:11px;font-weight:600;
                     letter-spacing:.8px;text-transform:uppercase;border-bottom:1px solid #2a2d3e;">File URL</th>
          <th style="padding:10px 16px;text-align:left;color:#5c6078;font-size:11px;font-weight:600;
                     letter-spacing:.8px;text-transform:uppercase;border-bottom:1px solid #2a2d3e;white-space:nowrap;">Confidence</th>
          <th style="padding:10px 16px;text-align:center;color:#5c6078;font-size:11px;font-weight:600;
                     letter-spacing:.8px;text-transform:uppercase;border-bottom:1px solid #2a2d3e;">Count</th>
        </tr>
        {url_rows}
      </table>
    </td>
  </tr>

  <!-- Recommended Actions -->
  <tr>
    <td style="background:#161822;border:1px solid #2a2d3e;border-top:none;padding:20px 36px 8px;">
      <p style="margin:0 0 12px;font-size:11px;font-weight:700;color:#00d4aa;letter-spacing:2px;text-transform:uppercase;
                border-top:1px solid #2a2d3e;padding-top:20px;">Recommended Actions</p>
      <table cellpadding="0" cellspacing="0" width="100%">
        <tr>
          <td style="background:#1c1f2e;border:1px solid #2a2d3e;border-left:3px solid #ff4d6a;
                     border-radius:6px;padding:12px 16px;">
            <p style="margin:0 0 4px;font-size:12px;font-weight:700;color:#ff4d6a;">URGENT — 0–2 hours</p>
            <p style="margin:0;font-size:12px;color:#8b8fa7;">Immediately remove or restrict public access to affected files. Verify data integrity and begin disclosure preparation.</p>
          </td>
        </tr>
        <tr><td height="8"></td></tr>
        <tr>
          <td style="background:#1c1f2e;border:1px solid #2a2d3e;border-left:3px solid #ff9f43;
                     border-radius:6px;padding:12px 16px;">
            <p style="margin:0 0 4px;font-size:12px;font-weight:700;color:#ff9f43;">HIGH PRIORITY — 2–24 hours</p>
            <p style="margin:0;font-size:12px;color:#8b8fa7;">Conduct forensic timeline analysis. Notify impacted individuals through official government channels. Implement emergency access controls.</p>
          </td>
        </tr>
        <tr><td height="8"></td></tr>
        <tr>
          <td style="background:#1c1f2e;border:1px solid #2a2d3e;border-left:3px solid #00d4aa;
                     border-radius:6px;padding:12px 16px;">
            <p style="margin:0 0 4px;font-size:12px;font-weight:700;color:#00d4aa;">FOLLOW-UP — 1–7 days</p>
            <p style="margin:0;font-size:12px;color:#8b8fa7;">Issue formal incident response report. Coordinate with law enforcement if required. Deploy preventive scanning policies to avoid recurrence.</p>
          </td>
        </tr>
      </table>
    </td>
  </tr>

</table>
</td></tr>
</table>
</body>
</html>"""

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
        report_date = datetime.now().strftime('%d %B %Y, %H:%M UTC')

        # Build suspicious site rows
        site_rows = ''
        for finding in findings[:20]:
            url = finding.get('url', 'Unknown')
            severity = finding.get('severity', 'HIGH')
            risk = finding.get('risk', 'Identity Theft, Financial Fraud')
            sev_color = '#ff4d6a' if severity in ('CRITICAL', 'HIGH') else '#ff9f43'
            url_display = url[:65] + ('…' if len(url) > 65 else '')
            site_rows += f'''
            <tr style="border-bottom:1px solid #2a2d3e;">
              <td style="padding:10px 16px;font-size:12px;word-break:break-all;max-width:320px;">
                <a href="{url}" style="color:#00d4aa;text-decoration:none;">{url_display}</a>
              </td>
              <td style="padding:10px 16px;white-space:nowrap;">
                <span style="color:{sev_color};font-weight:700;font-size:12px;">{severity}</span>
              </td>
              <td style="padding:10px 16px;font-size:12px;color:#8b8fa7;">{risk}</td>
            </tr>'''
        if len(findings) > 20:
            site_rows += f'''
            <tr><td colspan="3" style="padding:8px 16px;color:#5c6078;font-size:12px;font-style:italic;text-align:center;">
              + {len(findings) - 20} additional suspicious sites detected
            </td></tr>'''

        html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>CyberShield — Spoofing Website Detection Report</title></head>
<body style="margin:0;padding:0;background:#0d0f1a;font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;color:#e2e4ed;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#0d0f1a;padding:32px 16px;">
<tr><td align="center">
<table width="640" cellpadding="0" cellspacing="0" style="max-width:640px;width:100%;">

  <!-- Header -->
  <tr>
    <td style="background:linear-gradient(135deg,#1f150d 0%,#0a1628 100%);border:1px solid #ff9f4344;
               border-radius:12px 12px 0 0;padding:32px 36px;">
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td style="vertical-align:top;">
            <h1 style="margin:0 0 4px;font-size:21px;font-weight:800;color:#e2e4ed;line-height:1.2;">
              Government Website Spoofing Detected
            </h1>
            <p style="margin:0;font-size:12px;color:#5c6078;">{report_date}{f' &nbsp;&#8226;&nbsp; Scan ID: {scan_id}' if scan_id else ''}</p>
          </td>
          <td align="right" valign="top">
            <span style="display:inline-block;background:#ff9f4318;color:#ff9f43;border:1px solid #ff9f4344;
                         font-size:10px;font-weight:700;padding:4px 12px;border-radius:20px;letter-spacing:1px;">SPOOFING ALERT</span>
          </td>
        </tr>
      </table>
    </td>
  </tr>

  <!-- Danger Banner -->
  <tr>
    <td style="background:#ff4d6a14;border-left:4px solid #ff4d6a;border-right:1px solid #2a2d3e;
               border-bottom:1px solid #2a2d3e;padding:14px 36px;">
      <p style="margin:0 0 4px;font-size:13px;font-weight:700;color:#ff4d6a;">CRITICAL SPOOFING ALERT</p>
      <p style="margin:0;font-size:12px;color:#8b8fa7;">A spoofing website detected for impersonation of Indian Government services has been identified. These fraudulent portals are designed to deceive citizens into sharing sensitive personal and financial information.</p>
    </td>
  </tr>

  <!-- Threat Meta -->
  <tr>
    <td style="background:#ff9f4314;border-left:4px solid #ff9f43;border-right:1px solid #2a2d3e;
               border-bottom:1px solid #2a2d3e;padding:12px 36px;">
      <table cellpadding="0" cellspacing="6" style="font-size:12px;color:#8b8fa7;">
        <tr>
          <td style="padding-right:24px;"><span style="color:#ff9f43;font-weight:700;">Threat Type</span><br>Website Spoofing / Domain Squatting</td>
          <td style="padding-right:24px;"><span style="color:#ff9f43;font-weight:700;">Target</span><br>Indian Citizens / General Public</td>
          <td><span style="color:#ff9f43;font-weight:700;">Intent</span><br>Credential Harvesting, Identity Theft</td>
        </tr>
      </table>
    </td>
  </tr>

  <!-- Stats Row -->
  <tr>
    <td style="background:#161822;border:1px solid #2a2d3e;border-top:none;padding:24px 36px;">
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td align="center" style="background:#1c1f2e;border:1px solid #2a2d3e;border-radius:8px;padding:16px;width:44%;">
            <p style="margin:0;font-size:28px;font-weight:800;color:#ff4d6a;">{total_sites}</p>
            <p style="margin:4px 0 0;font-size:11px;color:#5c6078;font-weight:600;letter-spacing:.5px;text-transform:uppercase;">Spoofed Domains</p>
          </td>
          <td width="20"></td>
          <td align="center" style="background:#1c1f2e;border:1px solid #2a2d3e;border-radius:8px;padding:16px;width:44%;">
            <p style="margin:0;font-size:28px;font-weight:800;color:#ff9f43;">{suspicious_sites}</p>
            <p style="margin:4px 0 0;font-size:11px;color:#5c6078;font-weight:600;letter-spacing:.5px;text-transform:uppercase;">Suspicious Indicators</p>
          </td>
        </tr>
      </table>
    </td>
  </tr>

  <!-- Phishing Sites Table -->
  <tr>
    <td style="background:#161822;border:1px solid #2a2d3e;border-top:none;padding:0 36px 8px;">
      <p style="margin:0 0 12px;font-size:11px;font-weight:700;color:#ff9f43;letter-spacing:2px;text-transform:uppercase;
                border-top:1px solid #2a2d3e;padding-top:20px;">Detected Spoofed Government Sites</p>
      <table width="100%" cellpadding="0" cellspacing="0"
             style="border:1px solid #2a2d3e;border-radius:8px;overflow:hidden;font-size:12px;">
        <tr style="background:#1c1f2e;">
          <th style="padding:10px 16px;text-align:left;color:#5c6078;font-size:11px;font-weight:600;
                     letter-spacing:.8px;text-transform:uppercase;border-bottom:1px solid #2a2d3e;">Spoofed Domain / URL</th>
          <th style="padding:10px 16px;text-align:left;color:#5c6078;font-size:11px;font-weight:600;
                     letter-spacing:.8px;text-transform:uppercase;border-bottom:1px solid #2a2d3e;white-space:nowrap;">Severity</th>
          <th style="padding:10px 16px;text-align:left;color:#5c6078;font-size:11px;font-weight:600;
                     letter-spacing:.8px;text-transform:uppercase;border-bottom:1px solid #2a2d3e;">Risk</th>
        </tr>
        {site_rows}
      </table>
    </td>
  </tr>

  <!-- Action Items -->
  <tr>
    <td style="background:#161822;border:1px solid #2a2d3e;border-top:none;padding:20px 36px 8px;">
      <p style="margin:0 0 12px;font-size:11px;font-weight:700;color:#ff9f43;letter-spacing:2px;text-transform:uppercase;
                border-top:1px solid #2a2d3e;padding-top:20px;">Immediate Action Items</p>
      <table cellpadding="0" cellspacing="0" width="100%">
        <tr>
          <td style="background:#1c1f2e;border:1px solid #2a2d3e;border-left:3px solid #ff4d6a;
                     border-radius:6px;padding:12px 16px;">
            <p style="margin:0 0 4px;font-size:12px;font-weight:700;color:#ff4d6a;">URGENT — Immediate</p>
            <p style="margin:0;font-size:12px;color:#8b8fa7;">Issue a public advisory warning citizens about the spoofed websites. Contact domain registrars and hosting providers to initiate immediate takedown. Coordinate with the Cyber Crime Cell.</p>
          </td>
        </tr>
        <tr><td height="8"></td></tr>
        <tr>
          <td style="background:#1c1f2e;border:1px solid #2a2d3e;border-left:3px solid #ff9f43;
                     border-radius:6px;padding:12px 16px;">
            <p style="margin:0 0 4px;font-size:12px;font-weight:700;color:#ff9f43;">HIGH PRIORITY — 0–24 hours</p>
            <p style="margin:0;font-size:12px;color:#8b8fa7;">Report spoofed domains to the relevant government department. Request DNS sinkholing or domain suspension. Notify major search engines and browsers to flag or de-index the spoofed sites.</p>
          </td>
        </tr>
        <tr><td height="8"></td></tr>
        <tr>
          <td style="background:#1c1f2e;border:1px solid #2a2d3e;border-left:3px solid #00d4aa;
                     border-radius:6px;padding:12px 16px;">
            <p style="margin:0 0 4px;font-size:12px;font-weight:700;color:#00d4aa;">FOLLOW-UP — 1–7 days</p>
            <p style="margin:0;font-size:12px;color:#8b8fa7;">Launch a public awareness campaign to educate citizens on verifying official portals. Investigate perpetrators and pursue legal action. Deploy continuous monitoring to detect future spoofing attempts.</p>
          </td>
        </tr>
      </table>
    </td>
  </tr>

  <!-- Public Safety Tips -->
  <tr>
    <td style="background:#161822;border:1px solid #2a2d3e;border-top:none;padding:20px 36px 20px;">
      <p style="margin:0 0 10px;font-size:11px;font-weight:700;color:#00d4aa;letter-spacing:2px;text-transform:uppercase;
                border-top:1px solid #2a2d3e;padding-top:20px;">Public Protection Guidance</p>
      <table cellpadding="0" cellspacing="4" style="font-size:12px;color:#8b8fa7;">
        <tr><td style="padding:3px 0;">&#8226;&nbsp; Only use official government portals listed on <strong style="color:#e2e4ed;">india.gov.in</strong></td></tr>
        <tr><td style="padding:3px 0;">&#8226;&nbsp; Always verify domain names and SSL certificates before entering personal data</td></tr>
        <tr><td style="padding:3px 0;">&#8226;&nbsp; For Aadhaar services, only use <strong style="color:#e2e4ed;">www.uidai.gov.in</strong></td></tr>
        <tr><td style="padding:3px 0;">&#8226;&nbsp; Report suspicious websites immediately to <strong style="color:#e2e4ed;">cybercrime.gov.in</strong></td></tr>
      </table>
    </td>
  </tr>

</table>
</td></tr>
</table>
</body>
</html>"""

        return html
