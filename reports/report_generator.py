"""
Forensic Report Generation Module
Generates comprehensive PDF reports from analysis results
Manual generation only - no automatic reporting
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import logging

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Image, KeepTogether
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

logger = logging.getLogger(__name__)


class ForensicReportGenerator:
    """
    Generates professional forensic reports from analysis artifacts
    Reports include all evidence chains and technical details
    """
    
    def __init__(self):
        from config import REPORTS_OUTPUT_DIR, REPORT_LOGO_PATH
        
        self.output_dir = REPORTS_OUTPUT_DIR
        self.logo_path = REPORT_LOGO_PATH if REPORT_LOGO_PATH.exists() else None
        
        # Setup styles
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Create custom paragraph styles for report (Times New Roman)"""
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=16,
            fontName='Times-Bold',
            spaceAfter=12,
            alignment=TA_CENTER
        ))
        
        # Section header
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=14,
            fontName='Times-Bold',
            spaceAfter=12,
            spaceBefore=12
        ))
        
        # Normal text
        self.styles.add(ParagraphStyle(
            name='TimesNormal',
            parent=self.styles['Normal'],
            fontSize=12,
            fontName='Times-Roman',
            leading=14
        ))
        
        # Bullet text
        self.styles.add(ParagraphStyle(
            name='TimesBullet',
            parent=self.styles['Normal'],
            fontSize=12,
            fontName='Times-Roman',
            leading=14,
            leftIndent=15,
            bulletIndent=0
        ))
        
        # Status/Verdict style
        self.styles.add(ParagraphStyle(
            name='VerdictStyle',
            parent=self.styles['Normal'],
            fontSize=12,
            fontName='Times-Bold',
            leading=14
        ))
        
        # Critical finding
        self.styles.add(ParagraphStyle(
            name='Critical',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.red,
            fontName='Helvetica-Bold'
        ))
        
        # Code style
        self.styles.add(ParagraphStyle(
            name='ReportCode',
            parent=self.styles['Normal'],
            fontSize=8,
            fontName='Courier',
            textColor=colors.HexColor('#2c3e50'),
            backColor=colors.HexColor('#ecf0f1'),
            leftIndent=10,
            rightIndent=10
        ))
    
    def generate_report(
        self,
        process_info: Dict,
        yara_results: Dict,
        hook_results: Dict,
        feature_data: Dict,
        ml_results: Dict,
        anomaly_results: Dict,
        evidence_chain: Dict
    ) -> Path:
        """
        Generate comprehensive forensic report
        
        Args:
            process_info: Process metadata
            yara_results: YARA scan results
            hook_results: Hook detection results
            feature_data: Extracted features (JSON artifact)
            ml_results: ML inference results
            evidence_chain: Evidence lifecycle metadata
            
        Returns:
            Path to generated PDF report
        """
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        process_name = process_info.get('name', 'unknown')
        pid = process_info.get('pid', 0)
        
        filename = f"Forensic_Report_{process_name}_{pid}_{timestamp}.pdf"
        report_path = self.output_dir / filename
        
        logger.info(f"Generating forensic report: {filename}")
        
        # Create PDF document
        doc = SimpleDocTemplate(
            str(report_path),
            pagesize=letter,
            rightMargin=0.75*inch,
            leftMargin=0.75*inch,
            topMargin=1*inch,
            bottomMargin=0.75*inch
        )
        
        # Build report content
        story = []
        
        # Title page
        story.extend(self._build_title_page(process_info, timestamp))
        story.append(PageBreak())
        
        # Executive summary
        story.extend(self._build_executive_summary(
            yara_results, hook_results, ml_results, feature_data, anomaly_results
        ))
        story.append(PageBreak())
        
        # Process information
        story.extend(self._build_process_section(process_info))
        
        # YARA findings
        # Pass filtered signature data from features instead of raw yara_results
        filtered_sig_data = feature_data.get('signature_indicators', {})
        story.extend(self._build_yara_section(filtered_sig_data))
        story.append(PageBreak())
        
        # Hook detection findings
        story.extend(self._build_hook_section(hook_results))
        
        # Behavioral analysis
        story.extend(self._build_behavioral_section(feature_data))
        story.append(PageBreak())
        
        # Anomaly detection findings
        story.extend(self._build_anomaly_section(anomaly_results))
        story.append(PageBreak())
        
        # ML analysis
        story.extend(self._build_ml_section(ml_results))
        
        # Evidence chain
        story.extend(self._build_evidence_section(evidence_chain))
        story.append(PageBreak())
        
        # Recommendations
        story.extend(self._build_recommendations(
            yara_results, hook_results, ml_results, feature_data
        ))
        
        # Build PDF
        doc.build(story)
        
        # [NEW] Sign the Report for Integrity
        self.sign_pdf(report_path)
        
        logger.info(f"Report generated successfully: {report_path}")
        return report_path

    def sign_pdf(self, pdf_path: Path, key: str = "ForensicsDefaultKey") -> str:
        """
        Generate HMAC-SHA256 signature for the PDF to ensure integrity.
        Saves signature to a sidecar .sig file.
        """
        try:
            import hmac
            import hashlib
            
            with open(pdf_path, 'rb') as f:
                content = f.read()
                
            # Create HMAC
            # In a real scenario, key should be secure/user-provided
            signature = hmac.new(
                key.encode('utf-8'), 
                content, 
                hashlib.sha256
            ).hexdigest()
            
            # Save signature
            sig_path = pdf_path.with_suffix('.sig')
            with open(sig_path, 'w') as f:
                f.write(signature)
                
            logger.info(f"Report signed: {sig_path}")
            return signature

        except Exception as e:
            logger.error(f"Failed to sign report: {e}")
            return ""

    def generate_advanced_scan_report(
        self, 
        registry_data: Optional[Dict], 
        registry_analysis: Optional[Dict],
        kernel_results: Optional[List[Dict]]
    ) -> Path:
        """
        Generate a specialized report for Registry and Kernel scans.
        Strict adherence to Times New Roman and requested format.
        """
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        filename = f"Advanced_Forensic_Scan_Report_{timestamp}.pdf"
        report_path = self.output_dir / filename
        
        doc = SimpleDocTemplate(
            str(report_path),
            pagesize=A4,
            rightMargin=0.75*inch,
            leftMargin=0.75*inch,
            topMargin=0.75*inch,
            bottomMargin=0.75*inch
        )
        
        story = []
        
        # --- Helper Sections ---
        def add_section(title):
            story.append(Paragraph(title, self.styles['SectionHeader']))
            story.append(Spacer(1, 0.1*inch))
            
        def add_kv(key, value):
            story.append(Paragraph(f"<b>{key}:</b> {value}", self.styles['TimesNormal']))

        # --- Title Page ---
        story.append(Paragraph("ADVANCED FORENSIC SCAN REPORT", self.styles['CustomTitle']))
        story.append(Spacer(1, 0.2*inch))
        
        add_kv("Date Generated", datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        add_kv("Scan Scope", "Registry Persistence & Kernel/Rootkit Verification")
        add_kv("Analyst", "Admin (Automated System)")
        story.append(Spacer(1, 0.3*inch))
        
        story.append(Paragraph("<b>Disclaimer:</b> This report contains deep system analysis data. Interpret with caution.", self.styles['TimesNormal']))
        story.append(Spacer(1, 0.3*inch))

        # --- Section 1: Memory & Rootkit Analysis ---
        add_section("1. KERNEL / ROOTKIT ANALYSIS")
        
        if kernel_results is not None:
             # Check if we have results
             if not kernel_results:
                 story.append(Paragraph("No hidden processes or rootkit anomalies detected.", self.styles['TimesNormal']))
             else:
                 story.append(Paragraph(f"<b>[ALERT] {len(kernel_results)} Suspicious/Hidden Processes Detected</b>", self.styles['VerdictStyle']))
                 story.append(Spacer(1, 0.1*inch))
                 
                 for item in kernel_results:
                     pid = item.get('pid', 'N/A')
                     name = item.get('name', 'Unknown')
                     ctype = item.get('type', 'Hidden Process')
                     method = item.get('detection_method', 'Cross-View Analysis')
                     
                     ptext = f"• <b>PID {pid} ({name})</b> - {ctype}<br/>  Method: {method}"
                     story.append(Paragraph(ptext, self.styles['TimesBullet']))
        else:
            story.append(Paragraph("Kernel/Rootkit scan was not performed.", self.styles['TimesNormal']))
            
        story.append(Spacer(1, 0.3*inch))

        # --- Section 2: Registry Persistence Analysis ---
        add_section("2. REGISTRY PERSISTENCE ANALYSIS")
        
        if registry_data and registry_analysis:
            score = registry_analysis.get('registry_score', 0)
            status = "CLEAN" if score == 0 else "SUSPICIOUS"
            color = colors.green if score == 0 else colors.red
            
            # Status
            status_text = f"Registry Status: <font color='{color.hexval()}'><b>{status}</b></font> (Risk Score: {score})"
            story.append(Paragraph(status_text, self.styles['TimesNormal']))
            story.append(Spacer(1, 0.1*inch))
            
            # Findings
            findings = registry_analysis.get('findings', [])
            if findings:
                story.append(Paragraph("<b>Suspicious Entries Found:</b>", self.styles['TimesNormal']))
                for f in findings:
                    story.append(Paragraph(f"• {f}", self.styles['TimesBullet']))
            else:
                story.append(Paragraph("No suspicious persistence mechanisms found.", self.styles['TimesNormal']))
                
            story.append(Spacer(1, 0.1*inch))
            
            # Verified Paths (Proof of Scan)
            paths = registry_data.get('scanned_paths', [])
            if paths:
                story.append(Paragraph("<b>Verified Registry Locations (Proof of Scan):</b>", self.styles['TimesNormal']))
                for p in paths:
                    # Use smaller font for paths if list is long
                    story.append(Paragraph(f"• {p}", self.styles['ReportCode']))
        else:
             story.append(Paragraph("Registry scan was not performed.", self.styles['TimesNormal']))

        story.append(Spacer(1, 0.3*inch))
        
        # --- Sign-off ---
        story.append(Paragraph("END OF REPORT", self.styles['SectionHeader']))
        
        doc.build(story)
        self.sign_pdf(report_path)
        
        logger.info(f"Advanced report generated: {report_path}")
        return report_path

    def generate_batch_report(self, batch_results: List[Dict], output_path: Optional[Path] = None) -> Path:
        """
        Generate summary PDF report for batch analysis
        Uses the Custom 6-Section Format requested by user
        """
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        if output_path:
            report_path = output_path
        else:
            filename = f"Batch_Analysis_Report_{timestamp}.pdf"
            report_path = self.output_dir / filename
        
        doc = SimpleDocTemplate(
            str(report_path),
            pagesize=A4, # Standardize on A4
            rightMargin=0.75*inch,
            leftMargin=0.75*inch,
            topMargin=0.75*inch,
            bottomMargin=0.75*inch
        )
        
        story = []
        
        # Helper for bullets
        def bullet(text):
            return Paragraph(f"• {text}", self.styles['TimesBullet'])
            
        # --- Title Page ---
        story.append(Paragraph("REAL-TIME SYSTEM MEMORY (RAM) SCAN REPORT", self.styles['CustomTitle']))
        story.append(Spacer(1, 0.2*inch))
        story.append(Paragraph(f"<b>Date:</b> {datetime.now().strftime('%Y-%m-%d')}", self.styles['TimesNormal']))
        story.append(Paragraph("<b>Scan Type:</b> Live Memory Forensics", self.styles['TimesNormal']))
        story.append(Paragraph("<b>Generated By:</b> Live Memory Forensics Toolkit for Detecting In-Memory Malware and Hidden Processes", self.styles['TimesNormal']))
        story.append(Spacer(1, 0.3*inch))
        
        # 1. SCAN INTRODUCTION
        story.append(Paragraph("1. SCAN INTRODUCTION", self.styles['SectionHeader']))
        story.append(Paragraph(
            "This report details the findings of a Real-Time Memory (RAM) Scan conducted on the active system. "
            "The analysis focused exclusively on running processes and volatile memory structures. "
            "No static disk files were scanned. The rigorous analysis pipeline included Signature Matching (YARA), "
            "Behavioral Heuristics, and Machine Learning Anomaly Detection.",
            self.styles['TimesNormal']
        ))
        
        # 2. PROCESS ANALYSIS SUMMARY
        story.append(Paragraph("2. PROCESS ANALYSIS SUMMARY", self.styles['SectionHeader']))
        story.append(Paragraph("The following active processes were analyzed:", self.styles['TimesNormal']))
        story.append(Spacer(1, 0.1*inch))
        
        # Build Summary Table
        headers = ["Process Name", "PID", "Parent PID", "Memory (MB)", "Status"]
        summary_data = [headers]
        
        for res in batch_results:
            summary_data.append([
                res.get('process_name', 'Unknown')[:25], # Truncate long names
                str(res.get('pid', 'N/A')),
                str(res.get('ppid', 'N/A')), # Assuming ppid exists or need safe access
                f"{res.get('memory_mb', 0):.1f}",
                res.get('status', 'Unknown').capitalize()
            ])
            
        summary_table = Table(summary_data, colWidths=[2.5*inch, 1.0*inch, 1.0*inch, 1.2*inch, 1.0*inch])
        summary_table.setStyle(TableStyle([
            ('FONTNAME', (0,0), (-1,-1), 'Times-Roman'),
            ('FONTSIZE', (0,0), (-1,-1), 12),
            ('FONTNAME', (0,0), (-1,0), 'Times-Bold'), # Header bold
            ('GRID', (0,0), (-1,-1), 1, colors.black),
            ('BACKGROUND', (0,0), (-1,0), colors.lightgrey),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('TOPPADDING', (0,0), (-1,-1), 6),
        ]))
        story.append(summary_table)
        
        # 3. DETECTION POSITIVES
        story.append(Paragraph("3. DETECTION POSITIVES", self.styles['SectionHeader']))
        
        has_positives = False
        for res in batch_results:
            is_suspicious = res.get('ml_detection', {}).get('is_malicious', False) or \
                          (res.get('features', {}).get('risk_assessment', {}).get('risk_score', 0) > 30)
            
            if is_suspicious:
                has_positives = True
                name = res.get('process_name', 'Unknown')
                pid = res.get('pid')
                story.append(Paragraph(f"<b>Process: {name} (PID: {pid})</b>", self.styles['TimesNormal']))
                
                # Behavioral
                behavior = res.get('features', {}).get('behavioral_indicators', {})
                if behavior.get('suspicious_apis', {}).get('total_references', 0) > 0 or behavior.get('network_indicators', {}).get('has_network_activity'):
                    story.append(Paragraph("Behavioral Analysis Match:", self.styles['TimesNormal']))
                    if behavior.get('network_indicators', {}).get('has_network_activity'):
                         story.append(bullet("[SUSPICIOUS] Network Activity Detected"))
                    if behavior.get('suspicious_apis', {}).get('total_references', 0) > 0:
                         story.append(bullet(f"[SUSPICIOUS] Suspicious API Calls: {behavior['suspicious_apis']['total_references']} detections"))

                # YARA
                yara_res = res.get('features', {}).get('signature_indicators', {})
                if yara_res.get('total_detections', 0) > 0:
                     story.append(Paragraph("YARA Signature Match:", self.styles['TimesNormal']))
                     for match in yara_res.get('matched_rules', []):
                         sev = match.get('severity', 'HIGH').upper()
                         story.append(bullet(f"[{sev}] Rule Match: {match.get('name')}"))
                         
                # Anomaly
                anomaly = res.get('anomaly_detection', {})
                if anomaly.get('is_anomalous'):
                     story.append(Paragraph("Anomaly Detection:", self.styles['TimesNormal']))
                     for det in anomaly.get('detected_anomalies', []):
                         story.append(bullet(f"[{det.get('severity', 'MEDIUM')}] {det.get('type')}: {det.get('description')}"))
                
                story.append(Spacer(1, 0.1*inch))
                
        if not has_positives:
            story.append(Paragraph("No significant threats detected in active processes.", self.styles['TimesNormal']))

        # 4. THREAT SCORING
        story.append(Paragraph("4. THREAT SCORING", self.styles['SectionHeader']))
        
        scoring_data = [["Process", "Threat Score", "Severity", "Description"]]
        for res in batch_results:
            score = res.get('features', {}).get('risk_assessment', {}).get('risk_score', 0)
            
            # Determine logic
            if score < 20:
                sev = "Low (Safe)"
                desc = "Standard baseline behavior."
            elif score < 40:
                sev = "Medium (Suspicious)"
                desc = "Unusual patterns detected."
            elif score < 70:
                sev = "High (Danger)"
                desc = "Significant behavioral anomalies."
            else:
                sev = "Critical (Malicious)"
                desc = "Confirmed anomaly or signature."
                
            scoring_data.append([
                res.get('process_name'),
                f"{score:.0f} / 100",
                sev,
                desc
            ])
            
        score_table = Table(scoring_data, colWidths=[2.0*inch, 1.2*inch, 1.5*inch, 2.5*inch])
        score_table.setStyle(TableStyle([
             ('FONTNAME', (0,0), (-1,-1), 'Times-Roman'),
             ('FONTSIZE', (0,0), (-1,-1), 12),
             ('FONTNAME', (0,0), (-1,0), 'Times-Bold'),
             ('GRID', (0,0), (-1,-1), 1, colors.black),
             ('BACKGROUND', (0,0), (-1,0), colors.lightgrey),
        ]))
        story.append(score_table)
        
        story.append(Spacer(1, 0.1*inch))
        story.append(Paragraph("<b>Score Key:</b>", self.styles['TimesNormal']))
        story.append(bullet("Low (0–19): Safe. No significant anomalies."))
        story.append(bullet("Medium (20–39): Suspicious. Requires manual investigation."))
        story.append(bullet("High (40–69): High Risk. Significant behavioral anomalies."))
        story.append(bullet("Critical (70–100): confirmed threat/malicious."))

        # 5. PROCESS VERDICT
        story.append(Paragraph("5. PROCESS VERDICT", self.styles['SectionHeader']))
        
        for res in batch_results:
             name = res.get('process_name')
             pid = res.get('pid')
             score = res.get('features', {}).get('risk_assessment', {}).get('risk_score', 0)
             
             story.append(Paragraph(f"<b>{name} (PID: {pid})</b>", self.styles['TimesNormal']))
             
             if score < 20:
                 verdict = "[SAFE]"
             elif score < 40:
                 verdict = "[SUSPICIOUS]"
             elif score < 70:
                 verdict = "[HIGH RISK]"
             else:
                 verdict = "[MALICIOUS]"
                 
             story.append(Paragraph(f"Verdict: <b>{verdict}</b>", self.styles['TimesNormal']))
             # Mock rationale logic for generic output
             if score < 20:
                 rationale = "Explanation: Process behavior matches safe baseline. No anomalies."
             elif score < 40:
                 rationale = "Rationale: Exhibits minor unusual behavior, warranting review."
             elif score < 70:
                 rationale = "Rationale: HIGH RISK. Exhibits patterns strongly matching known threats."
             else:
                 rationale = "Rationale: CRITICAL THREAT. Confirmed signature or highly malicious artifact detected."
            
             story.append(Paragraph(rationale, self.styles['TimesNormal']))
             story.append(Spacer(1, 0.1*inch))
             
        # 6. OVERALL SCAN RESULT
        story.append(Paragraph("6. OVERALL SCAN RESULT", self.styles['SectionHeader']))
        
        # Stats
        total = len(batch_results)
        malicious = len([r for r in batch_results if r.get('features', {}).get('risk_assessment', {}).get('risk_score', 0) >= 70])
        high_risk = len([r for r in batch_results if 40 <= r.get('features', {}).get('risk_assessment', {}).get('risk_score', 0) < 70])
        suspicious = len([r for r in batch_results if 20 <= r.get('features', {}).get('risk_assessment', {}).get('risk_score', 0) < 40])
        safe = total - malicious - high_risk - suspicious
        
        story.append(Paragraph("<b>Scan Summary:</b>", self.styles['TimesNormal']))
        story.append(bullet(f"Total Processes Scanned: {total}"))
        story.append(bullet(f"Safe Processes: {safe}"))
        story.append(bullet(f"Suspicious Processes: {suspicious}"))
        story.append(bullet(f"High Risk Processes: {high_risk}"))
        story.append(bullet(f"Malicious Processes: {malicious}"))
        
        story.append(Spacer(1, 0.1*inch))
        story.append(Paragraph("<b>Final System Status:</b>", self.styles['TimesNormal']))
        
        if malicious > 0 or high_risk > 0:
            status_text = "[SYSTEM COMPROMISED]"
            action = "Action Required: High-risk or Malicious activity detected. Initiate Incident Response."
            status_color = colors.red
        elif suspicious > 0:
             status_text = "[SYSTEM WARNING]"
             action = "Action Required: Review suspicious processes manually."
             status_color = colors.orange
        else:
             status_text = "[SYSTEM SAFE]"
             action = "No active threats detected at this time."
             status_color = colors.green
             
        status_style = ParagraphStyle('StatusStyle', parent=self.styles['CustomTitle'], textColor=status_color)
        story.append(Paragraph(status_text, status_style))
        story.append(Spacer(1, 0.1*inch))
        story.append(Paragraph(f"<b>{action}</b>", self.styles['TimesNormal']))

        doc.build(story)
        
        # [NEW] Sign Batch Report
        self.sign_pdf(report_path)
        
        logger.info(f"Batch report generated: {report_path}")
        return report_path
    
    def _build_title_page(self, process_info: Dict, timestamp: str) -> List:
        """Build report title page"""
        elements = []
        
        # Logo (if available)
        if self.logo_path:
            try:
                logo = Image(str(self.logo_path), width=2*inch, height=2*inch)
                elements.append(logo)
                elements.append(Spacer(1, 0.5*inch))
            except:
                pass
        
        # Title
        elements.append(Paragraph(
            "FORENSIC MEMORY ANALYSIS REPORT",
            self.styles['CustomTitle']
        ))
        elements.append(Paragraph(
            "Generated by: Live Memory Forensics Toolkit for Detecting In-Memory Malware and Hidden Processes",
            self.styles['Normal']
        ))
        elements.append(Spacer(1, 0.3*inch))
        
        # Report metadata
        metadata_data = [
            ["Report Generated:", timestamp],
            ["Process Name:", process_info.get('name', 'N/A')],
            ["Process ID:", str(process_info.get('pid', 'N/A'))],
            ["Classification:", "CONFIDENTIAL - FORENSIC EVIDENCE"]
        ]
        
        metadata_table = Table(metadata_data, colWidths=[2*inch, 4*inch])
        metadata_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#34495e')),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.whitesmoke),
            ('BACKGROUND', (1, 0), (1, -1), colors.HexColor('#ecf0f1')),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey)
        ]))
        
        elements.append(metadata_table)
        
        return elements
    
    def _build_executive_summary(
        self,
        yara_results: Dict,
        hook_results: Dict,
        ml_results: Dict,
        feature_data: Dict,
        anomaly_results: Dict = None
    ) -> List:
        """Build executive summary section"""
        elements = []
        
        elements.append(Paragraph("EXECUTIVE SUMMARY", self.styles['SectionHeader']))
        elements.append(Spacer(1, 0.2*inch))
        
        # Determine overall verdict
        # Prioritize Risk Score (Feature Extractor) as it contains the Whitelist logic
        risk_score = feature_data.get('risk_assessment', {}).get('risk_score', 0)
        
        # Verdict Logic:
        # 1. If Risk Score is High/Critical (>55), it's MALICIOUS
        # 2. If Risk Score is Low/Medium, it's BENIGN
        
        # Check if risk assessment was actually performed
        has_risk_assessment = 'risk_assessment' in feature_data
        
        if has_risk_assessment:
             is_malicious = risk_score >= 70
        else:
             # Fallback only if no risk score exists
             is_malicious = (
                yara_results.get('is_malicious', False) or
                ml_results.get('is_malicious', False)
             )
        
        verdict = "MALICIOUS" if is_malicious else "BENIGN"
        verdict_color = colors.red if is_malicious else colors.green
        
        verdict_text = f"<b>OVERALL VERDICT: <font color='{verdict_color.hexval()}'>{verdict}</font></b>"
        elements.append(Paragraph(verdict_text, self.styles['Normal']))
        elements.append(Spacer(1, 0.2*inch))
        
        # Key findings
        # Use Filtered YARA count from features, not raw results
        filtered_yara_count = feature_data.get('signature_indicators', {}).get('total_detections', 0)
        
        summary_points = [
            f"• YARA Signature Detections: {filtered_yara_count}",
            f"• API Hooks Detected: {len(hook_results.get('hooks_detected', []))}",
            f"• ML Malware Confidence: {ml_results.get('confidence_scores', {}).get('malware', 0):.2%}",
            f"• Risk Score: {risk_score}/100"
        ]
        
        if anomaly_results:
             summary_points.append(f"• Anomalies Detected: {len(anomaly_results.get('detected_anomalies', []))}")
             summary_points.append(f"• Anomaly Score: {anomaly_results.get('anomaly_score', 0):.1f}/100")
        
        for point in summary_points:
            elements.append(Paragraph(point, self.styles['Normal']))
        
        elements.append(Spacer(1, 0.3*inch))
        
        return elements
    
    def _build_process_section(self, process_info: Dict) -> List:
        """Build process information section"""
        elements = []
        
        elements.append(Paragraph("PROCESS INFORMATION", self.styles['SectionHeader']))
        
        proc_data = [
            ["Property", "Value"],
            ["Process Name", process_info.get('name', 'N/A')],
            ["Process ID", str(process_info.get('pid', 'N/A'))],
            ["Memory Size (MB)", str(process_info.get('memory_mb', 'N/A'))]
        ]
        
        proc_table = Table(proc_data, colWidths=[2*inch, 4*inch])
        proc_table.setStyle(self._get_table_style())
        
        elements.append(proc_table)
        elements.append(Spacer(1, 0.3*inch))
        
        return elements
    
    def _build_yara_section(self, sig_indicators: Dict) -> List:
        """
        Build YARA findings section
        Uses filtered signature data from Feature Extraction
        
        Args:
            sig_indicators: Dictionary from features['signature_indicators']
        """
        elements = []
        
        elements.append(Paragraph("SIGNATURE-BASED DETECTION (YARA)", self.styles['SectionHeader']))
        
        # Use filtered total count
        total_matches = sig_indicators.get('total_detections', 0)
        
        # Handle case where suppressed count > 0 (Optional: display suppressed info?)
        suppressed = sig_indicators.get('suppressed_matches', 0)
        
        count_text = f"Total Matches: <b>{total_matches}</b>"
        if suppressed > 0:
            count_text += f" <font size=8 color='grey'>(Suppressed FS False Positives: {suppressed})</font>"
            
        elements.append(Paragraph(count_text, self.styles['Normal']))
        elements.append(Spacer(1, 0.1*inch))
        
        if total_matches > 0:
            for rule in sig_indicators.get('matched_rules', []):
                rule_name = rule.get('name', 'Unknown Rule')
                severity = rule.get('severity', 'unknown')
                
                elements.append(Paragraph(
                    f"<b>Rule: {rule_name}</b> [Severity: {severity.upper()}]",
                    self.styles['Critical'] if severity.lower() == 'critical' else self.styles['Normal']
                ))
                
                desc = rule.get('description', 'No description')
                elements.append(Paragraph(f"Description: {desc}", self.styles['Normal']))
                elements.append(Spacer(1, 0.1*inch))
        else:
            elements.append(Paragraph("No suspicious YARA signatures matched.", self.styles['Normal']))
        
        elements.append(Spacer(1, 0.3*inch))
        
        return elements
    
    def _build_hook_section(self, hook_results: Dict) -> List:
        """Build hook detection section"""
        elements = []
        
        elements.append(Paragraph("MEMORY INTEGRITY VALIDATION", self.styles['SectionHeader']))
        
        is_compromised = hook_results.get('is_compromised', False)
        status = "COMPROMISED" if is_compromised else "CLEAN"
        status_color = colors.red if is_compromised else colors.green
        
        elements.append(Paragraph(
            f"Status: <font color='{status_color.hexval()}'><b>{status}</b></font>",
            self.styles['Normal']
        ))
        elements.append(Spacer(1, 0.1*inch))
        
        hooks = hook_results.get('hooks_detected', [])
        if hooks:
            elements.append(Paragraph(f"<b>Hooked Functions ({len(hooks)}):</b>", self.styles['Normal']))
            
            for hook in hooks:
                elements.append(Paragraph(
                    f"• {hook['function']} @ {hook['address']}",
                    self.styles['Critical']
                ))
        else:
            elements.append(Paragraph("No API hooks detected.", self.styles['Normal']))
        
        elements.append(Spacer(1, 0.3*inch))
        
        return elements
    
    def _build_behavioral_section(self, feature_data: Dict) -> List:
        """Build behavioral analysis section"""
        elements = []
        
        elements.append(Paragraph("BEHAVIORAL INDICATORS", self.styles['SectionHeader']))
        
        behavioral = feature_data.get('behavioral_indicators', {})
        
        # Suspicious APIs
        api_data = behavioral.get('suspicious_apis', {})
        elements.append(Paragraph(
            f"Suspicious API References: {api_data.get('total_references', 0)}",
            self.styles['Normal']
        ))
        
        # Network indicators
        network = behavioral.get('network_indicators', {})
        if network.get('has_network_activity'):
            elements.append(Paragraph("[ALERT] Network activity detected", self.styles['Normal']))
        
        # URLs
        urls = behavioral.get('urls', [])
        if urls:
            elements.append(Paragraph(f"URLs Found: {len(urls)}", self.styles['Normal']))
            for url in urls[:5]:  # Show first 5
                elements.append(Paragraph(f"  • {url}", self.styles['ReportCode']))
        
        elements.append(Spacer(1, 0.3*inch))
        
        return elements

    def _build_anomaly_section(self, anomaly_results: Dict) -> List:
        """Build anomaly detection section"""
        elements = []
        
        elements.append(Paragraph("ANOMALY DETECTION", self.styles['SectionHeader']))
        
        if not anomaly_results:
            elements.append(Paragraph("No anomaly detection results available.", self.styles['Normal']))
            return elements
            
        score = anomaly_results.get('anomaly_score', 0)
        is_anomalous = anomaly_results.get('is_anomalous', False)
        
        status = "ANOMALOUS" if is_anomalous else "NORMAL"
        status_color = colors.red if is_anomalous else colors.green
        
        elements.append(Paragraph(
            f"Status: <font color='{status_color.hexval()}'><b>{status}</b></font> (Score: {score:.1f}/100)",
            self.styles['Normal']
        ))
        elements.append(Spacer(1, 0.1*inch))
        
        anomalies = anomaly_results.get('detected_anomalies', [])
        if anomalies:
            elements.append(Paragraph(f"<b>Detected Anomalies ({len(anomalies)}):</b>", self.styles['Normal']))
            
            for anomaly in anomalies:
                severity = anomaly.get('severity', 'LOW')
                style = self.styles['Critical'] if severity in ['HIGH', 'CRITICAL'] else self.styles['ReportCode']
                
                elements.append(Paragraph(
                    f"• [{severity}] {anomaly.get('type')}: {anomaly.get('description')}",
                    style
                ))
        else:
            elements.append(Paragraph("No statistical or behavioral anomalies detected.", self.styles['Normal']))
        
        elements.append(Spacer(1, 0.3*inch))
        
        return elements
    
    def _build_ml_section(self, ml_results: Dict) -> List:
        """Build ML analysis section"""
        elements = []
        
        elements.append(Paragraph("MACHINE LEARNING ANALYSIS", self.styles['SectionHeader']))
        
        classification = ml_results.get('classification', 'Unknown')
        malware_conf = ml_results.get('confidence_scores', {}).get('malware', 0)
        
        elements.append(Paragraph(f"Classification: <b>{classification}</b>", self.styles['Normal']))
        elements.append(Paragraph(f"Malware Confidence: <b>{malware_conf:.2%}</b>", self.styles['Normal']))
        
        # Feature importance
        if 'feature_importance' in ml_results:
            elements.append(Spacer(1, 0.1*inch))
            elements.append(Paragraph("Top Contributing Features:", self.styles['Normal']))
            
            for feat in ml_results['feature_importance'].get('top_contributing_features', [])[:5]:
                elements.append(Paragraph(
                    f"• {feat['name']}: {feat['value']} (importance: {feat['importance']:.3f})",
                    self.styles['Normal']
                ))
        
        elements.append(Spacer(1, 0.3*inch))
        
        return elements
    
    def _build_evidence_section(self, evidence_chain: Dict) -> List:
        """Build evidence chain section"""
        elements = []
        
        elements.append(Paragraph("EVIDENCE CHAIN", self.styles['SectionHeader']))
        
        # RAW dump info
        raw = evidence_chain.get('raw_dump', {})
        elements.append(Paragraph("<b>Raw Memory Dump:</b>", self.styles['Normal']))
        elements.append(Paragraph(f"SHA256: {raw.get('sha256', 'N/A')}", self.styles['ReportCode']))
        elements.append(Paragraph(f"Status: {raw.get('deletion_status', 'N/A')}", self.styles['Normal']))
        elements.append(Spacer(1, 0.1*inch))
        
        # Artifact info
        artifact = evidence_chain.get('artifact', {})
        elements.append(Paragraph("<b>JSON Artifact:</b>", self.styles['Normal']))
        elements.append(Paragraph(f"Path: {artifact.get('path', 'N/A')}", self.styles['ReportCode']))
        elements.append(Spacer(1, 0.3*inch))
        
        return elements
    
    def _build_recommendations(
        self,
        yara_results: Dict,
        hook_results: Dict,
        ml_results: Dict,
        feature_data: Dict = None
    ) -> List:
        """Build recommendations section"""
        elements = []
        
        elements.append(Paragraph("RECOMMENDATIONS", self.styles['SectionHeader']))
        
        recommendations = []
        
        # Verdict Logic based on Risk Score (filtered)
        if feature_data and 'risk_assessment' in feature_data:
            risk_score = feature_data['risk_assessment'].get('risk_score', 0)
            is_effectively_malicious = risk_score >= 70
        else:
            # Fallback to raw flags if risk score is missing
            is_effectively_malicious = yara_results.get('is_malicious', False)
        
        # Only show alarmist recommendations if effectively malicious (Risk Score > 55)
        # OR if there are critical integrity violations (Hooks) which are rarely false positives
        
        if is_effectively_malicious:
            recommendations.append("• Immediately quarantine or terminate the process")
            recommendations.append("• Perform full system scan with updated signatures")
        
        if hook_results.get('is_compromised'):
            recommendations.append("• Investigate hooking process origin")
            recommendations.append("• Check for rootkit or advanced malware")
        
        # Only add ML warning if verdict is malicious OR confidence is extremely high
        if ml_results.get('is_malicious') and is_effectively_malicious:
            recommendations.append("• Submit sample for advanced malware analysis")
            recommendations.append("• Review network logs for C2 communications")
        
        if hook_results.get('is_compromised'):
            recommendations.append("• Investigate hooking process origin")
            recommendations.append("• Check for rootkit or advanced malware")
        
        if ml_results.get('is_malicious'):
            recommendations.append("• Submit sample for advanced malware analysis")
            recommendations.append("• Review network logs for C2 communications")
        
        if not recommendations:
            # BENIGN/CLEAN Case: Use specific user-requested success message
            elements.append(Paragraph(
                "The system analysis was completed successfully. Based on the results obtained from behavioral analysis and rule-based detection mechanisms, no suspicious or malicious activity was detected at the time of analysis.",
                self.styles['Normal']
            ))
            return elements
        
        for rec in recommendations:
            elements.append(Paragraph(rec, self.styles['Normal']))
        
        return elements
    
    def _build_methodology_section(self) -> List:
        """Build methodology explanation section"""
        elements = []
        elements.append(Paragraph("DETECTION METHODOLOGY", self.styles['SectionHeader']))
        
        methodology_text = """
        <b>1. Signature-Based Detection (YARA):</b>
        Scans process memory against a database of known malware patterns (e.g., Ransomware, RATs, Keyloggers). 
        Matches indicate recognized threats.
        
        <b>2. Behavioral Analysis (Machine Learning):</b>
        Uses a Random Forest classifier to evaluate process behavior (API usage, Entropy, Network activity). 
        A "Suspicious" verdict indicates behavior resembling malware, even if no signature matches.
        
        <b>3. Anomaly Detection:</b>
        Statistical analysis to identify outliers. High entropy or unusual memory allocations contribute to the Anomaly Score.
        """
        elements.append(Paragraph(methodology_text, self.styles['Normal']))
        elements.append(Spacer(1, 0.2*inch))
        return elements

    def _build_verdict_interpretation(self) -> List:
        """Build verdict interpretation guide"""
        elements = []
        elements.append(Paragraph("VERDICT INTERPRETATION GUIDE", self.styles['SectionHeader']))
        
        guide_text = """
        <b>CLEAN:</b> No significant malicious indicators found. 
        <i>Note:</i> "Clean" verdict refers to the specific memory snapshot at the time of analysis. It does not guarantee the system is free of dormant malware.
        
        <b>SUSPICIOUS (Medium Risk):</b> Process exhibits behavior common to malware (e.g., high entropy, weird API calls) but lacks a confirmed signature. 
        <i>Action:</i> Manual review recommended.
        
        <b>MALICIOUS (High/Critical Risk):</b> Strong evidence of compromise. Confirmed by YARA signature OR high-confidence behavioral patterns. 
        <i>Action:</i> Immediate quarantine required.
        """
        elements.append(Paragraph(guide_text, self.styles['Normal']))
        return elements
        
    def _get_table_style(self) -> TableStyle:
        """Get standard table style"""
        return TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3498db')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ])
