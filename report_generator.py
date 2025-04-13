import google.generativeai as genai
import os
import json
import logging
from datetime import datetime
from pathlib import Path
from config import GEMINI_API_KEY, REPORT_TEMPLATES, REPORTS_DIR

# Configure logging
logger = logging.getLogger(__name__)

class ReportGenerator:
    def __init__(self):
        """Initialize the ReportGenerator with Gemini API."""
        try:
            logger.info("Initializing ReportGenerator")
            genai.configure(api_key=GEMINI_API_KEY)
            try:
                # Try to list available models first
                available_models = genai.list_models()
                logger.info(f"Available Gemini models: {[m.name for m in available_models]}")
                
                # Try to use gemini-pro, fall back to other models if available
                try:
                    self.model = genai.GenerativeModel('gemini-pro')
                    self.gemini_available = True
                    logger.info("Successfully initialized gemini-pro model")
                except Exception as e:
                    logger.warning(f"Failed to initialize gemini-pro model: {e}")
                    # Try to find an alternative model
                    alternative_models = [m for m in available_models if 'gemini' in m.name.lower()]
                    if alternative_models:
                        self.model = genai.GenerativeModel(alternative_models[0].name)
                        self.gemini_available = True
                        logger.info(f"Using alternative model: {alternative_models[0].name}")
                    else:
                        self.gemini_available = False
                        logger.warning("No suitable Gemini models found")
            except Exception as e:
                logger.warning(f"Gemini API not available: {e}")
                self.gemini_available = False
                
            # Ensure reports directory exists
            Path(REPORTS_DIR).mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.error(f"Error initializing ReportGenerator: {e}")
            self.gemini_available = False
            raise
        
    def generate_management_summary(self, vulnerabilities):
        """Generate a non-technical summary for management."""
        try:
            logger.info("Generating management summary")
            if not self.gemini_available:
                return self._generate_fallback_summary(vulnerabilities, "management")
            prompt = self._create_management_prompt(vulnerabilities)
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            logger.error(f"Error generating management summary: {e}")
            return self._generate_fallback_summary(vulnerabilities, "management")
    
    def generate_developer_report(self, vulnerabilities):
        """Generate a technical report with code patches for developers."""
        try:
            logger.info("Generating developer report")
            if not self.gemini_available:
                return self._generate_fallback_summary(vulnerabilities, "developer")
            prompt = self._create_developer_prompt(vulnerabilities)
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            logger.error(f"Error generating developer report: {e}")
            return self._generate_fallback_summary(vulnerabilities, "developer")
    
    def generate_technical_report(self, vulnerabilities):
        """Generate a detailed technical report."""
        try:
            logger.info("Generating technical report")
            if not self.gemini_available:
                return self._generate_fallback_summary(vulnerabilities, "technical")
            prompt = self._create_technical_prompt(vulnerabilities)
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            logger.error(f"Error generating technical report: {e}")
            return self._generate_fallback_summary(vulnerabilities, "technical")
    
    def _create_management_prompt(self, vulnerabilities):
        """Create a prompt for management summary."""
        try:
            return f"""
            Create a non-technical summary of these security vulnerabilities for management:
            {json.dumps(vulnerabilities, indent=2)}
            
            Focus on:
            1. Business impact
            2. Risk level
            3. Required actions
            4. Timeline for fixes
            
            Use simple language and avoid technical terms.
            """
        except Exception as e:
            logger.error(f"Error creating management prompt: {e}")
            return "Error creating management prompt."
    
    def _create_developer_prompt(self, vulnerabilities):
        """Create a prompt for developer report."""
        try:
            return f"""
            Create a technical report with code patches for these vulnerabilities:
            {json.dumps(vulnerabilities, indent=2)}
            
            For each vulnerability:
            1. Explain the technical issue
            2. Provide sample code showing the vulnerability
            3. Provide sample code showing the fix
            4. Include best practices to prevent similar issues
            
            Use code blocks with appropriate language tags.
            """
        except Exception as e:
            logger.error(f"Error creating developer prompt: {e}")
            return "Error creating developer prompt."
    
    def _create_technical_prompt(self, vulnerabilities):
        """Create a prompt for technical report."""
        try:
            return f"""
            Create a detailed technical report for these vulnerabilities:
            {json.dumps(vulnerabilities, indent=2)}
            
            Include:
            1. Vulnerability details
            2. CVE information
            3. Technical impact
            4. Recommended fixes
            5. References to security standards
            """
        except Exception as e:
            logger.error(f"Error creating technical prompt: {e}")
            return "Error creating technical prompt."
    
    def save_report(self, report_content, report_type, output_dir=REPORTS_DIR):
        """Save the generated report to a file."""
        try:
            logger.info(f"Saving {report_type} report")
            # Ensure the directory exists
            Path(output_dir).mkdir(parents=True, exist_ok=True)
            
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{report_type}_report_{timestamp}.md"
            filepath = Path(output_dir) / filename
            
            with open(filepath, 'w') as f:
                f.write(report_content)
            
            logger.info(f"Report saved to {filepath}")
            return str(filepath)
        except Exception as e:
            logger.error(f"Error saving report: {e}")
            return None
    
    def generate_all_reports(self, vulnerabilities, output_dir=REPORTS_DIR):
        """Generate all types of reports and save them."""
        try:
            logger.info("Generating all reports")
            reports = {
                'management': self.generate_management_summary(vulnerabilities),
                'developer': self.generate_developer_report(vulnerabilities),
                'technical': self.generate_technical_report(vulnerabilities)
            }
            
            saved_files = {}
            for report_type, content in reports.items():
                filepath = self.save_report(content, report_type, output_dir)
                if filepath:
                    saved_files[report_type] = filepath
            
            return saved_files
        except Exception as e:
            logger.error(f"Error generating all reports: {e}")
            return {}
    
    def get_cve_details(self, cve_id):
        """Get detailed information about a CVE using Gemini."""
        try:
            logger.info(f"Getting details for CVE-{cve_id}")
            prompt = f"""
            Provide detailed information about CVE-{cve_id}:
            1. Description
            2. Severity
            3. Affected systems
            4. Known exploits
            5. Mitigation strategies
            """
            
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            logger.error(f"Error getting CVE details: {e}")
            return f"Error retrieving details for CVE-{cve_id}. Please check the logs for details."
    
    def generate_patch_suggestion(self, vulnerability):
        """Generate a specific patch suggestion for a vulnerability."""
        try:
            logger.info("Generating patch suggestion")
            prompt = f"""
            Generate a specific code patch for this vulnerability:
            {json.dumps(vulnerability, indent=2)}
            
            Include:
            1. Before and after code examples
            2. Explanation of the fix
            3. Testing instructions
            4. Potential side effects to consider
            """
            
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            logger.error(f"Error generating patch suggestion: {e}")
            return "Error generating patch suggestion. Please check the logs for details."
            
    def generate_json_report(self, vulnerabilities):
        """Generate a JSON report of vulnerabilities."""
        try:
            logger.info("Generating JSON report")
            report = {
                "timestamp": datetime.now().isoformat(),
                "vulnerabilities": vulnerabilities,
                "summary": {
                    "total": len(vulnerabilities),
                    "by_risk": {
                        "high": sum(1 for v in vulnerabilities if v.get("risk", "").lower() == "high"),
                        "medium": sum(1 for v in vulnerabilities if v.get("risk", "").lower() == "medium"),
                        "low": sum(1 for v in vulnerabilities if v.get("risk", "").lower() == "low"),
                        "info": sum(1 for v in vulnerabilities if v.get("risk", "").lower() == "info")
                    }
                }
            }
            
            # Save the JSON report
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"vulnerability_report_{timestamp}.json"
            filepath = Path(REPORTS_DIR) / filename
            
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2)
                
            logger.info(f"JSON report saved to {filepath}")
            return str(filepath)
        except Exception as e:
            logger.error(f"Error generating JSON report: {e}")
            return None

    def _generate_fallback_summary(self, vulnerabilities, report_type):
        """Generate a fallback summary when Gemini API is not available."""
        try:
            # Count vulnerabilities by risk level
            risk_counts = {}
            for vuln in vulnerabilities:
                risk = vuln.get("risk", "Info")
                if risk in risk_counts:
                    risk_counts[risk] += 1
                else:
                    risk_counts[risk] = 1
            
            # Generate a simple summary
            total = len(vulnerabilities)
            summary = f"# {report_type.capitalize()} Report\n\n"
            summary += f"Total vulnerabilities found: {total}\n\n"
            
            if total > 0:
                summary += "## Risk Distribution\n\n"
                for risk, count in risk_counts.items():
                    summary += f"- {risk}: {count}\n"
                
                summary += "\n## Vulnerability Details\n\n"
                for i, vuln in enumerate(vulnerabilities, 1):
                    summary += f"### {i}. {vuln.get('name', 'Unknown')} ({vuln.get('risk', 'Info')})\n\n"
                    summary += f"**Description:** {vuln.get('description', 'No description available')}\n\n"
                    summary += f"**Solution:** {vuln.get('solution', 'No solution available')}\n\n"
                    summary += f"**URL:** {vuln.get('url', 'N/A')}\n\n"
            else:
                summary += "No vulnerabilities were found in the scan.\n"
            
            return summary
        except Exception as e:
            logger.error(f"Error generating fallback summary: {e}")
            return f"Error generating {report_type} report. Please check the logs for details." 