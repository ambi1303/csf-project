import os
import sys
import time
import json
import logging
from pathlib import Path
from datetime import datetime
from bs4 import BeautifulSoup
from zap_simple import ZAPSimpleScanner
from config import REPORTS_DIR, LOGS_DIR, SCAN_TYPES, LOG_LEVEL

# Configure logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOGS_DIR / "zap_integration.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("ZAPIntegration")

class ZAPIntegration:
    def __init__(self, report_dir=REPORTS_DIR):
        self.report_dir = Path(report_dir)
        self.report_dir.mkdir(exist_ok=True)
        self.scanner = None
        self.last_scan_results = None
        
    def initialize_scanner(self, target_url):
        """Initialize the ZAP scanner with a target URL"""
        try:
            self.scanner = ZAPSimpleScanner(target_url, self.report_dir)
            return True
        except Exception as e:
            logger.error(f"Error initializing ZAP scanner: {e}")
            return False
            
    def run_scan(self, scan_type="baseline"):
        """Run a scan with the specified type"""
        if not self.scanner:
            logger.error("Scanner not initialized")
            return {"error": "Scanner not initialized. Please click 'Initialize Scanner' first."}
            
        try:
            if scan_type not in SCAN_TYPES:
                logger.error(f"Unknown scan type: {scan_type}")
                return {"error": f"Unknown scan type: {scan_type}"}
                
            logger.info(f"Starting {scan_type} scan of {self.scanner.target_url}")
            
            # Verify target URL is accessible
            try:
                import requests
                response = requests.head(self.scanner.target_url, timeout=5)
                response.raise_for_status()
            except Exception as e:
                logger.error(f"Target URL is not accessible: {e}")
                return {"error": f"Target URL ({self.scanner.target_url}) is not accessible. Please verify the URL and try again."}
            
            report_file = self.scanner.run_scan(scan_type)
            
            if not report_file:
                logger.error("Scan failed to generate a report")
                return {
                    "error": "Scan failed. Please try:\n1. Stop ZAP using stop_zap.py\n2. Initialize scanner again\n3. Run the scan"
                }
                
            # Check if the report file exists
            if not os.path.exists(report_file):
                logger.error(f"Report file was not created: {report_file}")
                return {
                    "error": f"Report file was not created. The scan may have failed. Please try stopping and reinitializing ZAP."
                }
                
            results = self.parse_scan_results(report_file)
            if not results:
                logger.error(f"Failed to parse scan results from {report_file}")
                return {
                    "error": f"Failed to parse scan results. The report may be empty or in an unexpected format."
                }
                
            self.last_scan_results = results
            logger.info(f"Scan completed successfully. Results saved to {report_file}")
            return results
            
        except Exception as e:
            logger.error(f"Error running scan: {e}")
            return {"error": f"Error running scan: {str(e)}. Try stopping ZAP and initializing again."}
            
    def parse_scan_results(self, report_file):
        """Parse the scan results from the HTML report"""
        if not report_file or not os.path.exists(report_file):
            logger.error(f"Report file not found: {report_file}")
            return None
            
        try:
            with open(report_file, 'r', encoding='utf-8') as f:
                soup = BeautifulSoup(f.read(), 'html.parser')
                
            # Extract vulnerabilities from the report
            vulnerabilities = []
            alerts = soup.find_all('div', class_='alert')
            
            for alert in alerts:
                vuln = {
                    'severity': alert.get('data-risk', 'Unknown'),
                    'name': alert.find('h3').text if alert.find('h3') else 'Unknown',
                    'description': alert.find('p', class_='description').text if alert.find('p', class_='description') else '',
                    'solution': alert.find('p', class_='solution').text if alert.find('p', class_='solution') else '',
                    'references': alert.find('p', class_='references').text if alert.find('p', class_='references') else '',
                    'instances': []
                }
                
                # Extract vulnerability instances
                instances = alert.find_all('tr')
                for instance in instances:
                    cols = instance.find_all('td')
                    if len(cols) >= 3:
                        vuln['instances'].append({
                            'url': cols[0].text,
                            'parameter': cols[1].text,
                            'evidence': cols[2].text
                        })
                        
                vulnerabilities.append(vuln)
                
            return {
                'report_file': report_file,
                'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
                'target_url': self.scanner.target_url,
                'vulnerabilities': vulnerabilities,
                'summary': self.generate_summary(vulnerabilities)
            }
        except Exception as e:
            logger.error(f"Error parsing scan results: {e}")
            return None
            
    def generate_summary(self, vulnerabilities):
        """Generate a summary of the vulnerabilities"""
        severity_counts = {'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
        
        for vuln in vulnerabilities:
            severity = vuln['severity']
            if severity in severity_counts:
                severity_counts[severity] += 1
                
        summary = []
        for severity, count in severity_counts.items():
            if count > 0:
                summary.append(f"{count} {severity}")
                
        if not summary:
            return "No vulnerabilities found"
            
        return f"Found {len(vulnerabilities)} vulnerabilities: {', '.join(summary)}"
        
    def generate_report_for_streamlit(self, report_file):
        """Generate a report suitable for display in Streamlit"""
        results = self.parse_scan_results(report_file)
        if not results:
            return {
                "error": "Failed to parse scan results",
                "vulnerabilities": [],
                "summary": "No scan results available"
            }
            
        # Group vulnerabilities by severity
        severity_order = ['High', 'Medium', 'Low', 'Informational']
        grouped_vulns = {severity: [] for severity in severity_order}
        
        for vuln in results['vulnerabilities']:
            severity = vuln['severity']
            if severity in grouped_vulns:
                grouped_vulns[severity].append(vuln)
                
        # Format for Streamlit display
        return {
            "report_file": results['report_file'],
            "scan_time": results['scan_time'],
            "target_url": results['target_url'],
            "vulnerabilities": grouped_vulns,
            "summary": results['summary']
        }
        
    def get_chatbot_response(self, user_query, report_file=None):
        """Generate a response for the chatbot based on the user query and scan results"""
        if not report_file and hasattr(self.scanner, 'last_report_file'):
            report_file = self.scanner.last_report_file
            
        if not report_file or not os.path.exists(report_file):
            return "I don't have any scan results to analyze yet. Please run a scan first."
            
        results = self.parse_scan_results(report_file)
        if not results:
            return "I couldn't analyze the scan results. Please try running the scan again."
            
        query = user_query.lower()
        
        # Handle different types of queries
        if "vulnerability" in query or "vulnerabilities" in query:
            return self._handle_vulnerability_query(query, results)
        elif "fix" in query or "solution" in query or "remediation" in query:
            return self._handle_solution_query(query, results)
        elif "summary" in query or "overview" in query:
            return results['summary']
        else:
            return (
                "I can help you understand the scan results. You can ask about:\n"
                "- Vulnerabilities found\n"
                "- How to fix specific issues\n"
                "- Get a summary of the results\n"
                "What would you like to know?"
            )
            
    def _handle_vulnerability_query(self, query, results):
        """Handle queries about vulnerabilities"""
        vulns = results['vulnerabilities']
        
        if "high" in query:
            high_vulns = [v for v in vulns if v['severity'] == 'High']
            if high_vulns:
                return self._format_vulnerability_list(high_vulns, "high severity")
            return "No high severity vulnerabilities were found."
            
        if "medium" in query:
            medium_vulns = [v for v in vulns if v['severity'] == 'Medium']
            if medium_vulns:
                return self._format_vulnerability_list(medium_vulns, "medium severity")
            return "No medium severity vulnerabilities were found."
            
        # Default to showing all vulnerabilities
        return self._format_vulnerability_list(vulns, "all")
        
    def _handle_solution_query(self, query, results):
        """Handle queries about fixing vulnerabilities"""
        vulns = results['vulnerabilities']
        
        # Look for specific vulnerability mentions in the query
        for vuln in vulns:
            if vuln['name'].lower() in query:
                return (
                    f"To fix the {vuln['name']} vulnerability:\n\n"
                    f"{vuln['solution']}\n\n"
                    f"References:\n{vuln['references']}"
                )
                
        # If no specific vulnerability mentioned, provide general advice
        return (
            "To fix the identified vulnerabilities, you should:\n\n"
            "1. Address high severity issues first\n"
            "2. Follow secure coding practices\n"
            "3. Implement input validation\n"
            "4. Use parameterized queries\n"
            "5. Keep all software updated\n\n"
            "Would you like specific details about fixing a particular vulnerability?"
        )
        
    def _format_vulnerability_list(self, vulns, severity_type):
        """Format a list of vulnerabilities for display"""
        if not vulns:
            return f"No {severity_type} vulnerabilities found."
            
        result = f"Found {len(vulns)} {severity_type} vulnerabilities:\n\n"
        for i, vuln in enumerate(vulns, 1):
            result += (
                f"{i}. {vuln['name']} (Severity: {vuln['severity']})\n"
                f"   Description: {vuln['description']}\n"
                f"   Found in {len(vuln['instances'])} location(s)\n\n"
            )
        return result

def streamlit_integration():
    """Example of how to integrate with Streamlit"""
    pass  # Implementation moved to app.py

def chatbot_integration():
    """Example of how to integrate with a chatbot"""
    pass  # Implementation moved to bot.py

if __name__ == "__main__":
    # Example usage
    zap = ZAPIntegration()
    
    # Initialize scanner
    target_url = "http://example.com"
    if zap.initialize_scanner(target_url):
        print("Scanner initialized successfully!")
        
        # Run scan
        results = zap.run_scan("baseline")
        
        if "error" in results:
            print(f"Error: {results['error']}")
        else:
            print(f"Scan completed! Report saved to {results['report_file']}")
            
            # Generate report for Streamlit
            report_data = zap.generate_report_for_streamlit(results["report_file"])
            print("\nReport Summary:")
            print(report_data["summary"])
            
            # Example chatbot response
            response = zap.get_chatbot_response("What vulnerabilities did you find?", results["report_file"])
            print("\nChatbot Response:")
            print(response)
    else:
        print("Failed to initialize scanner.") 