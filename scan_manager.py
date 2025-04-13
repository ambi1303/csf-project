import os
import logging
from datetime import datetime
from pathlib import Path
from zap_simple import ZAPSimpleScanner
from config import SCAN_TYPES, PATHS
from vulnerability_analyzer import SimpleVulnerabilityAnalyzer
from report_generator import ReportGenerator

logger = logging.getLogger(__name__)

class ScanManager:
    def __init__(self):
        """Initialize the scan manager."""
        self.reports_dir = Path(PATHS["reports"])
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.scanner = None
        self.vulnerability_analyzer = SimpleVulnerabilityAnalyzer()
        self.report_generator = ReportGenerator()
        
    def start_scan(self, target_url, scan_type="quick"):
        """Start a security scan with the specified type."""
        try:
            # Validate scan type
            if scan_type not in SCAN_TYPES:
                raise ValueError(f"Invalid scan type: {scan_type}")
            
            # Initialize scanner if needed
            if not self.scanner:
                self.scanner = ZAPSimpleScanner(target_url, str(self.reports_dir))
            
            # Get scan configuration
            scan_config = SCAN_TYPES[scan_type]
            
            # Run the scan
            logger.info(f"Starting {scan_type} scan for {target_url}")
            scan_results = self.scanner.run_scan(target_url, scan_type)
            
            # Process scan results
            if "error" in scan_results:
                return scan_results
            
            # Generate report filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_filename = f"scan_{scan_type}_{timestamp}.html"
            report_path = self.reports_dir / report_filename
            
            # Count alerts by risk level
            alert_counts = {
                "High": 0,
                "Medium": 0,
                "Low": 0,
                "Info": 0
            }
            
            for alert in scan_results.get("alerts", []):
                try:
                    if isinstance(alert, dict):
                        risk = alert.get("risk", "Info")
                    else:
                        # If alert is a string, try to parse it or default to Info
                        risk = "Info"
                        logger.warning(f"Received string alert instead of dictionary: {alert}")
                    alert_counts[risk] = alert_counts.get(risk, 0) + 1
                except Exception as e:
                    logger.error(f"Error processing alert: {e}")
                    continue
            
            # Add metadata to results
            scan_results.update({
                "scan_type": scan_type,
                "scan_time": datetime.now().isoformat(),
                "target_url": target_url,
                "alert_counts": alert_counts,
                "report_path": str(report_path)
            })
            
            # Generate report
            try:
                # Extract vulnerabilities from scan results
                vulnerabilities = scan_results.get("alerts", [])
                
                # Generate all reports
                report_files = self.report_generator.generate_all_reports(vulnerabilities)
                
                # Update the report path in scan results
                if report_files and "technical" in report_files:
                    scan_results["report_path"] = report_files["technical"]
            except Exception as e:
                logger.error(f"Error generating report: {e}", exc_info=True)
                # Continue with the scan results even if report generation fails
            
            return scan_results
            
        except Exception as e:
            logger.error(f"Error during scan: {e}", exc_info=True)
            return {
                "error": "Scan failed",
                "details": str(e)
            }
    
    def get_scan_status(self, scan_id):
        """Get the status of a scan."""
        if not self.scanner:
            return {"status": "not_started"}
        
        try:
            return self.scanner.get_scan_status(scan_id)
        except Exception as e:
            logger.error(f"Error getting scan status: {e}", exc_info=True)
            return {"status": "error", "details": str(e)}
    
    def stop_scan(self, scan_id):
        """Stop a running scan."""
        if not self.scanner:
            return {"status": "not_started"}
        
        try:
            return self.scanner.stop_scan(scan_id)
        except Exception as e:
            logger.error(f"Error stopping scan: {e}", exc_info=True)
            return {"status": "error", "details": str(e)}

def main():
    """Main function to run the scan manager."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Run a security scan")
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument("--scan-type", choices=list(SCAN_TYPES.keys()), default="quick",
                      help="Type of scan to run")
    parser.add_argument("--output-dir", default=PATHS["reports"],
                      help="Directory to save reports")
    
    args = parser.parse_args()
    
    # Initialize scan manager
    manager = ScanManager()
    
    # Run scan
    results = manager.start_scan(args.url, args.scan_type)
    
    # Print results
    if "error" in results:
        print(f"Error: {results['error']}")
        if "details" in results:
            print(f"Details: {results['details']}")
    else:
        print(f"Scan completed successfully")
        print(f"Report saved to: {results['report_path']}")
        print("\nAlert Summary:")
        for risk, count in results["alert_counts"].items():
            print(f"{risk}: {count}")

if __name__ == "__main__":
    main() 