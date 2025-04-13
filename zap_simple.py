import os
import subprocess
import time
import sys
import platform
import json
import logging
from pathlib import Path
from config import (
    ZAP_PATHS,
    REPORTS_DIR,
    LOGS_DIR,
    SCAN_TYPES,
    LOG_LEVEL
)
from typing import Dict, Any
from datetime import datetime
from bs4 import BeautifulSoup

# Configure logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOGS_DIR / "zap_scanner.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("ZAPScanner")

class ZAPSimpleScanner:
    def __init__(self, target_url: str, reports_dir: str = None):
        """Initialize the ZAP scanner."""
        # Validate target URL
        if not target_url:
            raise ValueError("Target URL cannot be empty")
            
        # Format target URL
        target_url = target_url.strip()
        if target_url.startswith("http://") or target_url.startswith("https://"):
            self.target_url = target_url
        else:
            self.target_url = f"http://{target_url}"
            
        # Set up report directory
        if reports_dir:
            self.report_dir = reports_dir
        else:
            self.report_dir = os.path.join(os.getcwd(), "reports")
        os.makedirs(self.report_dir, exist_ok=True)
        
        # Find ZAP installation
        self.zap_path = self._find_zap_installation()
        if not self.zap_path:
            raise RuntimeError("ZAP installation not found")
            
        logger.info(f"Initialized ZAP scanner with target URL: {self.target_url}")
        
        # Set timeout based on scan type (will be updated in run_scan)
        self.timeout = SCAN_TYPES["quick"]["timeout"]  # Default to quick scan timeout
        
        # Verify the ZAP path exists and is accessible
        if not os.path.exists(self.zap_path):
            raise FileNotFoundError(f"ZAP path does not exist: {self.zap_path}")
            
        # Make sure the path is absolute
        self.zap_path = os.path.abspath(self.zap_path)
        logger.info(f"Using ZAP installation at: {self.zap_path}")
        
    def _find_zap_installation(self):
        """Find ZAP installation path based on operating system"""
        system = platform.system()
        
        # For macOS, try to find ZAP in Applications first
        if system == "Darwin":
            # Check Applications directory
            app_paths = [
                "/Applications/ZAP.app/Contents/Java",
                "/Applications/OWASP ZAP.app/Contents/Java"
            ]
            
            for path in app_paths:
                if os.path.exists(path):
                    logger.info(f"Found ZAP in Applications: {path}")
                    # Check for zap.sh first
                    zap_sh = os.path.join(path, "zap.sh")
                    if os.path.exists(zap_sh):
                        return zap_sh
                    # Then check for jar files
                    jar_files = list(Path(path).glob("zap-*.jar"))
                    if jar_files:
                        return str(jar_files[0])
                    # Check lib directory
                    lib_path = os.path.join(path, "lib")
                    if os.path.exists(lib_path):
                        jar_files = list(Path(lib_path).glob("zap-*.jar"))
                        if jar_files:
                            return str(jar_files[0])
            
            # If not found in Applications, check other paths
            for path in ZAP_PATHS[system]:
                if os.path.exists(path):
                    logger.info(f"Found ZAP in alternative location: {path}")
                    zap_sh = os.path.join(path, "zap.sh")
                    if os.path.exists(zap_sh):
                        return zap_sh
                    jar_files = list(Path(path).glob("zap-*.jar"))
                    if jar_files:
                        return str(jar_files[0])
        
        # For Linux and Windows, use the standard paths
        elif system in ZAP_PATHS:
            for path in ZAP_PATHS[system]:
                if os.path.exists(path):
                    logger.info(f"Found ZAP at: {path}")
                    if system == "Linux":
                        zap_sh = os.path.join(path, "zap.sh")
                        if os.path.exists(zap_sh):
                            return zap_sh
                    else:  # Windows
                        zap_bat = os.path.join(path, "zap.bat")
                        if os.path.exists(zap_bat):
                            return zap_bat
        
        logger.error(f"ZAP not found in any of the expected locations")
        return None
        
    def _show_installation_instructions(self):
        """Show instructions for installing ZAP"""
        print("\n❌ OWASP ZAP is not installed or not found in the expected location.")
        print("\nPlease follow these steps to install ZAP:")
        print("1. Visit https://www.zaproxy.org/download/")
        print("2. Download the appropriate package for your system:")
        if platform.system() == "Darwin":
            print("   - Download the macOS version")
            print("   - Move ZAP.app to your Applications folder")
        elif platform.system() == "Linux":
            print("   - Use your package manager:")
            print("     sudo apt install zaproxy  # For Ubuntu/Debian")
            print("     sudo dnf install zaproxy  # For Fedora")
        else:  # Windows
            print("   - Download the Windows installer")
            print("   - Run the installer with default options")
        print("3. Run this script again after installation")
        
    def _get_zap_command(self, args):
        """Get the appropriate ZAP command based on platform"""
        system = platform.system()
        
        # If we have a direct path to a jar file or script
        if self.zap_path.endswith('.jar') or self.zap_path.endswith('.sh') or self.zap_path.endswith('.bat'):
            if self.zap_path.endswith('.jar'):
                return ["java", "-jar", self.zap_path] + args
            else:
                return [self.zap_path] + args
        
        # Otherwise, build the command based on the platform
        if system == "Darwin":
            # For macOS
            zap_script = os.path.join(self.zap_path, "zap.sh")
            if os.path.exists(zap_script):
                return [zap_script] + args
            
            # Look for jar files
            jar_files = list(Path(self.zap_path).glob("zap-*.jar"))
            if jar_files:
                return ["java", "-jar", str(jar_files[0])] + args
            
            # Check lib directory
            lib_path = os.path.join(self.zap_path, "lib")
            if os.path.exists(lib_path):
                jar_files = list(Path(lib_path).glob("zap-*.jar"))
                if jar_files:
                    return ["java", "-jar", str(jar_files[0])] + args
        
        elif system == "Linux":
            # For Linux
            zap_script = os.path.join(self.zap_path, "zap.sh")
            if os.path.exists(zap_script):
                return [zap_script] + args
        
        else:  # Windows
            # For Windows
            zap_bat = os.path.join(self.zap_path, "zap.bat")
            if os.path.exists(zap_bat):
                return [zap_bat] + args
        
        raise FileNotFoundError(f"Could not find ZAP executable in {self.zap_path}")
            
    def _run_zap_command(self, args, background=False):
        """Run a ZAP command with proper error handling"""
        try:
            cmd = self._get_zap_command(args)
            logger.info(f"Running command: {' '.join(cmd)}")
            
            if background:
                subprocess.Popen(cmd)
                return True
            else:
                result = subprocess.run(cmd, check=True, capture_output=True, text=True)
                return result.stdout
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed with exit code {e.returncode}")
            logger.error(f"Error output: {e.stderr}")
            return None
        except Exception as e:
            logger.error(f"Error running ZAP command: {e}")
            return None
            
    def stop_zap(self):
        """Stop any running ZAP instances"""
        try:
            logger.info("Stopping any running ZAP instances")
            system = platform.system()
            
            if system == "Darwin":  # macOS
                subprocess.run(["pkill", "-f", "zap"], check=False)
            elif system == "Linux":
                subprocess.run(["pkill", "-f", "zap"], check=False)
            elif system == "Windows":
                subprocess.run(["taskkill", "/F", "/IM", "zap.exe"], check=False)
            else:
                logger.warning(f"Unsupported operating system: {system}")
                return False
                
            # Wait a moment to ensure processes are terminated
            time.sleep(2)
            return True
        except Exception as e:
            logger.error(f"Error stopping ZAP: {e}")
            return False
            
    def run_scan(self, target_url: str = None, scan_type: str = "quick") -> dict:
        """Run a security scan on the target URL."""
        try:
            # Use instance target_url if none provided
            if target_url is None:
                target_url = self.target_url
                
            # Validate scan type
            if scan_type not in SCAN_TYPES:
                raise ValueError(f"Invalid scan type: {scan_type}. Must be one of {list(SCAN_TYPES.keys())}")
                
            # Get scan configuration
            scan_config = SCAN_TYPES[scan_type]
            self.timeout = scan_config["timeout"]
            
            # Set up scan command
            cmd = [
                str(self.zap_path),
                "-cmd",
                "-quickurl", target_url,
                "-quickprogress",
                "-quickout", str(Path(self.report_dir) / f"report_{scan_type}.html")
            ]
            
            # Add scan type specific settings
            if "config" in scan_config:
                for key, value in scan_config["config"].items():
                    cmd.extend(["-config", f"{key}={value}"])
            
            logger.info(f"Starting {scan_type} scan on {target_url}")
            logger.debug(f"Scan command: {' '.join(cmd)}")
            
            # Run the scan
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            # Wait for the scan to complete or timeout
            try:
                stdout, stderr = process.communicate(timeout=self.timeout)
                if process.returncode != 0:
                    logger.error(f"Scan failed with return code {process.returncode}")
                    logger.error(f"Stderr: {stderr}")
                    return {"error": f"Scan failed: {stderr}"}
                    
                # Parse the report
                report_file = Path(self.report_dir) / f"report_{scan_type}.html"
                if not report_file.exists():
                    logger.error("Report file not found")
                    return {"error": "Report file not found"}
                    
                alerts = self._parse_report(report_file)
                return {"alerts": alerts}
                
            except subprocess.TimeoutExpired:
                process.kill()
                logger.error(f"Scan timed out after {self.timeout} seconds")
                return {"error": f"Scan timed out after {self.timeout} seconds"}
                
        except Exception as e:
            logger.error(f"Error running scan: {str(e)}")
            return {"error": str(e)}
        
    def run_gui(self):
        """Launch ZAP GUI with the target URL"""
        logger.info(f"Launching ZAP GUI for {self.target_url}")
        return self._run_zap_command(["-url", self.target_url], background=True)
        
    def get_scan_results(self, report_file):
        """Parse the scan results from the report file"""
        if not report_file or not os.path.exists(report_file):
            logger.error(f"Report file not found: {report_file}")
            return None
            
        try:
            return {
                "report_file": report_file,
                "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "target_url": self.target_url,
                "scan_status": "completed"
            }
        except Exception as e:
            logger.error(f"Error parsing scan results: {e}")
            return None

    def _parse_report(self, report_file: Path) -> Dict:
        """Parse the HTML report file and extract vulnerability information"""
        try:
            if not report_file.exists():
                logger.error(f"Report file not found: {report_file}")
                return {"error": "Report file not found"}

            # Read the HTML report
            with open(report_file, 'r', encoding='utf-8') as f:
                html_content = f.read()

            # Parse the HTML content
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Extract alerts
            alerts = []
            alert_sections = soup.find_all('div', class_='alert')
            
            for alert in alert_sections:
                try:
                    # Extract risk level
                    risk_elem = alert.find('span', class_='risk')
                    risk = risk_elem.text.strip() if risk_elem else "Info"
                    
                    # Extract alert name
                    name_elem = alert.find('h3')
                    name = name_elem.text.strip() if name_elem else "Unknown"
                    
                    # Extract description
                    desc_elem = alert.find('div', class_='desc')
                    description = desc_elem.text.strip() if desc_elem else ""
                    
                    # Extract solution
                    solution_elem = alert.find('div', class_='solution')
                    solution = solution_elem.text.strip() if solution_elem else ""
                    
                    # Extract URL
                    url_elem = alert.find('div', class_='url')
                    url = url_elem.text.strip() if url_elem else ""
                    
                    alerts.append({
                        "name": name,
                        "risk": risk,
                        "description": description,
                        "solution": solution,
                        "url": url
                    })
                except Exception as e:
                    logger.warning(f"Error parsing alert: {e}")
                    continue

            return {
                "alerts": alerts,
                "report_file": str(report_file),
                "scan_time": datetime.now().isoformat(),
                "target_url": self.target_url,
                "scan_status": "completed"
            }

        except Exception as e:
            logger.error(f"Error parsing report: {e}", exc_info=True)
            return {"error": f"Error parsing report: {str(e)}"}

def main():
    print("\n🔒 OWASP ZAP Simple Scanner")
    print("=========================")
    
    # Use testphp.vulnweb.com as the default URL
    target_url = "http://testphp.vulnweb.com"
    print(f"\nUsing default target URL: {target_url}")
    
    try:
        # Create scanner
        scanner = ZAPSimpleScanner(target_url)
        
        # Show scan options
        print("\nAvailable scan types:")
        for key, scan in SCAN_TYPES.items():
            print(f"{key}: {scan['name']} - {scan['description']}")
        print("gui: Launch ZAP GUI")
        
        # Get user choice
        choice = input("\nEnter scan type: ").lower()
        
        if choice == "gui":
            if scanner.run_gui():
                print("✅ ZAP GUI launched successfully")
            else:
                print("❌ Failed to launch ZAP GUI")
        elif choice in SCAN_TYPES:
            results = scanner.run_scan(choice)
            if results.get("error"):
                print(f"\n❌ Error: {results['error']}")
            else:
                print("\nScan Results:")
                print(json.dumps(results, indent=2))
        else:
            print("❌ Invalid scan type selected")
            
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        logger.exception("Unexpected error occurred")

if __name__ == "__main__":
    main() 