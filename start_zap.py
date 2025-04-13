import os
import sys
import platform
import subprocess
import time
import logging
from pathlib import Path
from config import ZAP_PATHS, ZAP_API_KEY, ZAP_PORT

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("ZAPStarter")

def check_zap_installation():
    """Check if ZAP is installed and return the installation path"""
    system = platform.system()
    if system in ZAP_PATHS:
        for path in ZAP_PATHS[system]:
            if os.path.exists(path):
                return path
    return None

def start_zap():
    """Start ZAP with the correct configuration"""
    zap_path = check_zap_installation()
    if not zap_path:
        logger.error("OWASP ZAP not found in expected locations")
        show_installation_instructions()
        sys.exit(1)

    logger.info(f"Found ZAP at: {zap_path}")
    
    # Get the appropriate ZAP command based on platform
    system = platform.system()
    if system == "Darwin":  # macOS
        zap_script = os.path.join(zap_path, "zap.sh")
        if not os.path.exists(zap_script):
            # Use jar directly if script not found
            jar_files = list(Path(zap_path).glob("zap-*.jar"))
            if not jar_files:
                logger.error("ZAP JAR file not found")
                sys.exit(1)
            cmd = ["java", "-jar", str(jar_files[0])]
        else:
            cmd = [zap_script]
    elif system == "Linux":
        cmd = [os.path.join(zap_path, "zap.sh")]
    else:  # Windows
        cmd = [os.path.join(zap_path, "zap.bat")]

    # Add configuration options
    cmd.extend([
        "-daemon",
        "-port", str(ZAP_PORT),
        "-config", f"api.key={ZAP_API_KEY}",
        "-config", "api.addrs.addr.name=.*",
        "-config", "api.addrs.addr.regex=true",
        "-config", "api.addrs.addr.enabled=true",
        "-config", "api.key.disable=false",
        "-config", "api.incerrordetails=true"
    ])

    try:
        logger.info("Starting ZAP...")
        subprocess.Popen(cmd)
        
        # Wait for ZAP to start
        time.sleep(5)
        
        # Check if ZAP is running
        if check_zap_running():
            logger.info("✅ ZAP started successfully")
            show_configuration_instructions()
        else:
            logger.error("❌ Failed to start ZAP")
            sys.exit(1)
    except Exception as e:
        logger.error(f"Error starting ZAP: {e}")
        sys.exit(1)

def check_zap_running():
    """Check if ZAP is running by attempting to connect to it"""
    try:
        import requests
        response = requests.get(f"http://localhost:{ZAP_PORT}/")
        return response.status_code == 200
    except:
        return False

def show_installation_instructions():
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

def show_configuration_instructions():
    """Show instructions for configuring ZAP"""
    print("\n✅ ZAP is now running with the following configuration:")
    print(f"- Port: {ZAP_PORT}")
    print(f"- API Key: {ZAP_API_KEY}")
    print("\nYou can now:")
    print("1. Run the scanner using: python3 zap_simple.py <target_url>")
    print("2. Use the integration: python3 zap_integration.py")
    print("3. Start the Streamlit app: streamlit run app.py")

def main():
    print("\n🔒 OWASP ZAP Starter")
    print("===================")
    start_zap()

if __name__ == "__main__":
    main() 