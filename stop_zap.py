#!/usr/bin/env python3
import os
import sys
import platform
import subprocess
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("ZAPStopper")

def stop_zap():
    """Stop any running ZAP instances"""
    system = platform.system()
    
    try:
        if system == "Darwin":  # macOS
            # Use pkill to find and kill ZAP processes
            logger.info("Stopping ZAP processes on macOS...")
            subprocess.run(["pkill", "-f", "zap"], check=False)
            logger.info("ZAP processes stopped")
            
        elif system == "Linux":
            # Use pkill on Linux
            logger.info("Stopping ZAP processes on Linux...")
            subprocess.run(["pkill", "-f", "zap"], check=False)
            logger.info("ZAP processes stopped")
            
        elif system == "Windows":
            # Use taskkill on Windows
            logger.info("Stopping ZAP processes on Windows...")
            subprocess.run(["taskkill", "/F", "/IM", "zap.exe"], check=False)
            logger.info("ZAP processes stopped")
            
        else:
            logger.error(f"Unsupported operating system: {system}")
            return False
            
        # Wait a moment to ensure processes are terminated
        import time
        time.sleep(2)
        
        return True
        
    except Exception as e:
        logger.error(f"Error stopping ZAP: {e}")
        return False

def main():
    print("\n🛑 OWASP ZAP Stopper")
    print("===================")
    
    if stop_zap():
        print("✅ ZAP processes stopped successfully")
    else:
        print("❌ Failed to stop ZAP processes")
        print("You may need to manually stop ZAP processes")

if __name__ == "__main__":
    main() 