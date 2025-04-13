"""
Configuration settings for the security scanner.
"""

import os
from pathlib import Path

# Base paths
BASE_DIR = Path(__file__).parent
REPORTS_DIR = BASE_DIR / "reports"
LOGS_DIR = BASE_DIR / "logs"

# Create necessary directories
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
LOGS_DIR.mkdir(parents=True, exist_ok=True)

# Path configuration
PATHS = {
    "reports": str(REPORTS_DIR),
    "logs": str(LOGS_DIR),
    "templates": str(BASE_DIR / "templates"),
    "data": str(BASE_DIR / "data")
}

# Scan type configurations
SCAN_TYPES = {
    "quick": {
        "name": "Quick Scan",
        "description": "Fast scan with basic security checks",
        "timeout": 300,  # 5 minutes
        "scanner_settings": {
            "max_children_to_crawl": 10,
            "max_depth": 3,
            "max_parse_size_bytes": 2621440,  # 2.5MB
            "excluded_paths": [],
            "included_paths": [],
            "scan_rules": ["10016", "10020", "10021", "10038"]  # Basic security rules
        }
    },
    "baseline": {
        "name": "Baseline Scan",
        "description": "Standard security assessment",
        "timeout": 900,  # 15 minutes
        "scanner_settings": {
            "max_children_to_crawl": 50,
            "max_depth": 5,
            "max_parse_size_bytes": 5242880,  # 5MB
            "excluded_paths": [],
            "included_paths": [],
            "scan_rules": ["10016", "10020", "10021", "10038", "90022", "90018"]  # Extended security rules
        }
    },
    "full": {
        "name": "Full Scan",
        "description": "Comprehensive security assessment",
        "timeout": 1800,  # 30 minutes
        "scanner_settings": {
            "max_children_to_crawl": 100,
            "max_depth": 10,
            "max_parse_size_bytes": 10485760,  # 10MB
            "excluded_paths": [],
            "included_paths": [],
            "scan_rules": []  # All rules
        }
    }
}

# Risk level definitions
RISK_LEVELS = {
    "High": {
        "score": 3,
        "color": "#ff4444",
        "description": "Critical security issues that require immediate attention"
    },
    "Medium": {
        "score": 2,
        "color": "#ffbb33",
        "description": "Security issues that should be addressed soon"
    },
    "Low": {
        "score": 1,
        "color": "#00C851",
        "description": "Minor security issues that should be monitored"
    },
    "Info": {
        "score": 0,
        "color": "#33b5e5",
        "description": "Informational findings that may be of interest"
    }
}

# Scanner settings
SCANNER_SETTINGS = {
    "api_key": os.getenv("ZAP_API_KEY", ""),
    "api_url": os.getenv("ZAP_API_URL", "http://localhost:8080"),
    "proxy": os.getenv("HTTP_PROXY", ""),
    "timeout": 300,
    "max_retries": 3
}

# Report settings
REPORT_SETTINGS = {
    "template": "default",
    "format": "html",
    "include_screenshots": True,
    "include_request_response": True,
    "include_evidence": True
}

# ZAP Configuration
ZAP_CONFIG = {
    "api_key": "your-api-key-here",
    "target_url": "http://testphp.vulnweb.com",
    "scan_policy": {
        "name": "Default Policy",
        "description": "Default scanning policy",
        "rules": [
            {
                "id": 40012,
                "name": "Cross Site Scripting (Reflected)",
                "threshold": "MEDIUM"
            },
            {
                "id": 40014,
                "name": "Cross Site Scripting (Persistent)",
                "threshold": "MEDIUM"
            },
            {
                "id": 40018,
                "name": "SQL Injection",
                "threshold": "HIGH"
            },
            {
                "id": 90022,
                "name": "Application Error Disclosure",
                "threshold": "MEDIUM"
            }
        ]
    },
    "scan_settings": {
        "max_scan_duration": 3600,  # 1 hour
        "max_alerts": 100,
        "target_timeout": 300,  # 5 minutes
        "thread_count": 4,
        "delay_in_ms": 0
    }
}

# Scan Types Configuration
SCAN_TYPES = {
    "quick": {
        "name": "Quick Scan",
        "description": "Fast scan with basic checks",
        "timeout": 180,  # 3 minutes
        "config": {
            "scanner.strength": "low",
            "scanner.maxRuleDurationInMins": "1",
            "scanner.maxScanDurationInMins": "2",
            "scanner.maxResultsToScan": "50",
            "scanner.maxChildrenToCrawl": "5",
            "scanner.maxDepthToCrawl": "2",
            "scanner.maxParseSizeBytes": "1048576",
            "scanner.maxScansInUI": "1",
            "scanner.threadPerHost": "1",
            "scanner.excludeUserAgent": "true",
            "scanner.excludeFromScan": ".*\\.(css|js|png|jpg|jpeg|gif|ico|woff|woff2|ttf|eot)$",
            "spider.maxDuration": "1",
            "spider.maxParseSizeBytes": "1048576",
            "spider.maxChildrenToCrawl": "5",
            "spider.maxDepthToCrawl": "2",
            "spider.maxThreads": "1",
            "spider.maxTimeInMinutes": "1",
            "spider.maxChildrenToCrawl": "5",
            "spider.maxDepthToCrawl": "2",
            "spider.maxParseSizeBytes": "1048576",
            "spider.maxThreads": "1",
            "spider.maxTimeInMinutes": "1",
            "spider.maxChildrenToCrawl": "5",
            "spider.maxDepthToCrawl": "2",
            "spider.maxParseSizeBytes": "1048576",
            "spider.maxThreads": "1",
            "spider.maxTimeInMinutes": "1"
        }
    },
    "baseline": {
        "name": "Baseline Scan",
        "description": "Standard security checks",
        "timeout": 600,  # 10 minutes
        "config": {
            "scanner.strength": "medium",
            "scanner.maxRuleDurationInMins": "5",
            "scanner.maxScanDurationInMins": "10",
            "scanner.maxResultsToScan": "200",
            "scanner.maxChildrenToCrawl": "20",
            "scanner.maxDepthToCrawl": "5",
            "scanner.maxParseSizeBytes": "5242880",
            "scanner.maxScansInUI": "1",
            "scanner.threadPerHost": "4",
            "scanner.excludeUserAgent": "true",
            "scanner.excludeFromScan": ".*\\.(css|js|png|jpg|jpeg|gif|ico|woff|woff2|ttf|eot)$"
        }
    },
    "full": {
        "name": "Full Scan",
        "description": "Comprehensive security analysis",
        "timeout": 1200,  # 20 minutes
        "config": {
            "scanner.strength": "high",
            "scanner.maxRuleDurationInMins": "10",
            "scanner.maxScanDurationInMins": "20",
            "scanner.maxResultsToScan": "500",
            "scanner.maxChildrenToCrawl": "50",
            "scanner.maxDepthToCrawl": "10",
            "scanner.maxParseSizeBytes": "10485760",
            "scanner.maxScansInUI": "1",
            "scanner.threadPerHost": "8",
            "scanner.excludeUserAgent": "true",
            "scanner.excludeFromScan": ".*\\.(css|js|png|jpg|jpeg|gif|ico|woff|woff2|ttf|eot)$"
        }
    }
}

# Paths Configuration
REPORTS_DIR = BASE_DIR / 'reports'
LOGS_DIR = BASE_DIR / 'logs'
MODELS_DIR = BASE_DIR / 'models'
CHAT_HISTORY_DIR = BASE_DIR / 'chat_history'

# Create necessary directories
for directory in [REPORTS_DIR, LOGS_DIR, MODELS_DIR, CHAT_HISTORY_DIR]:
    directory.mkdir(exist_ok=True)

# Logging Configuration
LOG_CONFIG = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'standard': {
            'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
        },
    },
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': LOGS_DIR / 'zap_scanner.log',
            'formatter': 'standard',
        },
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'standard',
        }
    },
    'loggers': {
        '': {  # root logger
            'handlers': ['console', 'file'],
            'level': 'INFO',
            'propagate': True
        }
    }
}

# Report Configuration
REPORT_FORMATS = {
    'json': {
        'enabled': True,
        'template': None  # Uses default JSON serialization
    },
    'html': {
        'enabled': True,
        'template': str(BASE_DIR / 'templates' / 'report.html')
    },
    'pdf': {
        'enabled': False,
        'template': str(BASE_DIR / 'templates' / 'report.pdf')
    }
}

# Default paths for different operating systems
ZAP_PATHS = {
    "Darwin": [  # macOS
        "/Applications/ZAP.app/Contents/Java",
        "/Applications/OWASP ZAP.app/Contents/Java"
    ],
    "Linux": [
        "/usr/share/zaproxy",
        "/usr/share/zap",
        "/opt/zaproxy"
    ],
    "Windows": [
        r"C:\Program Files\OWASP\ZAP",
        r"C:\Program Files (x86)\OWASP\ZAP"
    ]
}

# Scan Configuration
DEFAULT_SCAN_POLICY = "Default Policy"

# Logging Configuration
LOG_LEVEL = "INFO"

# Vulnerability Analysis Configuration
VULNERABILITY_RISK_FACTORS = {
    'exploitability': 0.3,
    'cve_severity': 0.2,
    'endpoint_criticality': 0.2,
    'user_access_frequency': 0.15,
    'business_impact': 0.15
}

RISK_THRESHOLDS = {
    'high': 0.7,
    'medium': 0.4,
    'low': 0.1
}

FALSE_POSITIVE_MODEL_PATH = MODELS_DIR / 'false_positive_model.joblib'
VULNERABILITY_RANKER_PATH = MODELS_DIR / 'vulnerability_ranker.joblib'

# Chatbot Configuration
GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY', 'your-gemini-api-key-here')
CHATBOT_SETTINGS = {
    'max_history': 10,
    'temperature': 0.7,
    'top_p': 0.9
}

# Report Templates
REPORT_TEMPLATES = {
    'management': str(BASE_DIR / 'templates' / 'management_report.md'),
    'developer': str(BASE_DIR / 'templates' / 'developer_report.md'),
    'technical': str(BASE_DIR / 'templates' / 'technical_report.md')
}

# ML Model Configuration
ML_CONFIG = {
    'models': {
        'exploitability': {
            'path': MODELS_DIR / 'exploitability_model.joblib',
            'version': '1.0',
            'type': 'ensemble'
        },
        'false_positive': {
            'path': MODELS_DIR / 'false_positive_model.joblib',
            'version': '1.0',
            'type': 'ensemble'
        },
        'business_impact': {
            'path': MODELS_DIR / 'business_impact_model.joblib',
            'version': '1.0',
            'type': 'ensemble'
        }
    },
    'training': {
        'batch_size': 32,
        'epochs': 10,
        'validation_split': 0.2
    }
}

# NLP Configuration
NLP_CONFIG = {
    'embeddings': {
        'model': 'sentence-transformers/all-MiniLM-L6-v2',
        'max_length': 512
    },
    'summarization': {
        'max_length': 150,
        'min_length': 50,
        'do_sample': True
    }
}

# Dashboard Configuration
DASHBOARD_CONFIG = {
    'update_interval': 300,  # 5 minutes
    'max_history_points': 100,
    'chart_theme': 'plotly_dark',
    'risk_colors': {
        'high': '#ff4b4b',
        'medium': '#ffa500',
        'low': '#2ecc71',
        'info': '#3498db'
    }
}

# Knowledge Base Configuration
KB_CONFIG = {
    'sources': {
        'owasp': 'https://owasp.org/www-project-top-ten/',
        'cve': 'https://cve.mitre.org/data/downloads/',
        'cwe': 'https://cwe.mitre.org/data/published/cwe_latest.pdf'
    },
    'update_frequency': 86400  # 24 hours
} 