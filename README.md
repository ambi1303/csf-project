# Web Application Security Scanner

A web-based security scanning tool powered by OWASP ZAP, featuring an interactive dashboard and chatbot interface.

## Features

- Multiple scan types (Quick, Baseline, Full)
- Interactive dashboard with vulnerability visualization
- Chatbot interface for exploring scan results
- Detailed vulnerability reporting
- Cross-platform support (macOS, Linux, Windows)

## Prerequisites

1. Python 3.8 or higher
2. OWASP ZAP installed on your system
3. pip (Python package manager)

## Installation

1. Install OWASP ZAP:
   - **macOS**: `brew install --cask owasp-zap`
   - **Linux**: `sudo apt install zaproxy` (Ubuntu/Debian) or `sudo dnf install zaproxy` (Fedora)
   - **Windows**: Download from [OWASP ZAP website](https://www.zaproxy.org/download/)

2. Clone this repository:
   ```bash
   git clone <repository-url>
   cd web-security-scanner
   ```

3. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

4. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Start the Streamlit app:
   ```bash
   streamlit run app.py
   ```

2. Open your web browser and navigate to the URL shown in the terminal (usually http://localhost:8501)

3. In the web interface:
   - Enter the target URL
   - Select a scan type
   - Initialize the scanner
   - Run the scan
   - Explore the results and use the chatbot for questions

## Scan Types

1. **Quick Scan**
   - Fast scan with basic security checks
   - Duration: ~5 minutes
   - Best for initial assessment

2. **Baseline Scan**
   - Standard security checks
   - Duration: ~20 minutes
   - Recommended for most cases

3. **Full Scan**
   - Comprehensive security assessment
   - Duration: ~60 minutes
   - Best for thorough testing

## Configuration

The scanner can be configured by modifying `config.py`:
- API settings
- Scan timeouts
- Report formats
- Logging options

## Troubleshooting

1. **ZAP not found**
   - Verify OWASP ZAP is installed
   - Check installation path in config.py
   - Try running ZAP manually first

2. **Connection errors**
   - Ensure target URL is accessible
   - Check firewall settings
   - Verify ZAP is running

3. **Scan failures**
   - Check logs in the logs directory
   - Verify target is responsive
   - Try a different scan type

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- OWASP ZAP Team
- Streamlit
- Beautiful Soup
- Plotly 