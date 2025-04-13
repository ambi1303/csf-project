import streamlit as st
import logging
from datetime import datetime
import json
from pathlib import Path
from scan_manager import ScanManager
from vulnerability_analyzer import SimpleVulnerabilityAnalyzer
from report_generator import ReportGenerator
from config import SCAN_TYPES, LOG_CONFIG, DASHBOARD_CONFIG
import logging.config
import os
from zap_integration import ZAPIntegration
import pandas as pd
import plotly.express as px
from simple_chatbot import SimpleSecurityChatbot

# Configure logging
logging.config.dictConfig(LOG_CONFIG)
logger = logging.getLogger(__name__)

def initialize_session_state():
    """Initialize session state variables."""
    if "scan_manager" not in st.session_state:
        st.session_state.scan_manager = ScanManager()
    if "vulnerability_analyzer" not in st.session_state:
        st.session_state.vulnerability_analyzer = SimpleVulnerabilityAnalyzer()
    if "report_generator" not in st.session_state:
        st.session_state.report_generator = ReportGenerator()
    if "chatbot" not in st.session_state:
        st.session_state.chatbot = SimpleSecurityChatbot()
    if "scan_complete" not in st.session_state:
        st.session_state.scan_complete = False
    if "current_report" not in st.session_state:
        st.session_state.current_report = None
    if "chat_history" not in st.session_state:
        st.session_state.chat_history = []

def display_scan_results(results):
    """Display scan results in a formatted way"""
    if "error" in results:
        st.error(f"❌ {results['error']}")
        if "details" in results:
            st.error(f"Details: {results['details']}")
        return

    # Display summary metrics
    st.subheader("📊 Scan Summary")
    
    # Create columns for metrics
    col1, col2, col3, col4 = st.columns(4)
    
    # Display alert counts
    alert_counts = results.get("alert_counts", {})
    with col1:
        st.metric("High Risk", alert_counts.get("High", 0), delta=None)
    with col2:
        st.metric("Medium Risk", alert_counts.get("Medium", 0), delta=None)
    with col3:
        st.metric("Low Risk", alert_counts.get("Low", 0), delta=None)
    with col4:
        st.metric("Info", alert_counts.get("Info", 0), delta=None)

    # Display scan details
    st.subheader("🔍 Scan Details")
    st.write(f"Target URL: {results.get('target_url', 'N/A')}")
    st.write(f"Scan Time: {results.get('scan_time', 'N/A')}")
    st.write(f"Scan Status: {results.get('scan_status', 'N/A')}")

    # Display vulnerabilities
    if "alerts" in results and results["alerts"]:
        st.subheader("🚨 Vulnerabilities Found")
        
        # Group alerts by risk level
        alerts_by_risk = {
            "High": [],
            "Medium": [],
            "Low": [],
            "Info": []
        }
        
        for alert in results["alerts"]:
            try:
                if isinstance(alert, dict):
                    risk = alert.get("risk", "Info")
                    alerts_by_risk[risk].append(alert)
                else:
                    # If alert is a string, log it and skip
                    logger.warning(f"Received string alert instead of dictionary: {alert}")
                    alerts_by_risk["Info"].append({"name": "Unknown", "description": str(alert), "risk": "Info"})
            except Exception as e:
                logger.error(f"Error processing alert: {e}")
                continue
        
        # Display alerts by risk level
        for risk_level in ["High", "Medium", "Low", "Info"]:
            if alerts_by_risk[risk_level]:
                with st.expander(f"{risk_level} Risk Alerts ({len(alerts_by_risk[risk_level])})"):
                    for alert in alerts_by_risk[risk_level]:
                        if isinstance(alert, dict):
                            st.markdown(f"**{alert.get('name', 'Unknown')}**")
                            st.write(f"Description: {alert.get('description', 'No description available')}")
                            st.write(f"Solution: {alert.get('solution', 'No solution available')}")
                            st.write(f"URL: {alert.get('url', 'N/A')}")
                        else:
                            st.write(f"Alert: {str(alert)}")
                        st.divider()
    else:
        st.success("✅ No vulnerabilities found!")

    # Add download report button
    if "report_path" in results:
        report_path = results["report_path"]
        if os.path.exists(report_path):
            with open(report_path, "rb") as f:
                st.download_button(
                    label="📥 Download Full Report",
                    data=f,
                    file_name=os.path.basename(report_path),
                    mime="text/html"
                )

def display_chatbot():
    """Display the chatbot interface"""
    st.header("💬 Security Assistant")
    
    # Check if chatbot is available
    if st.session_state.chatbot is None:
        st.warning("Chatbot is not available due to API key issues. Please check your configuration.")
        return
    
    # Display chat history
    for message in st.session_state.chat_history:
        with st.chat_message(message["role"]):
            st.write(message["content"])
    
    # Chat input
    if prompt := st.chat_input("Ask about security vulnerabilities..."):
        # Add user message to chat history
        st.session_state.chat_history.append({"role": "user", "content": prompt})
        
        # Display user message
        with st.chat_message("user"):
            st.write(prompt)
        
        # Get chatbot response
        with st.chat_message("assistant"):
            with st.spinner("Thinking..."):
                try:
                    response = st.session_state.chatbot.process_query(prompt)
                    st.write(response)
                    st.session_state.chat_history.append({"role": "assistant", "content": response})
                except Exception as e:
                    st.error(f"Error: {e}")
                    logger.error(f"Chatbot error: {e}", exc_info=True)
    
    # Add buttons for common actions
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Clear Chat"):
            st.session_state.chat_history = []
            st.session_state.chatbot.clear_context()
            st.experimental_rerun()
    
    with col2:
        if st.button("Save Chat"):
            filepath = st.session_state.chatbot.save_conversation()
            if filepath:
                st.success(f"Chat saved to {filepath}")
            else:
                st.error("Failed to save chat")

def display_vulnerability_analyzer():
    """Display the vulnerability analyzer interface."""
    st.subheader("Vulnerability Analyzer")
    
    if not st.session_state.current_report or "alerts" not in st.session_state.current_report:
        st.info("Run a scan first to analyze vulnerabilities")
        return
    
    vulnerabilities = st.session_state.current_report["alerts"]
    
    # Analyze vulnerabilities
    with st.spinner("Analyzing vulnerabilities..."):
        analysis = st.session_state.vulnerability_analyzer.analyze_vulnerabilities(vulnerabilities)
    
    # Display analysis results
    st.markdown("### Vulnerability Analysis")
    
    # Check if analysis was successful
    if "error" in analysis:
        st.error(f"Error analyzing vulnerabilities: {analysis['error']}")
        return
    
    # Risk distribution
    st.subheader("Risk Distribution")
    if "summary" in analysis and "by_risk" in analysis["summary"]:
        risk_data = analysis["summary"]["by_risk"]
        st.bar_chart(risk_data)
    else:
        st.warning("Risk distribution data not available")
    
    # Detailed analysis
    st.subheader("Detailed Analysis")
    if "alerts" in analysis:
        for vuln in analysis["alerts"]:
            with st.expander(f"{vuln['risk']} - {vuln['name']}"):
                st.markdown(f"**Risk Score:** {vuln.get('risk_score', 'N/A')}")
                st.markdown(f"**False Positive Probability:** {vuln.get('false_positive_probability', 'N/A')}")
                st.markdown(f"**Adjusted Risk Score:** {vuln.get('adjusted_risk_score', 'N/A')}")
                
                # Get fix suggestion
                if st.button(f"Get Fix Suggestion", key=f"fix_{vuln['name']}"):
                    with st.spinner("Generating fix suggestion..."):
                        fix = st.session_state.chatbot.get_fix_suggestion(vuln)
                        st.markdown("### Fix Suggestion")
                        st.markdown(fix)
    else:
        # Display vulnerabilities directly from the scan results
        for vuln in vulnerabilities:
            with st.expander(f"{vuln.get('risk', 'Info')} - {vuln.get('name', 'Unknown')}"):
                st.markdown(f"**Description:** {vuln.get('description', 'No description available')}")
                st.markdown(f"**Solution:** {vuln.get('solution', 'No solution available')}")
                st.markdown(f"**URL:** {vuln.get('url', 'N/A')}")
                
                # Get fix suggestion
                if st.button(f"Get Fix Suggestion", key=f"fix_{vuln.get('name', 'Unknown')}"):
                    with st.spinner("Generating fix suggestion..."):
                        fix = st.session_state.chatbot.get_fix_suggestion(vuln)
                        st.markdown("### Fix Suggestion")
                        st.markdown(fix)
    
    # Display recommendations if available
    if "recommendations" in analysis:
        st.subheader("Recommendations")
        for i, rec in enumerate(analysis["recommendations"], 1):
            st.markdown(f"{i}. {rec}")

def create_risk_trend_chart(historical_data):
    """Create an interactive risk trend chart."""
    df = pd.DataFrame(historical_data)
    
    fig = px.line(df, x='timestamp', y=['high_risk', 'medium_risk', 'low_risk'],
                  title='Vulnerability Risk Trends',
                  template=DASHBOARD_CONFIG['chart_theme'])
    
    fig.update_layout(
        xaxis_title="Time",
        yaxis_title="Number of Vulnerabilities",
        hovermode='x unified'
    )
    
    return fig

def create_vulnerability_heatmap(vulnerabilities):
    """Create a heatmap of vulnerability locations."""
    df = pd.DataFrame(vulnerabilities)
    
    fig = px.density_heatmap(
        df,
        x='endpoint',
        y='risk_level',
        z='count',
        title='Vulnerability Distribution Heatmap',
        template=DASHBOARD_CONFIG['chart_theme']
    )
    
    return fig

def display_enhanced_dashboard():
    """Display the enhanced security dashboard."""
    st.header("📊 Security Dashboard")
    
    # Create columns for key metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            "Critical Vulnerabilities",
            len([v for v in st.session_state.current_report.get('alerts', [])
                 if v.get('risk') == 'High']),
            delta="-2"
        )
    
    with col2:
        st.metric(
            "False Positive Rate",
            f"{calculate_false_positive_rate():.1f}%",
            delta="-1.2%"
        )
    
    with col3:
        st.metric(
            "Average Fix Time",
            "2.5 days",
            delta="-0.5 days"
        )
    
    with col4:
        st.metric(
            "Security Score",
            calculate_security_score(),
            delta="+5"
        )
    
    # Display trend charts
    col1, col2 = st.columns(2)
    
    with col1:
        st.plotly_chart(
            create_risk_trend_chart(get_historical_data()),
            use_container_width=True
        )
    
    with col2:
        st.plotly_chart(
            create_vulnerability_heatmap(get_current_vulnerabilities()),
            use_container_width=True
        )
    
    # Display patch status
    with st.expander("🔧 Patch Status"):
        display_patch_status()

def calculate_false_positive_rate():
    """Calculate the false positive rate from current report."""
    if not st.session_state.current_report or "alerts" not in st.session_state.current_report:
        return 0.0
    
    alerts = st.session_state.current_report["alerts"]
    if not alerts:
        return 0.0
    
    # This is a placeholder implementation
    # In a real implementation, you would use ML to predict false positives
    return 15.0

def calculate_security_score():
    """Calculate a security score based on vulnerabilities."""
    if not st.session_state.current_report or "alerts" not in st.session_state.current_report:
        return 0
    
    alerts = st.session_state.current_report["alerts"]
    if not alerts:
        return 100
    
    # Simple scoring algorithm
    high_count = sum(1 for a in alerts if a.get('risk') == 'High')
    medium_count = sum(1 for a in alerts if a.get('risk') == 'Medium')
    low_count = sum(1 for a in alerts if a.get('risk') == 'Low')
    
    # Weighted scoring
    score = 100 - (high_count * 10 + medium_count * 5 + low_count * 2)
    return max(0, min(100, score))

def get_historical_data():
    """Get historical vulnerability data for trend chart."""
    # This is a placeholder implementation
    # In a real implementation, you would load historical data from a database
    return [
        {'timestamp': '2023-01-01', 'high_risk': 5, 'medium_risk': 8, 'low_risk': 12},
        {'timestamp': '2023-02-01', 'high_risk': 4, 'medium_risk': 7, 'low_risk': 10},
        {'timestamp': '2023-03-01', 'high_risk': 3, 'medium_risk': 6, 'low_risk': 9},
        {'timestamp': '2023-04-01', 'high_risk': 2, 'medium_risk': 5, 'low_risk': 8},
    ]

def get_current_vulnerabilities():
    """Get current vulnerability data for heatmap."""
    if not st.session_state.current_report or "alerts" not in st.session_state.current_report:
        return []
    
    alerts = st.session_state.current_report["alerts"]
    if not alerts:
        return []
    
    # Group by endpoint and risk level
    vuln_data = {}
    for alert in alerts:
        endpoint = alert.get('url', 'unknown')
        risk_level = alert.get('risk', 'Info')
        
        key = (endpoint, risk_level)
        if key not in vuln_data:
            vuln_data[key] = 0
        vuln_data[key] += 1
    
    # Convert to list for DataFrame
    result = []
    for (endpoint, risk_level), count in vuln_data.items():
        result.append({
            'endpoint': endpoint,
            'risk_level': risk_level,
            'count': count
        })
    
    return result

def display_patch_status():
    """Display the status of vulnerability patches."""
    if not st.session_state.current_report or "alerts" not in st.session_state.current_report:
        st.info("Run a scan first to see patch status")
        return
    
    alerts = st.session_state.current_report["alerts"]
    if not alerts:
        st.success("No vulnerabilities to patch")
        return
    
    # Group by risk level
    by_risk = {
        'High': [],
        'Medium': [],
        'Low': [],
        'Info': []
    }
    
    for alert in alerts:
        risk = alert.get('risk', 'Info')
        by_risk[risk].append(alert)
    
    # Display patch status by risk level
    for risk_level in ['High', 'Medium', 'Low', 'Info']:
        if by_risk[risk_level]:
            with st.expander(f"{risk_level} Risk Vulnerabilities ({len(by_risk[risk_level])})"):
                for alert in by_risk[risk_level]:
                    st.markdown(f"**{alert.get('name', 'Unknown')}**")
                    st.write(f"URL: {alert.get('url', 'N/A')}")
                    
                    # Add patch status (placeholder)
                    status = "Pending"
                    if risk_level == 'High':
                        status = "In Progress"
                    elif risk_level == 'Info':
                        status = "Scheduled"
                    
                    st.write(f"Patch Status: {status}")
                    st.divider()

def main():
    """Main function to run the Streamlit app"""
    st.set_page_config(
        page_title="Security Scanner",
        layout="wide"
    )
    
    # Initialize session state
    initialize_session_state()
    
    # App title and description
    st.title("🔒 Security Scanner")
    st.markdown("""
    This application allows you to scan web applications for security vulnerabilities using OWASP ZAP.
    """)
    
    # Sidebar for configuration
    with st.sidebar:
        st.title("🔒 Security Scanner")
        target_url = st.text_input("Target URL", "http://testphp.vulnweb.com")
        scan_type = st.selectbox("Scan Type", list(SCAN_TYPES.keys()), format_func=lambda x: SCAN_TYPES[x]["name"])
        
        if st.button("Start Scan"):
            with st.spinner("Running scan..."):
                results = run_scan(target_url, scan_type)
                st.session_state.scan_results = results
                st.session_state.current_report = results
                st.session_state.scan_complete = True
    
    # Main content area
    tab1, tab2, tab3 = st.tabs(["Scanner", "Vulnerability Analyzer", "Security Assistant"])
    
    with tab1:
        if 'scan_results' in st.session_state:
            display_scan_results(st.session_state.scan_results)
    
    with tab2:
        display_vulnerability_analyzer()
    
    with tab3:
        display_chatbot()

def run_scan(url, scan_type="quick"):
    """Run a security scan using the scan manager."""
    try:
        logger.info(f"Starting {scan_type} scan for {url}")
        results = st.session_state.scan_manager.start_scan(url, scan_type)
        return results
    except Exception as e:
        logger.error(f"Error running scan: {e}", exc_info=True)
        return {
            "error": "Scan failed",
            "details": str(e)
        }

if __name__ == "__main__":
    main() 