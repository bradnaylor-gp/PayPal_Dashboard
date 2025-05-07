import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import numpy as np
from datetime import datetime, timedelta
import json
from PIL import Image
import io
import base64
import random

# Set page configuration
st.set_page_config(
    page_title="PayPal ASM Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for sleek appearance
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: 700;
        color: #003087;  /* PayPal blue */
        margin-bottom: 1rem;
    }
    .sub-header {
        font-size: 1.5rem;
        font-weight: 600;
        color: #0070BA;  /* PayPal lighter blue */
        margin-bottom: 0.5rem;
    }
    .card {
        border-radius: 5px;
        padding: 1.5rem;
        background-color: white;
        box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        margin-bottom: 1rem;
    }
    .metric-card {
        text-align: center;
        padding: 1rem;
        border-radius: 5px;
        background-color: white;
        box-shadow: 0 2px 5px rgba(0,0,0,0.1);
    }
    .metric-value {
        font-size: 2rem;
        font-weight: 700;
        color: #000;  /* Ensure dark text on light background */
    }
    .metric-label {
        font-size: 0.9rem;
        color: #333;  /* Darker gray for better contrast */
    }
    .critical {
        color: #d32f2f;
        font-weight: 600;
    }
    .high {
        color: #e65100;  /* Darker orange for better contrast */
        font-weight: 600;
    }
    .medium {
        color: #b3a000;  /* Darker yellow for better contrast */
        font-weight: 600;
    }
    .low {
        color: #2e7d32;  /* Slightly darker green */
        font-weight: 600;
    }
    .highlight {
        background-color: #ffffff;
        padding: 1.5rem;
        border: 1px solid #e0e0e0;
        border-left: 4px solid #0070BA;
        margin-bottom: 1rem;
        box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        color: #333;
        border-radius: 4px;
    }
    .highlight strong {
        color: #0070BA;
        font-weight: 600;
    }
    .stButton button {
        background-color: #0070BA;
        color: white;
    }
    /* Custom table styling */
    .dataframe {
        width: 100%;
        border-collapse: collapse;
    }
    .dataframe th {
        background-color: #f1f1f1;
        padding: 8px;
    }
    .dataframe td {
        padding: 8px;
        border-bottom: 1px solid #f1f1f1;
    }
    /* Fix for plotly hover */
    .js-plotly-plot .plotly .modebar {
        right: 50px !important;
    }
    /* Tab styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 2px;
    }
    .stTabs [data-baseweb="tab"] {
        height: 50px;
        white-space: pre-wrap;
        background-color: #f8f9fa;
        border-radius: 4px 4px 0 0;
        gap: 1px;
        padding-top: 10px;
        padding-bottom: 10px;
    }
    .stTabs [aria-selected="true"] {
        background-color: #0070BA;
        color: white;
    }
</style>
""", unsafe_allow_html=True)

# Generate sample ASM data
@st.cache_data
def load_sample_data():
    # Generate dates for the last 30 days
    end_date = datetime.now()
    start_date = end_date - timedelta(days=30)
    dates = pd.date_range(start=start_date, end=end_date, freq='D')
    
    # Severity distributions
    severities = ['Critical', 'High', 'Medium', 'Low']
    severity_weights = [0.1, 0.25, 0.4, 0.25]
    
    # Finding types
    finding_types = ['Vulnerability', 'Misconfiguration', 'Exposure', 'Certificate Issue', 'Open Port']
    
    # Generate random findings
    num_findings = 250
    findings = []
    
    domains = [
        "api.paypal.com", "checkout.paypal.com", "www.paypal.com", 
        "developer.paypal.com", "auth.paypal.com", "app.paypal.com",
        "mobile.paypal.com", "business.paypal.com", "status.paypal.com",
        "venmo.paypal.com", "investor.paypal.com", "security.paypal.com"
    ]
    
    tech_stacks = [
        ["Angular.js 1.5.6", "nginx 1.18.0", "Ubuntu 20.04"],
        ["React 17", "Apache 2.4", "Amazon Linux 2"],
        ["Vue.js 2.6", "nginx 1.20.0", "Debian 10"],
        ["jQuery 3.4.1", "IIS 10", "Windows Server 2019"],
        ["Angular 12", "Tomcat 9", "Red Hat 8"],
        ["React 16", "Node.js 14", "Ubuntu 18.04"]
    ]
    
    # Generate Angular.js findings specifically
    angular_domains = np.random.choice(domains, size=12, replace=True)
    
    for i in range(num_findings):
        # Basic finding info
        finding_id = f"ASM-2023-{10000 + i}"
        
        # Force some Angular.js findings
        if i < 12:
            domain = angular_domains[i]
            tech_stack = ["Angular.js 1.5.6", "nginx 1.18.0", "Ubuntu 20.04"]
            finding_type = "Vulnerability"
            severity = np.random.choice(["Critical", "High"], p=[0.3, 0.7])
        else:
            severity = np.random.choice(severities, p=severity_weights)
            finding_type = np.random.choice(finding_types)
            domain = np.random.choice(domains)
            tech_stack = random.choice(tech_stacks)
            
        discovery_date = pd.Timestamp(np.random.choice(dates))
        
        # Validation status
        if i % 10 < 7:  # 70% validated
            validated = True
            if i % 10 < 6:  # 60% true positive (out of all findings)
                validation_result = "True Positive"
            else:  # 10% false positive (out of all findings)
                validation_result = "False Positive"
        else:  # 30% pending validation
            validated = False
            validation_result = "Pending"
        
        # Remediation status
        if validation_result == "True Positive":
            if i % 5 == 0:
                remediation_status = "Remediated"
                remediation_date = discovery_date + timedelta(days=np.random.randint(1, 14))
            elif i % 5 == 1:
                remediation_status = "In Progress"
                remediation_date = None
            else:
                remediation_status = "Open"
                remediation_date = None
        else:
            remediation_status = "Not Required"
            remediation_date = None
            
        # Ownership
        if i % 20 == 0:  # 5% unknown ownership
            owner = "Unknown"
        else:
            owner = np.random.choice(["Payments Team", "Authentication Team", "API Team", 
                                     "Frontend Team", "Mobile Team", "Infrastructure Team"])
        
        # Enrichment data
        has_screenshot = np.random.choice([True, False], p=[0.8, 0.2])
        has_certificate = "certificate" in domain or np.random.choice([True, False], p=[0.7, 0.3])
        
        # CVE details for vulnerabilities
        cve = None
        if finding_type == "Vulnerability":
            cve = f"CVE-2023-{np.random.randint(1000, 9999)}"
            
        # For Angular.js, use a specific CVE
        if "Angular.js 1.5.6" in tech_stack:
            cve = "CVE-2022-25869"
        
        findings.append({
            "finding_id": finding_id,
            "severity": severity,
            "type": finding_type,
            "domain": domain,
            "discovery_date": discovery_date,
            "validated": validated,
            "validation_result": validation_result,
            "remediation_status": remediation_status,
            "remediation_date": remediation_date,
            "owner": owner,
            "tech_stack": tech_stack,
            "has_screenshot": has_screenshot,
            "has_certificate": has_certificate,
            "cve": cve
        })
    
    df = pd.DataFrame(findings)
    return df

# Display overview page
def display_overview(df):
    st.markdown('<div class="main-header">ASM Dashboard Overview</div>', unsafe_allow_html=True)
    
    # Key metrics row
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{len(df)}</div>
            <div class="metric-label">Total Findings</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        critical_high = len(df[df['severity'].isin(['Critical', 'High'])])
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value high">{critical_high}</div>
            <div class="metric-label">Critical & High</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        validated = len(df[df['validated'] == True])
        validation_percent = int((validated / len(df)) * 100) if len(df) > 0 else 0
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{validation_percent}%</div>
            <div class="metric-label">Validation Complete</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        remediated = len(df[df['remediation_status'] == 'Remediated'])
        true_positives = len(df[df['validation_result'] == 'True Positive'])
        remediation_percent = int((remediated / true_positives) * 100) if true_positives > 0 else 0
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{remediation_percent}%</div>
            <div class="metric-label">Remediation Complete</div>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Two charts row
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown('<div class="sub-header">Findings by Severity</div>', unsafe_allow_html=True)
        severity_counts = df['severity'].value_counts().reset_index()
        severity_counts.columns = ['Severity', 'Count']
        
        # Define colors for each severity
        colors = {'Critical': '#d32f2f', 'High': '#e65100', 'Medium': '#b3a000', 'Low': '#2e7d32'}
        
        fig = px.pie(severity_counts, values='Count', names='Severity', 
                    color='Severity', color_discrete_map=colors,
                    hole=0.4)
        fig.update_layout(margin=dict(t=0, b=0, l=0, r=0))
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.markdown('<div class="sub-header">Findings Over Time</div>', unsafe_allow_html=True)
        df['date'] = pd.to_datetime(df['discovery_date']).dt.date
        time_series = df.groupby(['date', 'severity']).size().reset_index(name='count')
        
        fig = px.line(time_series, x='date', y='count', color='severity',
                     color_discrete_map=colors)
        fig.update_layout(margin=dict(t=0, b=0, l=0, r=0), 
                         xaxis_title="Date",
                         yaxis_title="Number of Findings")
        st.plotly_chart(fig, use_container_width=True)
    
    # Angular.js highlight
    st.markdown('<div class="sub-header">Key Insights</div>', unsafe_allow_html=True)
    
    angular_findings = df[df['tech_stack'].apply(lambda x: "Angular.js 1.5.6" in x)]
    
    st.markdown(f"""
    <div class="highlight">
        <strong>Angular.js Detection:</strong> Our enrichment process has identified {len(angular_findings)} instances of Angular.js 1.5.6 
        across multiple domains, despite a previous remediation campaign. These instances have been validated and 
        tickets created for the appropriate teams.
    </div>
    """, unsafe_allow_html=True)
    
    # Recent findings table
    st.markdown('<div class="sub-header">Recent Critical & High Findings</div>', unsafe_allow_html=True)
    recent_high = df[df['severity'].isin(['Critical', 'High'])].sort_values('discovery_date', ascending=False).head(5)
    
    if not recent_high.empty:
        display_cols = ['finding_id', 'severity', 'type', 'domain', 'discovery_date', 'validation_result']
        st.dataframe(recent_high[display_cols], use_container_width=True)
    else:
        st.info("No critical or high findings in the selected date range.")

# Display asset inventory page
def display_asset_inventory(df):
    st.markdown('<div class="main-header">Asset Inventory</div>', unsafe_allow_html=True)
    
    # Asset statistics
    domains = df['domain'].nunique()
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{domains}</div>
            <div class="metric-label">Unique Domains</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        # Count unique tech stack items
        tech_stack_items = set()
        for stack in df['tech_stack']:
            for item in stack:
                tech_stack_items.add(item)
                
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{len(tech_stack_items)}</div>
            <div class="metric-label">Unique Technologies</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        owners = df['owner'].nunique()
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{owners}</div>
            <div class="metric-label">Asset Owners</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    
    # Domain findings table with sorting
    st.markdown('<div class="sub-header">Domain Inventory</div>', unsafe_allow_html=True)
    
    # Group by domain and count findings
    domain_stats = df.groupby('domain').agg(
        total_findings=('finding_id', 'count'),
        critical=('severity', lambda x: sum(x == 'Critical')),
        high=('severity', lambda x: sum(x == 'High')),
        validated=('validated', lambda x: sum(x)),
        technologies=('tech_stack', lambda x: set([item for sublist in x for item in sublist]))
    ).reset_index()
    
    domain_stats['technologies'] = domain_stats['technologies'].apply(lambda x: ', '.join(list(x)[:3]) + ('...' if len(x) > 3 else ''))
    
    st.dataframe(domain_stats, use_container_width=True)
    
    # Technologies visualization
    st.markdown('<div class="sub-header">Technology Distribution</div>', unsafe_allow_html=True)
    
    # Extract all technologies
    all_techs = []
    for stack in df['tech_stack']:
        all_techs.extend(stack)
    
    tech_counts = pd.Series(all_techs).value_counts().reset_index()
    tech_counts.columns = ['Technology', 'Count']
    tech_counts = tech_counts.sort_values('Count', ascending=False).head(10)
    
    fig = px.bar(tech_counts, x='Technology', y='Count', 
                color='Count', color_continuous_scale='Blues',
                text='Count')
    fig.update_layout(xaxis_title="", yaxis_title="")
    st.plotly_chart(fig, use_container_width=True)

# Display findings explorer page
def display_findings_explorer(df):
    st.markdown('<div class="main-header">Findings Explorer</div>', unsafe_allow_html=True)
    
    # Filters in columns
    col1, col2, col3 = st.columns(3)
    
    with col1:
        selected_severity = st.multiselect('Severity', options=sorted(df['severity'].unique()), default=sorted(df['severity'].unique()))
    
    with col2:
        selected_types = st.multiselect('Finding Type', options=sorted(df['type'].unique()), default=sorted(df['type'].unique()))
    
    with col3:
        selected_validation = st.multiselect('Validation Status', options=sorted(df['validation_result'].unique()), default=sorted(df['validation_result'].unique()))
    
    # Apply filters
    filtered_df = df[
        df['severity'].isin(selected_severity) & 
        df['type'].isin(selected_types) & 
        df['validation_result'].isin(selected_validation)
    ]
    
    # Display count
    st.markdown(f"<div style='text-align: right; color: #666;'>{len(filtered_df)} findings</div>", unsafe_allow_html=True)
    
    # Search box
    search = st.text_input("Search by domain or finding ID")
    if search:
        filtered_df = filtered_df[
            filtered_df['domain'].str.contains(search, case=False) | 
            filtered_df['finding_id'].str.contains(search, case=False)
        ]
    
    # Display findings table
    if not filtered_df.empty:
        # Prepare display columns
        display_df = filtered_df[[
            'finding_id', 'severity', 'type', 'domain', 
            'discovery_date', 'validation_result', 'remediation_status'
        ]].copy()
        
        # Add color coding to severity
        def color_severity(val):
            colors = {'Critical': '#ffcdd2', 'High': '#ffe0b2', 'Medium': '#fff9c4', 'Low': '#c8e6c9'}
            return f'background-color: {colors.get(val, "")}'
        
        # Display styled dataframe
        st.dataframe(
            display_df.style.applymap(color_severity, subset=['severity']),
            use_container_width=True
        )
        
        # Finding details expander
        with st.expander("Select Finding for Details"):
            selected_finding = st.selectbox("Choose Finding ID", options=filtered_df['finding_id'].tolist())
            
            if selected_finding:
                finding = filtered_df[filtered_df['finding_id'] == selected_finding].iloc[0]
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown("### Finding Details")
                    st.markdown(f"**ID:** {finding['finding_id']}")
                    st.markdown(f"**Severity:** {finding['severity']}")
                    st.markdown(f"**Type:** {finding['type']}")
                    st.markdown(f"**Domain:** {finding['domain']}")
                    st.markdown(f"**Discovered:** {finding['discovery_date'].strftime('%b %d, %Y')}")
                    if finding['cve']:
                        st.markdown(f"**CVE:** {finding['cve']}")
                
                with col2:
                    st.markdown("### Status")
                    st.markdown(f"**Validation:** {finding['validation_result']}")
                    st.markdown(f"**Remediation:** {finding['remediation_status']}")
                    st.markdown(f"**Owner:** {finding['owner']}")
                    if finding['remediation_date'] is not None:
                        st.markdown(f"**Remediated on:** {finding['remediation_date'].strftime('%Y-%m-%d')}")
                
                st.markdown("### Technology Stack")
                st.write(", ".join(finding['tech_stack']))
                
                # Mock screenshot
                if finding['has_screenshot']:
                    st.markdown("### Screenshot")
                    # Generate a colored rectangle as a mock screenshot
                    import matplotlib.pyplot as plt
                    fig, ax = plt.subplots(figsize=(10, 5))
                    ax.text(0.5, 0.5, f"Screenshot of {finding['domain']}", 
                            horizontalalignment='center', verticalalignment='center', fontsize=14)
                    ax.axis('off')
                    st.pyplot(fig)
    else:
        st.info("No findings match the selected filters.")

# Display enrichment details page
def display_enrichment_details(df):
    st.markdown('<div class="main-header">Enrichment Details</div>', unsafe_allow_html=True)
    
    # Angular.js case study
    st.markdown('<div class="sub-header">Case Study: Angular.js Detection</div>', unsafe_allow_html=True)
    
    col1, col2 = st.columns([1, 2])
    
    with col1:
        st.markdown("""
        ### Enrichment Process
        
        1. **Data Export**
           - Exported from Expanse
           - Combined alerts & websites views
        
        2. **Technology Detection**
           - Used Wappalyzer for identification
           - Confirmed with screenshot analysis
        
        3. **Vulnerability Context**
           - Checked CVE details
           - Verified exploitability
        
        4. **Usage Assessment**
           - Determined if actively used
           - Checked if primary or auxiliary
        """)
    
    with col2:
        angular_findings = df[df['tech_stack'].apply(lambda x: "Angular.js 1.5.6" in x)]
        
        # Create a bar chart of Angular.js instances by domain
        domain_counts = angular_findings['domain'].value_counts().reset_index()
        domain_counts.columns = ['Domain', 'Count']
        
        fig = px.bar(domain_counts, x='Domain', y='Count',
                    title="Angular.js 1.5.6 Instances by Domain",
                    color_discrete_sequence=['#0070BA'])
        fig.update_layout(xaxis_title="", yaxis_title="")
        st.plotly_chart(fig, use_container_width=True)
    
    # Enrichment tools
    st.markdown('<div class="sub-header">Enrichment Tools</div>', unsafe_allow_html=True)
    
    tools = [
        {
            "name": "GoWitness",
            "purpose": "Screenshot Automation",
            "command": "gowitness single https://example.paypal.com",
            "output": "Screenshots of web interfaces"
        },
        {
            "name": "Wappalyzer",
            "purpose": "Technology Stack Detection",
            "command": "npx wappalyzer https://example.paypal.com --pretty",
            "output": "List of technologies in use"
        },
        {
            "name": "OpenSSL",
            "purpose": "Certificate Analysis",
            "command": "openssl s_client -connect example.paypal.com:443 -showcerts </dev/null",
            "output": "Certificate details and chain"
        },
        {
            "name": "DNS Tools",
            "purpose": "DNS Record Collection",
            "command": "dig +nocmd example.paypal.com any +multiline +noall +answer",
            "output": "DNS records for the domain"
        }
    ]
    
    tool_df = pd.DataFrame(tools)
    st.dataframe(tool_df, use_container_width=True)
    
    # Sample enrichment output
    st.markdown('<div class="sub-header">Sample Enrichment Output</div>', unsafe_allow_html=True)
    
    with st.expander("Wappalyzer Output for api.paypal.com"):
        st.code("""
{
  "urls": {
    "https://api.paypal.com/": {
      "status": 200
    }
  },
  "technologies": [
    {
      "slug": "angular",
      "name": "Angular.js",
      "confidence": 100,
      "version": "1.5.6",
      "icon": "Angular.svg",
      "website": "https://angular.io",
      "cpe": "cpe:/a:google:angularjs:1.5.6",
      "categories": [
        {
          "id": 12,
          "slug": "javascript-frameworks",
          "name": "JavaScript frameworks"
        }
      ]
    },
    {
      "slug": "nginx",
      "name": "Nginx",
      "confidence": 100,
      "version": "1.18.0",
      "icon": "Nginx.svg",
      "website": "https://nginx.org/en",
      "cpe": "cpe:/a:nginx:nginx:1.18.0",
      "categories": [
        {
          "id": 22,
          "slug": "web-servers",
          "name": "Web servers"
        }
      ]
    }
  ]
}
        """)

# Display validation results page
def display_validation_results(df):
    st.markdown('<div class="main-header">Validation Results</div>', unsafe_allow_html=True)
    
    # Validation statistics
    col1, col2, col3 = st.columns(3)
    
    with col1:
        validated_count = len(df[df['validated'] == True])
        validation_percent = int((validated_count / len(df)) * 100) if len(df) > 0 else 0
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{validation_percent}%</div>
            <div class="metric-label">Findings Validated</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        true_positives = len(df[df['validation_result'] == 'True Positive'])
        true_positive_percent = int((true_positives / validated_count) * 100) if validated_count > 0 else 0
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{true_positive_percent}%</div>
            <div class="metric-label">True Positive Rate</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        pending = len(df[df['validation_result'] == 'Pending'])
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{pending}</div>
            <div class="metric-label">Pending Validation</div>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Validation results chart
    st.markdown('<div class="sub-header">Validation Results by Severity</div>', unsafe_allow_html=True)
    
    # Create a dataframe for the chart
    validation_by_severity = df.groupby(['severity', 'validation_result']).size().reset_index(name='count')
    
    fig = px.bar(validation_by_severity, x='severity', y='count', color='validation_result',
                barmode='group',
                color_discrete_map={
                    'True Positive': '#4caf50',
                    'False Positive': '#f44336',
                    'Pending': '#9e9e9e'
                })
    fig.update_layout(
        xaxis_title="Severity",
        yaxis_title="Count",
        legend_title="Validation Result"
    )
    st.plotly_chart(fig, use_container_width=True)
    
    # Validation methods
    st.markdown('<div class="sub-header">Validation Methods</div>', unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        ### Automated Validation
        
        **Nuclei Templates:**
        - CVE-specific templates
        - Misconfigurations
        - Technology-specific checks
        - Subdomain takeover validation
        
        **Example Command:**
        ```bash
        nuclei -u https://example.paypal.com -t cves/2022/CVE-2022-25869.yaml
        ```
        """)
    
    with col2:
        st.markdown("""
        ### Manual Validation
        
        **Process:**
        1. Review enrichment data
        2. Analyze context and usage
        3. Determine if exploitable
        4. Document evidence
        
        **Decision Criteria:**
        - Is the vulnerability exploitable?
        - Is the component actively used?
        - What is the actual exposure?
        """)
    
    # Sample validation case
    st.markdown('<div class="sub-header">Validation Case Study: Azure Subdomain Takeover</div>', unsafe_allow_html=True)
    
    st.markdown("""
    <div class="highlight">
        <strong>Finding:</strong> Potential Azure subdomain takeover vulnerability in status.paypal.com
        
        <strong>Validation Process:</strong>
        1. Exported finding details from Expanse
        2. Collected DNS records showing CNAME pointing to Azure service
        3. Ran Nuclei subdomain takeover template
        4. Template confirmed the subdomain was vulnerable
        5. Screenshot captured showing takeover possibility
        
        <strong>Result:</strong> True Positive - Immediately ticketed for remediation
    </div>
    """, unsafe_allow_html=True)

# Display remediation tracking page
def display_remediation_tracking(df):
    st.markdown('<div class="main-header">Remediation Tracking</div>', unsafe_allow_html=True)
    
    # Filter to only include true positives
    remediation_df = df[df['validation_result'] == 'True Positive']
    
    # Remediation statistics
    col1, col2, col3 = st.columns(3)
    
    with col1:
        total_to_fix = len(remediation_df)
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{total_to_fix}</div>
            <div class="metric-label">Total Issues to Fix</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        fixed = len(remediation_df[remediation_df['remediation_status'] == 'Remediated'])
        fixed_percent = int((fixed / total_to_fix) * 100) if total_to_fix > 0 else 0
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{fixed_percent}%</div>
            <div class="metric-label">Issues Fixed</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        in_progress = len(remediation_df[remediation_df['remediation_status'] == 'In Progress'])
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{in_progress}</div>
            <div class="metric-label">In Progress</div>
        </div>
        """, unsafe_allow_html=True)
    
    # Remediation status chart
    st.markdown('<div class="sub-header">Remediation Status by Severity</div>', unsafe_allow_html=True)
    
    status_by_severity = remediation_df.groupby(['severity', 'remediation_status']).size().reset_index(name='count')
    
    fig = px.bar(status_by_severity, x='severity', y='count', color='remediation_status',
                barmode='group',
                color_discrete_map={
                    'Remediated': '#4caf50',
                    'In Progress': '#2196f3',
                    'Open': '#f44336'
                })
    fig.update_layout(
        xaxis_title="Severity",
        yaxis_title="Count",
        legend_title="Status"
    )
    st.plotly_chart(fig, use_container_width=True)
    
    # Remediation tracking table
    st.markdown('<div class="sub-header">Open Issues</div>', unsafe_allow_html=True)
    
    open_issues = remediation_df[remediation_df['remediation_status'] != 'Remediated'].sort_values('severity')
    
    if not open_issues.empty:
        display_cols = ['finding_id', 'severity', 'type', 'domain', 'owner', 'remediation_status']
        st.dataframe(open_issues[display_cols], use_container_width=True)
    else:
        st.success("No open issues! All validated findings have been remediated.")

# Main function to run the app
def main():
    # Sidebar navigation
    st.sidebar.image("https://upload.wikimedia.org/wikipedia/commons/thumb/b/b5/PayPal.svg/1200px-PayPal.svg.png", width=200)
    st.sidebar.title("Navigation")
    page = st.sidebar.radio("", ["Overview", "Asset Inventory", "Findings Explorer", 
                                "Enrichment Details", "Validation Results", "Remediation Tracking"])
    
    st.sidebar.markdown("---")
    st.sidebar.markdown("### Filters")
    
    # Global filters
    severity_filter = st.sidebar.multiselect("Severity", ["Critical", "High", "Medium", "Low"], default=["Critical", "High"])
    date_range = st.sidebar.date_input("Date Range", [datetime.now() - timedelta(days=30), datetime.now()])
    
    # Load data
    df = load_sample_data()
    
    # Apply filters
    filtered_df = df[df['severity'].isin(severity_filter)]
    filtered_df = filtered_df[(filtered_df['discovery_date'] >= pd.Timestamp(date_range[0])) & 
                             (filtered_df['discovery_date'] <= pd.Timestamp(date_range[1]))]
    
    # Display the selected page
    if page == "Overview":
        display_overview(filtered_df)
    elif page == "Asset Inventory":
        display_asset_inventory(filtered_df)
    elif page == "Findings Explorer":
        display_findings_explorer(filtered_df)
    elif page == "Enrichment Details":
        display_enrichment_details(filtered_df)
    elif page == "Validation Results":
        display_validation_results(filtered_df)
    elif page == "Remediation Tracking":
        display_remediation_tracking(filtered_df)
    
    # Footer
    st.markdown("---")
    st.markdown("*This is a proof-of-concept dashboard for PayPal ASM implementation strategy*")

if __name__ == "__main__":
    main()
