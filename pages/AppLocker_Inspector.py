import streamlit as st
import xml.etree.ElementTree as ET
import pandas as pd
import re
from datetime import datetime
from collections import defaultdict
import io

def parse_applocker_xml(xml_content):
    """Parse AppLocker XML and extract policy information"""
    try:
        root = ET.fromstring(xml_content)
        return root
    except ET.ParseError as e:
        st.error(f"Invalid XML format: {e}")
        return None

def assess_collection_risk(rule_collections):
    """Assess risk for collection enforcement modes"""
    findings = []
    
    for collection in rule_collections:
        collection_type = collection.get('Type', 'Unknown')
        enforcement_mode = collection.get('EnforcementMode', 'NotConfigured')
        
        if enforcement_mode == 'NotConfigured':
            findings.append({
                'Severity': 'High',
                'Collection': collection_type,
                'RuleType': '(collection)',
                'Action': 'n/a',
                'Principal': 'n/a',
                'RuleName': 'n/a',
                'ConditionType': 'n/a',
                'Condition': 'n/a',
                'Reason': f"Collection '{collection_type}' is NotConfigured → default-allow for this type.",
                'Recommendation': f"Set EnforcementMode=Enabled for {collection_type} (or AuditOnly during pilot)."
            })
        elif enforcement_mode == 'AuditOnly':
            findings.append({
                'Severity': 'Medium',
                'Collection': collection_type,
                'RuleType': '(collection)',
                'Action': 'n/a',
                'Principal': 'n/a',
                'RuleName': 'n/a',
                'ConditionType': 'n/a',
                'Condition': 'n/a',
                'Reason': f"Collection '{collection_type}' is in AuditOnly mode → not enforcing blocks.",
                'Recommendation': f"Consider setting EnforcementMode=Enabled for {collection_type} after testing."
            })
    
    return findings

def is_broad_principal(principal):
    """Check if a principal is considered broad/risky"""
    broad_principals = [
        'Everyone',
        'Authenticated Users', 
        'BUILTIN\\Users',
        'Users',
        'Domain Users',
        'S-1-1-0',  # Everyone SID
        'S-1-5-11', # Authenticated Users SID
        'S-1-5-32-545'  # Users SID
    ]
    
    return any(bp.lower() in principal.lower() for bp in broad_principals)

def is_user_writable_path(path):
    """Check if a path is typically user-writable"""
    user_writable_patterns = [
        r'\\users\\.*\\appdata\\',
        r'\\users\\.*\\temp\\',
        r'\\users\\.*\\downloads\\',
        r'\\users\\.*\\documents\\',
        r'\\temp\\',
        r'\\windows\\temp\\',
        r'^[a-z]:\\$',  # Drive roots
        r'^[a-z]:\\\\$',  # Drive roots with backslash
        r'\\\\.*\\.*\\.*',  # UNC paths (potentially writable)
    ]
    
    return any(re.search(pattern, path.lower()) for pattern in user_writable_patterns)

def is_protected_path(path):
    """Check if a path is in a protected/read-only location"""
    protected_patterns = [
        r'\\program files\\',
        r'\\program files \(x86\)\\',
        r'\\windows\\(?!temp)',  # Windows folder but not temp
        r'\\windows\\system32\\',
        r'\\windows\\syswow64\\',
    ]
    
    return any(re.search(pattern, path.lower()) for pattern in protected_patterns)

def has_dangerous_wildcards(path):
    """Check for dangerous wildcard patterns"""
    dangerous_patterns = [
        r'\*\.exe$',
        r'\*\.dll$', 
        r'\*\.ps1$',
        r'\*\.bat$',
        r'\*\.cmd$',
        r'\\\*\\',  # Wildcard in directory path
    ]
    
    return any(re.search(pattern, path.lower()) for pattern in dangerous_patterns)

def assess_path_rule_risk(rule, collection_type):
    """Assess risk for file path rules"""
    findings = []
    
    rule_name = rule.get('Name', 'Unnamed Rule')
    action = rule.get('Action', 'Unknown')
    user_or_group = rule.find('UserOrGroupSid')
    principal = user_or_group.text if user_or_group is not None else 'Unknown'
    
    # Find path conditions
    conditions = rule.find('Conditions')
    if conditions is not None:
        for condition in conditions:
            if condition.tag == 'FilePathCondition':
                path = condition.get('Path', '')
                
                severity = 'Info'
                reasons = []
                recommendations = []
                
                # Check for broad principals
                if is_broad_principal(principal):
                    reasons.append("Principal is broad")
                    recommendations.append("reduce principal scope")
                
                # Check for user-writable paths
                if is_user_writable_path(path):
                    reasons.append("User-writable path")
                    recommendations.append("avoid user-writable paths; replace with Publisher/Hash rules")
                    severity = 'High'
                
                # Check for dangerous wildcards
                if has_dangerous_wildcards(path):
                    reasons.append(f"Wildcard extension pattern ({path.split('\\')[-1]})")
                    recommendations.append("avoid wildcard allows on executable types")
                    if severity != 'High':
                        severity = 'Medium'
                
                # Check for drive roots
                if re.match(r'^[a-z]:\\?$', path.lower()):
                    reasons.append("Drive root access")
                    recommendations.append("specify exact paths instead of drive roots")
                    severity = 'High'
                
                # Downgrade if protected path
                if is_protected_path(path) and severity == 'High':
                    severity = 'Info'
                    recommendations = ["No change needed if file remains locked down; consider Publisher/Hash for defense-in-depth"]
                
                if reasons:
                    findings.append({
                        'Severity': severity,
                        'Collection': collection_type,
                        'RuleType': 'FilePathRule',
                        'Action': action,
                        'Principal': principal,
                        'RuleName': rule_name,
                        'ConditionType': 'Path',
                        'Condition': path,
                        'Reason': '; '.join(reasons) + '.',
                        'Recommendation': '; '.join(recommendations) + '.'
                    })
    
    return findings

def assess_publisher_rule_risk(rule, collection_type):
    """Assess risk for file publisher rules"""
    findings = []
    
    rule_name = rule.get('Name', 'Unnamed Rule')
    action = rule.get('Action', 'Unknown')
    user_or_group = rule.find('UserOrGroupSid')
    principal = user_or_group.text if user_or_group is not None else 'Unknown'
    
    conditions = rule.find('Conditions')
    if conditions is not None:
        for condition in conditions:
            if condition.tag == 'FilePublisherCondition':
                publisher_name = condition.get('PublisherName', '')
                product_name = condition.get('ProductName', '')
                binary_name = condition.get('BinaryName', '')
                
                binary_version_range = condition.find('BinaryVersionRange')
                low_section = binary_version_range.get('LowSection', '') if binary_version_range is not None else ''
                high_section = binary_version_range.get('HighSection', '') if binary_version_range is not None else ''
                
                reasons = []
                recommendations = []
                severity = 'Info'
                
                # Check for overly broad publisher rules
                if product_name == '*' and binary_name == '*':
                    reasons.append("Any product and any binary from the publisher are allowed")
                    recommendations.append("constrain to specific Product/Binary")
                    severity = 'Medium'
                
                if product_name == '*':
                    reasons.append("Any product from publisher allowed")
                    recommendations.append("specify exact product name")
                    if severity == 'Info':
                        severity = 'Medium'
                
                if binary_name == '*':
                    reasons.append("Any binary from publisher/product allowed")
                    recommendations.append("specify exact binary name")
                    if severity == 'Info':
                        severity = 'Medium'
                
                # Check for no upper version bound
                if high_section == '*' or not high_section:
                    reasons.append("No upper version bound")
                    recommendations.append("set an upper version bound")
                    if severity == 'Info':
                        severity = 'Medium'
                
                # Check for broad principals
                if is_broad_principal(principal):
                    reasons.append("Principal is broad")
                    recommendations.append("reduce principal scope")
                
                condition_text = f"Publisher='{publisher_name}'; Product='{product_name}'; Binary='{binary_name}'; VersionRange=[{low_section}, {high_section}]"
                
                if reasons:
                    findings.append({
                        'Severity': severity,
                        'Collection': collection_type,
                        'RuleType': 'FilePublisherRule',
                        'Action': action,
                        'Principal': principal,
                        'RuleName': rule_name,
                        'ConditionType': 'Publisher',
                        'Condition': condition_text,
                        'Reason': '; '.join(reasons) + '.',
                        'Recommendation': '; '.join(recommendations) + '.'
                    })
    
    return findings

def assess_hash_rule_risk(rule, collection_type):
    """Assess risk for file hash rules"""
    findings = []
    
    rule_name = rule.get('Name', 'Unnamed Rule')
    action = rule.get('Action', 'Unknown')
    user_or_group = rule.find('UserOrGroupSid')
    principal = user_or_group.text if user_or_group is not None else 'Unknown'
    
    conditions = rule.find('Conditions')
    if conditions is not None:
        for condition in conditions:
            if condition.tag == 'FileHashCondition':
                file_hash = condition.find('FileHash')
                hash_value = file_hash.get('Data', '') if file_hash is not None else ''
                hash_type = file_hash.get('Type', 'Unknown') if file_hash is not None else 'Unknown'
                
                # Hash rules are generally good, but check for broad principals
                if is_broad_principal(principal):
                    findings.append({
                        'Severity': 'Low',
                        'Collection': collection_type,
                        'RuleType': 'FileHashRule',
                        'Action': action,
                        'Principal': principal,
                        'RuleName': rule_name,
                        'ConditionType': 'Hash',
                        'Condition': f"{hash_type}: {hash_value[:16]}...",
                        'Reason': "Allow-by-hash given to broad principals (rule is tight, group is broad).",
                        'Recommendation': "Consider reducing principal scope for defense-in-depth."
                    })
    
    return findings

def inspect_applocker_policy(xml_content):
    """Main inspection function that analyzes an AppLocker policy"""
    root = parse_applocker_xml(xml_content)
    if root is None:
        return []
    
    findings = []
    
    # Find all rule collections
    rule_collections = root.findall('RuleCollection')
    
    # Assess collection-level risks
    findings.extend(assess_collection_risk(rule_collections))
    
    # Assess individual rules
    for collection in rule_collections:
        collection_type = collection.get('Type', 'Unknown')
        
        # Check each rule type
        for rule in collection:
            if rule.tag == 'FilePathRule':
                findings.extend(assess_path_rule_risk(rule, collection_type))
            elif rule.tag == 'FilePublisherRule':
                findings.extend(assess_publisher_rule_risk(rule, collection_type))
            elif rule.tag == 'FileHashRule':
                findings.extend(assess_hash_rule_risk(rule, collection_type))
    
    return findings

def generate_summary_metrics(findings):
    """Generate summary metrics from findings"""
    severity_counts = defaultdict(int)
    collection_counts = defaultdict(int)
    
    for finding in findings:
        severity_counts[finding['Severity']] += 1
        collection_counts[finding['Collection']] += 1
    
    return severity_counts, collection_counts

# Streamlit UI
st.set_page_config(
    page_title="🔍 AppLocker Inspector", 
    layout="wide",
    initial_sidebar_state="expanded"
)

st.title("🔍 AppLocker Inspector")
st.markdown("""
**Collaboration with Spencer Alessi (@techspence)** 🤝

This tool audits AppLocker policy XML files and reports weak, misconfigured, or risky settings. 
Upload your AppLocker policy to get detailed security recommendations.

*Based on the original [AppLocker Inspector PowerShell script](https://github.com/techspence/AppLockerInspector) by Spencer Alessi*
""")

# File upload
uploaded_file = st.file_uploader(
    "Upload AppLocker Policy XML", 
    type=['xml'],
    help="Upload your AppLocker policy XML file for security analysis"
)

if uploaded_file is not None:
    raw_content = uploaded_file.getvalue()
    
    xml_content = None
    encodings_to_try = ['utf-8-sig', 'utf-16', 'utf-16-le', 'utf-16-be', 'utf-8', 'latin1', 'cp1252']
    
    for encoding in encodings_to_try:
        try:
            xml_content = raw_content.decode(encoding)
            st.success(f"✅ File decoded successfully using {encoding} encoding")
            break
        except UnicodeDecodeError:
            continue
    
    if xml_content is None:
        st.error("❌ Unable to decode the file. Please ensure it's a valid XML file saved with UTF-8, UTF-16, or Windows encoding.")
        st.stop()
    
    with st.spinner('🔍 Analyzing AppLocker policy...'):
        findings = inspect_applocker_policy(xml_content)
    
    if findings:
        # Generate summary metrics
        severity_counts, collection_counts = generate_summary_metrics(findings)
        
        # Display summary metrics
        st.markdown("## 📊 Security Analysis Summary")
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("🔴 High Risk", severity_counts.get('High', 0))
        with col2:
            st.metric("🟡 Medium Risk", severity_counts.get('Medium', 0))
        with col3:
            st.metric("🔵 Low Risk", severity_counts.get('Low', 0))
        with col4:
            st.metric("ℹ️ Info", severity_counts.get('Info', 0))
        
        if collection_counts:
            st.markdown("### Collections Analyzed")
            cols = st.columns(len(collection_counts))
            for i, (collection, count) in enumerate(collection_counts.items()):
                with cols[i]:
                    st.metric(f"{collection}", count)
        
        st.markdown("## 🔍 Detailed Findings")
        
        df = pd.DataFrame(findings)
        
        def style_severity(val):
            if val == 'High':
                return 'background-color: #ffebee; color: #c62828'
            elif val == 'Medium':
                return 'background-color: #fff3e0; color: #ef6c00'
            elif val == 'Low':
                return 'background-color: #e8f5e8; color: #2e7d32'
            else:  # Info
                return 'background-color: #e3f2fd; color: #1565c0'
        
        severity_filter = st.multiselect(
            "Filter by Severity",
            options=['High', 'Medium', 'Low', 'Info'],
            default=['High', 'Medium', 'Low', 'Info']
        )
        
        collection_filter = st.multiselect(
            "Filter by Collection",
            options=df['Collection'].unique(),
            default=df['Collection'].unique()
        )
        
        filtered_df = df[
            (df['Severity'].isin(severity_filter)) & 
            (df['Collection'].isin(collection_filter))
        ]
        
        if not filtered_df.empty:
            styled_df = filtered_df.style.applymap(style_severity, subset=['Severity'])
            st.dataframe(styled_df, use_container_width=True, height=400)
            
            st.markdown("## 📤 Export Results")
            
            col1, col2 = st.columns(2)
            
            with col1:
                csv_buffer = io.StringIO()
                filtered_df.to_csv(csv_buffer, index=False)
                csv_data = csv_buffer.getvalue()
                
                st.download_button(
                    label="📊 Download as CSV",
                    data=csv_data,
                    file_name=f"applocker_inspection_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )
            
            with col2:
                json_data = filtered_df.to_json(orient='records', indent=2)
                
                st.download_button(
                    label="📋 Download as JSON",
                    data=json_data,
                    file_name=f"applocker_inspection_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json"
                )
            
            high_findings = filtered_df[filtered_df['Severity'] == 'High']
            if not high_findings.empty:
                st.markdown("## 🚨 High Priority Recommendations")
                for _, finding in high_findings.iterrows():
                    with st.expander(f"🔴 {finding['Collection']} - {finding['RuleName']}"):
                        st.markdown(f"**Issue:** {finding['Reason']}")
                        st.markdown(f"**Recommendation:** {finding['Recommendation']}")
                        st.markdown(f"**Rule Type:** {finding['RuleType']}")
                        st.markdown(f"**Condition:** `{finding['Condition']}`")
        else:
            st.info("No findings match the selected filters.")
    
    else:
        st.success("🎉 No security issues found in the AppLocker policy!")
        st.balloons()

else:
    st.markdown("## 🔍 What does AppLocker Inspector check?")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        ### 🚨 High Risk Issues
        - **NotConfigured collections** - Default allow behavior
        - **User-writable paths** - Temp folders, user directories
        - **Drive root access** - C:\\, D:\\, etc.
        - **Broad principals** - Everyone, Authenticated Users
        """)
        
        st.markdown("""
        ### 🟡 Medium Risk Issues  
        - **AuditOnly mode** - Not enforcing blocks
        - **Wildcard patterns** - *.exe, *.dll in risky locations
        - **Overly broad publishers** - Any product/binary allowed
        - **No version bounds** - No upper version limits
        """)
    
    with col2:
        st.markdown("""
        ### 🔵 Low Risk Issues
        - **Hash rules with broad principals** - Good rule, broad group
        """)
        
        st.markdown("""
        ### ℹ️ Informational
        - **Protected paths** - Rules in Program Files, Windows
        - **Well-configured rules** - Specific paths and principals
        """)

st.sidebar.image("assets/logo.png", width=250)
st.sidebar.markdown("---")
st.sidebar.markdown("""
### 🤝 Collaboration
This feature was developed in collaboration with **Spencer Alessi** ([@techspence](https://github.com/techspence))

Original PowerShell script: [AppLocker Inspector](https://github.com/techspence/AppLockerInspector)
""")
