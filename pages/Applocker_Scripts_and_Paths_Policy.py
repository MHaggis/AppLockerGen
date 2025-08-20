import streamlit as st
import uuid
import xml.etree.ElementTree as ET
from xml.dom import minidom

st.set_page_config(
    page_title="⚒️ Applocker Scripts and Paths Policy Generator",
    layout="wide",
    initial_sidebar_state="expanded",
)
try:
    st.sidebar.image("assets/logo.png", width=250)
except:
    # Fallback if logo can't be loaded
    st.sidebar.markdown("### 🔒 AppLockerGen")

def generate_xml(rules, enforcement_mode):
    root = ET.Element("AppLockerPolicy", Version="1")
    rule_collection = ET.SubElement(root, "RuleCollection", Type="Script", EnforcementMode=enforcement_mode)
    for rule in rules:
        file_path_rule = ET.SubElement(rule_collection, "FilePathRule", Id=str(uuid.uuid4()), Name=rule['name'], Description=rule.get('description', ""), UserOrGroupSid="S-1-1-0", Action=rule['action'])
        conditions = ET.SubElement(file_path_rule, "Conditions")
        ET.SubElement(conditions, "FilePathCondition", Path=rule['path'])

    rough_string = ET.tostring(root, 'utf-8')
    reparsed = minidom.parseString(rough_string)
    return reparsed.toprettyxml(indent="  ")

st.title("Applocker Scripts and Paths Policy Generator")

st.markdown("""
This application generates XML policies for script and path rules for AppLocker.

You can specify rules for paths and scripts, and choose whether to set them to 'Audit' or 'Block' mode.
""")

mode = st.radio("Select Mode", ('Block', 'Audit'))
enforcement_mode = "AuditOnly" if mode == 'Audit' else "Enabled"

rule_options = st.multiselect(
    "Select the types of rules to include in the policy",
    ['Paths', 'Scripts'],
    default=['Paths', 'Scripts']
)

with st.expander("Paths"):
    st.caption("Specify paths to include in the policy. You can use environment variables like %PROGRAMFILES%.")
    path_rules = st.text_area("Enter each path on a new line", height=150)

with st.expander("Scripts"):
    st.caption("Specify script rules to include in the policy. You can use environment variables and wildcards.")
    script_rules = st.text_area("Enter each script rule on a new line", height=150)

if st.button("Generate Policy"):
    rules = []
    if 'Paths' in rule_options:
        for line in path_rules.split('\n'):
            if line.strip():
                rules.append({
                    'name': line.strip(),
                    'path': line.strip(),
                    'action': 'Deny'
                })
    if 'Scripts' in rule_options:
        for line in script_rules.split('\n'):
            if line.strip():
                rules.append({
                    'name': line.strip(),
                    'path': line.strip(),
                    'action': 'Deny'
                })
    xml_content = generate_xml(rules, enforcement_mode)
    st.text_area("Generated Policy XML", xml_content, height=250)
    st.download_button(
        label="Download XML File",
        data=xml_content,
        file_name="applocker_scripts_paths_policy.xml",
        mime="text/xml"
    )
else:
    st.write("Enter rules and click 'Generate Policy' to see the XML.")