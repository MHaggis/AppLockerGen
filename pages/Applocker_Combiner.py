import streamlit as st
import xml.etree.ElementTree as ET
from lxml import etree

def parse_xml(xml_content):
    return ET.fromstring(xml_content)
def combine_xml_roots(root1, root2):
    rule_collections = {rc.get('Type'): rc for rc in root1.findall('RuleCollection')}
    
    for rc in root2.findall('RuleCollection'):
        rc_type = rc.get('Type')
        if rc_type in rule_collections:
            existing_rc = rule_collections[rc_type]
            existing_ids = {rule.get('Id') for rule in existing_rc}
            for rule in rc:
                if rule.get('Id') not in existing_ids:
                    existing_rc.append(rule)
                    existing_ids.add(rule.get('Id'))
        else:
            root1.append(rc)
            rule_collections[rc_type] = rc
    return root1

def pretty_print_xml(xml_root):
    xml_str = ET.tostring(xml_root, encoding='unicode')
    parser = etree.XMLParser(remove_blank_text=True)
    xml_etree = etree.fromstring(xml_str.encode(), parser)
    return etree.tostring(xml_etree, pretty_print=True).decode()

def validate_xml(xml_content):
    try:
        etree.fromstring(xml_content)
        return True
    except etree.XMLSyntaxError:
        return False

st.title('AppLocker Policy Combiner')
st.markdown("""
    This tool helps you combine multiple AppLocker policies into a single policy file. 
    Simply upload two or more XML files, and it will merge them, ensuring that there are no duplicate rules.
    """)

uploaded_files = st.file_uploader("Upload XML Files", accept_multiple_files=True, type=['xml'])

if uploaded_files and st.button('Combine Policies'):
    combined_root = None

    for uploaded_file in uploaded_files:
        content = uploaded_file.getvalue()
        if combined_root is None:
            combined_root = parse_xml(content)
        else:
            root_to_combine = parse_xml(content)
            combined_root = combine_xml_roots(combined_root, root_to_combine)

    if combined_root is not None:
        combined_xml_str = pretty_print_xml(combined_root)
        if validate_xml(combined_xml_str):
            st.code(combined_xml_str, language='xml')
            st.download_button(label="Download Combined XML", data=combined_xml_str, file_name="combined_applocker_policy.xml", mime="text/xml")
        else:
            st.error('The combined XML is not valid.')
    else:
        st.error('No XML files to combine.')
        
st.sidebar.image("assets/logo.png", width=250)