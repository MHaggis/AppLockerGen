import streamlit as st
import os
import xml.etree.ElementTree as ET

def validate_xml(xml_string):
    try:
        ET.fromstring(xml_string)
        return True
    except ET.ParseError:
        return False

st.set_page_config(
    page_title="🔒 AppLocker Pre-Built Policies",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.title("AppLocker Pre-Built Policies")

st.markdown("""
By default, AppLocker is not configured to block any applications. This application allows you to download pre-created policies to block common applications. You can also modify the policies to suit your needs.

**Note:** These policies are not exhaustive and are not guaranteed to block all applications. You should test the policies in your environment before deploying them to production.
""")

default_policies_path = 'default/'
policy_files = os.listdir(default_policies_path)
selected_policy = st.selectbox("Select a pre-created AppLocker policy", policy_files)

if 'selected_policy' not in st.session_state or st.session_state.selected_policy != selected_policy:
    st.session_state.selected_policy = selected_policy
    policy_path = os.path.join(default_policies_path, selected_policy)
    with open(policy_path, 'r') as policy_file:
        st.session_state.policy_content = policy_file.read()

policy_content = st.text_area("Edit the policy XML:", st.session_state.policy_content, height=500)

if st.button("Download Policy"):
    if validate_xml(policy_content):
        st.download_button(label="Download XML", data=policy_content, file_name=selected_policy, mime='text/xml')
    else:
        st.error("The modified XML is not valid. Please check your changes and try again.")
        
st.sidebar.image("assets/logo.png", width=250)