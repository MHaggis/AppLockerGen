import streamlit as st
import hashlib
import xml.etree.ElementTree as ET
import base64
from xml.dom import minidom
import uuid
import os
import lief
#import exiftool

st.set_page_config(
    page_title="⚒️ Applocker EXE Policy Generator",
    layout="wide",
    initial_sidebar_state="expanded",
)
try:
    st.sidebar.image("assets/logo.png", width=250)
except:
    # Fallback if logo can't be loaded
    st.sidebar.markdown("### 🔒 AppLockerGen")

def extract_publisher_and_version_info(file_path):
    try:
        pe = lief.parse(file_path)
        if len(pe.signatures) == 0:
            return None, None, None

        cert = pe.signatures[0].certificates[0]
        publisher = cert.subject.replace('\\', '').replace('-', ',')

        version_info = pe.resources_manager.version.string_file_info.langcode_items[0].items
        version = version_info.get('FileVersion', b'').decode("utf-8")
        internal_name = version_info.get('InternalName', b'').decode("utf-8")

        return publisher, version, internal_name
    except Exception as e:
        print(f"Could not extract publisher, version info, and internal name: {e}")
        return None, None, None

def calculate_hash_and_length(file):
    sha256_hash = hashlib.sha256()
    file_length = 0
    file.seek(0)
    for byte_block in iter(lambda: file.read(4096), b""):
        file_length += len(byte_block)
        sha256_hash.update(byte_block)
    return sha256_hash.hexdigest(), file_length

def generate_xml(publishers, versions, internal_names, file_hashes, filenames, lengths, mode, include_hash, include_publisher):
    enforcement_mode = "AuditOnly" if mode == 'Audit' else "Enabled"
    action = "Deny" if mode == 'Block' else "Allow"
    root = ET.Element("AppLockerPolicy", Version="1")
    rule_collection = ET.SubElement(root, "RuleCollection", Type="Exe", EnforcementMode=enforcement_mode)

    publisher_rules_dict = {}

    for publisher, version, internal_name, file_hash, filename, length in zip(publishers, versions, internal_names, file_hashes, filenames, lengths):
        binary_name = internal_name if internal_name and '.' in internal_name else filename

        if include_hash:
            rule_id_hash = str(uuid.uuid4())
            file_hash_rule = ET.SubElement(rule_collection, "FileHashRule", Id=rule_id_hash, Name="Hash Rule for " + binary_name, Description="", UserOrGroupSid="S-1-1-0", Action=action)
            conditions_hash = ET.SubElement(file_hash_rule, "Conditions")
            file_hash_condition = ET.SubElement(conditions_hash, "FileHashCondition")
            formatted_hash = f"0x{file_hash.upper()}"
            ET.SubElement(file_hash_condition, "FileHash", Type="SHA256", Data=formatted_hash, SourceFileName=binary_name, SourceFileLength=str(length))

        if include_publisher and publisher:
            publisher_rule_key = (publisher, version, binary_name)
            if publisher_rule_key not in publisher_rules_dict:
                publisher_rules_dict[publisher_rule_key] = {
                    'rule_id': str(uuid.uuid4()),
                    'filenames': [filename]
                }
            else:
                publisher_rules_dict[publisher_rule_key]['filenames'].append(filename)

    if include_publisher:
        for (publisher, version, binary_name), rule_info in publisher_rules_dict.items():
            rule_id_publisher = rule_info['rule_id']
            covered_filenames = ', '.join(rule_info['filenames'])
            description = f"Files covered by this rule: {covered_filenames}"

            file_publisher_rule = ET.SubElement(rule_collection, "FilePublisherRule", Id=rule_id_publisher, Name="Publisher Rule for " + binary_name, Description=description, UserOrGroupSid="S-1-1-0", Action=action)
            conditions_publisher = ET.SubElement(file_publisher_rule, "Conditions")
            file_publisher_condition = ET.SubElement(conditions_publisher, "FilePublisherCondition", PublisherName=publisher, ProductName="*", BinaryName=binary_name)
            version_range_low = version_range_high = version or "0.0.0.0"
            ET.SubElement(file_publisher_condition, "BinaryVersionRange", LowSection=version_range_low, HighSection=version_range_high)

    rough_string = ET.tostring(root, 'utf-8')
    reparsed = minidom.parseString(rough_string)
    return reparsed.toprettyxml(indent="  ")


st.title("Applocker EXE Policy Generator")

st.markdown("""
This application generates XML policies for uploaded .exe, .sys, .dll, or .bin files.

For each uploaded file, it extracts the publisher and version information, calculates the SHA256 hash and file length, and generates an AppLocker policy.

The policy includes both a Publisher Rule and a Hash Rule for each file. The Publisher Rule allows execution of files from the same publisher and with the same internal name, within a specific version range. The Hash Rule allows execution of files with the same SHA256 hash.

You can choose to generate the policies in 'Block' or 'Audit' mode. In 'Block' mode, the policies are enforced and execution of non-compliant files is blocked. In 'Audit' mode, policy violations are only logged and execution is not blocked.

After generating the policies, you can view the generated XML and download it as an 'applocker_config.xml' file.
""")

uploaded_files = st.file_uploader("Upload .exe, .sys, or .dll files", accept_multiple_files=True, type=['exe', 'sys', 'dll', 'bin'])
mode = st.radio("Select Mode", ('Block', 'Audit'))

rule_options = st.multiselect(
    "Select the types of rules to include in the policy",
    ['Hash', 'Publisher'],
    default=['Hash', 'Publisher']
)

publishers = []
versions = []
internal_names = []
file_hashes = []
filenames = []
file_lengths = []
xml_content = ""

if uploaded_files:
    for uploaded_file in uploaded_files:
        temp_file_path = f"./{uploaded_file.name}"
        with open(temp_file_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        try:
            file_hash, file_length = calculate_hash_and_length(uploaded_file)
            publisher, version, internal_name = extract_publisher_and_version_info(temp_file_path)
            publishers.append(publisher)
            versions.append(version)
            internal_names.append(internal_name)
            file_hashes.append(file_hash)
            filenames.append(uploaded_file.name)
            file_lengths.append(file_length)
            include_hash = 'Hash' in rule_options
            include_publisher = 'Publisher' in rule_options
        except Exception as e:
            st.error(f"Error processing file {uploaded_file.name}: {e}")
        finally:
            os.remove(temp_file_path)

    xml_content = generate_xml(publishers, versions, internal_names, file_hashes, filenames, file_lengths, mode, include_hash, include_publisher)

st.markdown("### Policy", unsafe_allow_html=True)
policy_content = st.text_area("Modify the policy as needed", xml_content, height=250)

st.markdown("### Output", unsafe_allow_html=True)
st.code(policy_content, language="xml")

st.download_button(
    label="Download XML File",
    data=policy_content,
    file_name="applocker_exe_policy.xml",
    mime="text/xml"
)