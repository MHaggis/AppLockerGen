import streamlit as st

st.set_page_config(page_title="AppLockerGen", layout="wide")

st.markdown("<h1 style='text-align: left;'>AppLocker Policy Generator</h1>", unsafe_allow_html=True)

col1, col2 = st.columns([3, 1])

with col1:
    st.write("""
    <b>Welcome to AppLockerGen.</b> 🎉 This tool is designed to assist system administrators and security professionals in creating and managing AppLocker policies. 🛡️

    AppLockerGen simplifies the process of generating AppLocker XML policies, providing a user-friendly interface to create, merge, and manage rules effectively. 🚀

    Key features of AppLockerGen include:

    1️⃣ **Policy Creation**: Easily define rules for your applications, scripts, and installers to enhance security. 📝

    2️⃣ **Policy Merging**: Combine multiple AppLocker policies into one comprehensive set of rules. 🧩

    3️⃣ **Policy Validation**: Ensure that your AppLocker policies are correctly formatted and free of errors before deployment. ✅

    4️⃣ **Export and Import**: Import existing policies for editing, and export your policies for deployment across your organization. 🔄

    AppLockerGen is an open-source project, and we encourage contributions and feedback from the community to continue improving the tool. 🌐

    Get started by uploading your existing AppLocker XML files or create new policies using the interface provided. 📤📥

    """, unsafe_allow_html=True)

with col2:
    st.markdown("""
    <iframe width="560" height="315" src="https://www.youtube.com/embed/1emSFbHw3_A?si=ZToPayrAofa0rX0c" title="AppLockerGen Demo" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" allowfullscreen></iframe>
    """, unsafe_allow_html=True)

st.sidebar.image("assets/logo.png", width=250)