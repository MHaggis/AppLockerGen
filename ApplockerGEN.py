import streamlit as st

st.set_page_config(page_title="AppLockerGen", layout="wide")

st.markdown("<h1 style='text-align: left;'>AppLocker Policy Generator</h1>", unsafe_allow_html=True)

col1, col2, col3 = st.columns([2,1,1])

with col1:
    st.write("""
    <b>Welcome to AppLockerGen.</b> 🎉 This tool is designed to assist system administrators and security professionals in creating and managing AppLocker policies. 🛡️

    AppLockerGen simplifies the process of generating AppLocker XML policies, providing a user-friendly interface to create, merge, and manage rules effectively. 🚀

    Key features of AppLockerGen include:

    1️⃣ <a href="AppLocker_Scripts_and_Paths_Policy" target="_self">**Policy Creation**</a>: Easily define rules for your applications, scripts, and installers to enhance security. This page allows you to specify rules for paths and scripts, and choose whether to set them to 'Audit' or 'Block' mode. 📝

    2️⃣ <a href="App:ocker_Combiner" target="_self">**Policy Merging**</a>: Combine multiple AppLocker policies into one comprehensive set of rules. This tool helps you combine multiple AppLocker policies into a single policy file. 🧩

    3️⃣ <a href="AppLocker_Pre-Built_Policies" target="_self">**Pre-Built Policies**</a>: Ensure that your AppLocker policies are correctly formatted and free of errors before deployment. This application allows you to download pre-created policies to block common applications. You can also modify the policies to suit your needs. ✅

    4️⃣ <a href="Modify_AppLocker_Policy" target="_self">**Export and Import**</a>: Import existing policies for editing, and export your policies for deployment across your organization. This page allows you to upload an AppLocker Policy XML file or paste your AppLocker Policy XML for modification. 🔄
    
    5️⃣ <a href="AppLocker_Essentials" target="_self">**Learn More About AppLocker**</a>: This page provides a brief overview of AppLocker, including the different types of rules, and how to configure AppLocker. 📊
    
    6️⃣ <a href="AppLocker_Atomic_Testing" target="_self">**AppLocker Atomic Testing**</a>: This page provides a list of common AppLocker bypasses and how to test them. 📄

    AppLockerGen is an open-source project, and we encourage contributions and feedback from the community to continue improving the tool. 🌐

    Get started by uploading your existing AppLocker XML files or create new policies using the interface provided. 📤📥

    """, unsafe_allow_html=True)

with col2:
    st.markdown("""
    <iframe width="560" height="315" src="https://www.youtube.com/embed/1emSFbHw3_A?si=ZToPayrAofa0rX0c" title="AppLockerGen Demo" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" allowfullscreen></iframe>
    """, unsafe_allow_html=True)

st.sidebar.image("assets/logo.png", width=250)