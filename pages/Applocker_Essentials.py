import streamlit as st

st.set_page_config(page_title="AppLocker Essentials", layout="wide")
st.sidebar.image("assets/logo.png", width=250)

st.title("AppLocker Essentials")

toc = """
1. **[Introduction](#what-is-applocker)**
   - [What is AppLocker?](#what-is-applocker)

2. **[Using AppLocker](#using-applocker)**
   - [Through Group Policy Objects (GPO)](#group-policy-objects-gpo)
   - [Using PowerShell](#powershell)

3. **[Checking Event Logs](#checking-event-logs)**
   - [Event Viewer Steps](#event-viewer-steps)
"""

st.markdown(toc, unsafe_allow_html=True)

st.header("What is AppLocker?")
st.write("""
AppLocker is a Windows feature that enhances security by restricting the execution of unwanted or unknown applications. It allows administrators to control which users or groups can run particular applications based on files' unique identities.
""")

st.header("Using AppLocker")
st.subheader("Group Policy Objects (GPO)")
st.write("""
AppLocker can be configured via Group Policy Objects. The steps include:
- Open the Group Policy Management Console (GPMC).
- Edit the appropriate GPO.
- Navigate to Application Control Policies > AppLocker.
- Create new rules as needed.
""")

st.subheader("PowerShell")
st.write("""
AppLocker policies can also be set using PowerShell cmdlets:
- Open PowerShell with administrative privileges.
- Use the `Set-AppLockerPolicy` cmdlet to configure policies.
""")

st.code("""
# Example of using Set-AppLockerPolicy to merge a new policy with existing policies
Set-AppLockerPolicy -XmlPolicy 'C:\\Policies\\AppLockerPolicy.xml' -Merge

# Example of using Get-AppLockerPolicy to retrieve the effective policy on the local machine
$policy = Get-AppLockerPolicy -Effective
Out-File -InputObject $policy -FilePath 'C:\\Policies\\EffectiveAppLockerPolicy.xml'

# Example of using New-AppLockerPolicy to create a policy from a list of files
$fileList = Get-ChildItem -Path 'C:\\Apps\\' -Recurse
$newPolicy = New-AppLockerPolicy -FileInformation $fileList -RuleType Publisher, Hash -User Everyone
Out-File -InputObject $newPolicy -FilePath 'C:\\Policies\\NewAppLockerPolicy.xml'

# Example of using Test-AppLockerPolicy to test a policy against a file for a specific user
$userSid = 'S-1-5-21-1234567890-1234567890-1234567890-1001'
$result = Test-AppLockerPolicy -XmlPolicy 'C:\\Policies\\AppLockerPolicy.xml' -Path 'C:\\Apps\\MyApp.exe' -UserSid $userSid
Write-Host "The file will " + $(if ($result) { "be allowed" } else { "not be allowed" }) + " to run for the user."

# Example of using Get-AppLockerFileInformation to retrieve file information for rule creation
$fileInfo = Get-AppLockerFileInformation -Path 'C:\\Apps\\MyApp.exe'
Write-Host "File Publisher: " $fileInfo.Publisher
Write-Host "File Hash: " $fileInfo.Hash
""", language="powershell")

st.markdown("For more information on AppLocker cmdlets, visit the [AppLocker Cmdlets in Windows PowerShell](https://learn.microsoft.com/en-us/powershell/module/applocker/?view=windowsserver2022-ps) documentation.")


st.header("Checking Event Logs")
st.subheader("Event Viewer Steps")
st.write("""
To review AppLocker logs in Event Viewer:
- Open Event Viewer.
- Navigate to Windows Logs > Application.
- Use the 'Filter Current Log' option to select AppLocker events.
""")

st.subheader("AppLocker Event IDs")
st.write("""
AppLocker logs various events in the Event Viewer, which can be identified by specific Event IDs:
- `8000`: Policy Application Failure
- `8001`: Policy Application Success
- `8002`: Allowed File Execution
- `8003`: Audited File Execution
- `8004`: Blocked File Execution
- `8005`: Allowed Script or MSI Execution
- `8006`: Audited Script or MSI Execution
- `8007`: Blocked Script or MSI Execution
- `8020`: Allowed Packaged App
- `8021`: Audited Packaged App
- `8022`: Disabled Packaged App
- `8023`: Allowed Packaged App Installation
- `8024`: Audited Packaged App Installation
- `8025`: Disabled Packaged App Installation
- `8027`: No Packaged App Rule
""")

st.subheader("AppLocker Log Storage Locations")
st.write("""
AppLocker events are stored in different logs within Event Viewer. Here are the four primary logs:
- `EXE and DLL`: Microsoft-Windows-AppLocker/EXE and DLL
- `Packaged app-Execution`: Microsoft-Windows-AppLocker/Packaged app-Execution
- `Packaged app-Deployment`: Microsoft-Windows-AppLocker/Packaged app-Deployment
- `MSI and Script`: Microsoft-Windows-AppLocker/MSI and Script
""")

st.caption("[Learn more about AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-overview)")