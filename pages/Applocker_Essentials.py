import streamlit as st

st.set_page_config(page_title="AppLocker Essentials", layout="wide")
try:
    st.sidebar.image("assets/logo.png", width=250)
except:
    # Fallback if logo can't be loaded
    st.sidebar.markdown("### 🔒 AppLockerGen")

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

st.code("""
PS > Test-AppLockerPolicy -XmlPolicy C:\\policies\\applocker.xml -Path C:\\temp\\hello.ps1

FilePath           PolicyDecision MatchingRule
--------           -------------- ------------
C:\\temp\\hello.ps1 DeniedByDefault
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
- `8000`: AppID policy conversion failed. Status * <%1> *	Indicates that the policy wasn't applied correctly to the computer. The status message is provided for troubleshooting purposes.
- `8001`: The AppLocker policy was applied successfully to this computer.	Indicates that the AppLocker policy was successfully applied to the computer.
- `8002`: *<File name> * was allowed to run.	Indicates an AppLocker rule allowed the .exe or .dll file.
- `8003`: *<File name> * was allowed to run but would have been prevented from running if the AppLocker policy were enforced.	Shown only when the Audit only enforcement mode is enabled. Indicates that the AppLocker policy would block the .exe or .dll file if the enforcement mode setting was Enforce rules.
- `8004`: *<File name> * was prevented from running.	AppLocker blocked the named EXE or DLL file. Shown only when the Enforce rules enforcement mode is enabled.
- `8005`: *<File name> * was allowed to run.	Indicates an AppLocker rule allowed the script or .msi file.
- `8006`: *<File name> * was allowed to run but would have been prevented from running if the AppLocker policy were enforced.	Shown only when the Audit only enforcement mode is enabled. Indicates that the AppLocker policy would block the script or .msi file if the Enforce rules enforcement mode was enabled.
- `8007`: *<File name> * was prevented from running.	AppLocker blocked the named Script or MSI. Shown only when the Enforce rules enforcement mode is enabled.
- `8008`: *<File name> *: AppLocker component not available on this SKU.	Indicates an edition of Windows that doesn't support AppLocker.
- `8020`: *<File name> * was allowed to run.	Added in Windows Server 2012 and Windows 8.
- `8021`: *<File name> * was allowed to run but would have been prevented from running if the AppLocker policy were enforced.	Added in Windows Server 2012 and Windows 8.
- `8022`: *<File name> * was prevented from running.	Added in Windows Server 2012 and Windows 8.
- `8023`: *<File name> * was allowed to be installed.	Added in Windows Server 2012 and Windows 8.
- `8024`: *<File name> * was allowed to run but would have been prevented from running if the AppLocker policy were enforced.	Added in Windows Server 2012 and Windows 8.
- `8025`: *<File name> * was prevented from running.	Added in Windows Server 2012 and Windows 8.
- `8027`: No packaged apps can be executed while Exe rules are being enforced and no Packaged app rules have been configured.	Added in Windows Server 2012 and Windows 8.
- `8028`: *<File name> * was allowed to run but would have been prevented if the Config CI policy were enforced.	Added in Windows Server 2016 and Windows 10.
- `8029`: *<File name> * was prevented from running due to Config CI policy.	Added in Windows Server 2016 and Windows 10.
- `8030`: ManagedInstaller check SUCCEEDED during Appid verification of *	Added in Windows Server 2016 and Windows 10.
- `8031`: SmartlockerFilter detected file * being written by process *	Added in Windows Server 2016 and Windows 10.
- `8032`: ManagedInstaller check FAILED during Appid verification of *	Added in Windows Server 2016 and Windows 10.
- `8033`: ManagedInstaller check FAILED during Appid verification of * . Allowed to run due to Audit AppLocker Policy.	Added in Windows Server 2016 and Windows 10.
- `8034`: ManagedInstaller Script check FAILED during Appid verification of *	Added in Windows Server 2016 and Windows 10.
- `8035`: ManagedInstaller Script check SUCCEEDED during Appid verification of *	Added in Windows Server 2016 and Windows 10.
- `8036`: * was prevented from running due to Config CI policy	Added in Windows Server 2016 and Windows 10.
- `8037`: * passed Config CI policy and was allowed to run.	Added in Windows Server 2016 and Windows 10.
- `8038`: Publisher info: Subject: * Issuer: * Signature index * (* total)	Added in Windows Server 2016 and Windows 10.
- `8039`: Package family name * version * was allowed to install or update but would have been prevented if the Config CI policy	Added in Windows Server 2016 and Windows 10.
- `8040`: Package family name * version * was prevented from installing or updating due to Config CI policy	Added in Windows Server 2016 and Windows 10.
""")

st.header("AppLocker Rule Collections and Associated File Formats")
st.markdown("For more details, visit [Microsoft's official documentation](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-overview)")
st.write("""
| Rule Collection | Associated File Formats |
| --- | --- |
| Executable files | .exe, .com |
| Scripts | .ps1, .bat, .cmd, .vbs, .js |
| Windows Installer files | .msi, .msp, .mst |
| Packaged apps and packaged installers | .appx |
| DLL files | .dll, .ocx |
""")


st.subheader("AppLocker Events in Event Viewer")
st.write("""
AppLocker events are stored in different logs within Event Viewer. Here are the four primary logs:
- `EXE and DLL`: Microsoft-Windows-AppLocker/EXE and DLL
- `Packaged app-Execution`: Microsoft-Windows-AppLocker/Packaged app-Execution
- `Packaged app-Deployment`: Microsoft-Windows-AppLocker/Packaged app-Deployment
- `MSI and Script`: Microsoft-Windows-AppLocker/MSI and Script
""")

st.caption("[Learn more about AppLocker - MSFT](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-overview)")
st.caption("[Ultimate AppLocker Bypass List - api0cradle](https://github.com/api0cradle/UltimateAppLockerByPassList)")