# PersistenceHunter.ps1

**🔍 PowerShell-based Threat Hunting Tool to Detect Windows Persistence Mechanisms**  
A lightweight and extensible CLI tool for **blue teamers**, **SOC analysts**, and **malware researchers** to uncover hidden persistence footholds and suspicious autoruns on Windows systems.

---

### 🚀 What It Does

`PersistenceHunter.ps1` inspects various Windows startup vectors to detect:
- Autoruns with missing or invalid digital signatures
- Obfuscated or suspicious file paths and command-line arguments
- Hardcoded IPs/domains used in malware persistence
- Malicious Registry startup modifications
- Boot-start driver manipulation
- Suspicious `.lnk` shortcut targets
- DLL injection via AppInitDLLs

💡 Built using MITRE ATT&CK mappings:
- [T1547.001](https://attack.mitre.org/techniques/T1547/001/) – Registry Run Keys
- [T1053](https://attack.mitre.org/techniques/T1053/) – Scheduled Tasks
- [T1546.010](https://attack.mitre.org/techniques/T1546/010/) – AppInit DLLs

---

### 🧠 Key Features

- 🔍 **Auto mode**: Instantly filters and flags high-confidence persistence entries
- 🧾 **CSV reporting**: Generate detailed audit logs for IR or evidence
- 🧩 **Modular modes**: Target `Registry`, `Services`, `Tasks`, or `Startup` individually
- 🎯 **Keyword hunting**: Match suspicious strings like `Cobalt`, `Invoke`, `http`, etc.
- 🖥️ **No installation** required — perfect for portable, stealthy investigations

---

### 📦 Usage

#### 📁 Local Execution:
```powershell
Invoke-Expression (Get-Content "C:\Tools\PersistenceHunter.ps1" -Raw)
Hunt-Persistence -mode "Auto" -strings @("Invoke-WebRequest", "http", "reverse") -csv "C:\Reports\autoruns.csv"
