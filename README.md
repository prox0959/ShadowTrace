> ⚡ **NEW COMMERCIAL RELEASE:** Check out **[ProxSuite PRO (Apex v2.5 Enterprise)](https://prox0959.github.io/ProxSuite-PRO/)** — Our **25-in-1 Native x64 Windows EDR, Live Memory Forensics (Module Stomping / Ghosting / Syscalls), Anti-Stealer & SIEM Suite** (~95 KB EXE, 100% Defender Clean). **[24h Free Trial / .99 License /  Full C# Source Code (Crypto Only)](https://prox0959.github.io/ProxSuite-PRO/#instant-checkout)**

---

# 🕵️‍♂️ ShadowTrace

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=for-the-badge&logo=windows)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Languages](https://img.shields.io/badge/Language-English%20%7C%20T%C3%BCrk%C3%A7e-00FF41?style=for-the-badge)

**A lightweight Windows program execution forensics & activity timeline extraction tool.**

</div>

---

## 🔍 What is ShadowTrace?

In Windows incident response and digital forensics (DFIR), investigating whether a suspect or malware executed unauthorized software (e.g., credential dumpers, keyloggers, or malicious payloads) is critical. Even if an attacker deletes an executable from the filesystem, Windows maintains silent execution artifacts in the Registry.

**ShadowTrace** extracts and parses two critical Windows execution artifacts:
1. **UserAssist (`HKCU\...\UserAssist`):**
   - Windows Explorer records every GUI application launched by the user.
   - To conceal these entries, Windows obfuscates the subkey names with **ROT13** (a Caesar cipher variant).
   - Each entry stores a binary structure containing the **exact execution timestamp (`FILETIME`)**, **run count**, and **active focus duration** (how many seconds the user actively had the app in the foreground).
2. **RunMRU (`HKCU\...\RunMRU`):**
   - Tracks commands typed and executed via the `Win + R` Run dialog, along with execution ordering (`MRUList`).

ShadowTrace decodes the ROT13 strings, unpacks the 72-byte binary structures, and correlates them into a unified chronological execution timeline.

## ✨ Features
- ⚡ **Zero External Dependencies:** Built entirely using Python standard libraries (`winreg`, `struct`, `codecs`, `datetime`, `json`).
- 🌐 **Bilingual Support:** Full English (default) and Turkish CLI output options.
- 🔓 **ROT13 Decryption:** Automatically decodes obfuscated UserAssist registry values.
- ⏱️ **Timestamp & Duration Decoding:** Translates 64-bit Windows `FILETIME` and microsecond focus times into human-readable timelines.
- 📋 **DFIR JSON Reporting:** Exports a forensic timeline report (`forensic_execution_timeline.json`) ready for timeline analysis and ingestion into SIEM tools.

## 🚀 Usage

```bash
# Clone the repository
git clone https://github.com/prox0959/ShadowTrace.git
cd ShadowTrace

# Run in English (Default)
python shadowtrace.py

# Run with Turkish output
python shadowtrace.py --lang tr
```

## 🌐 Language Options

| Argument | Description |
|---|---|
| `python shadowtrace.py` | Runs with default **English** DFIR headers and reporting |
| `python shadowtrace.py --lang en` | Explicitly sets language to **English** |
| `python shadowtrace.py --lang tr` | Sets language to **Turkish (Türkçe)** |

## 📊 Sample Output (English Default)

```text
===============================================================================================
 [SHADOWTRACE] - WINDOWS PROGRAM EXECUTION & FORENSIC ARTIFACTS
===============================================================================================
[*] Decoded a total of 193 program execution forensic artifacts:

#   | Application / Command                         | Runs    | Focus(s) | Last Execution (Local)
-----------------------------------------------------------------------------------------------
1   | Run Command: cmd                              | 1+      | N/A      | Recent Session     
2   | Run Command: appdata                          | 1+      | N/A      | Recent Session     
3   | Microsoft.VisualStudioCode                    | 4       | 141.4    | 2026-09-24 00:58:48
4   | SpotifyAB.SpotifyMusic_zpdnekdrzrea0!Spotify  | 2       | 800.1    | 2026-09-24 00:11:21
5   | electron.app.Antigravity                      | 3       | 5433.5   | 2026-09-24 00:04:04
6   | Microsoft.WindowsCalculator_8wekyb3d8bbwe!App | 1       | 30.9     | 2026-09-23 23:22:52
7   | OperaSoftware.OperaGXWebBrowser.1783096419    | 2       | 4600.7   | 2026-09-23 21:20:53
8   | C:\Users\prox\Desktop\npcap-installer.exe     | 0       | 0.0      | 2026-09-21 23:17:31
... and 158 older records exported to JSON.
===============================================================================================

[+] Forensic timeline successfully saved to: forensic_execution_timeline.json
```

## ⚖️ License
MIT License. Built for educational and digital forensics / incident response (DFIR) research.
