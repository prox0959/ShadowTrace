# 🕵️‍♂️ ShadowTrace

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=for-the-badge&logo=windows)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

**A lightweight Windows program execution forensics & activity timeline extraction tool.**

</div>

---

## 🔍 What is ShadowTrace?

In Windows incident response and digital forensics (DFIR), investigating whether a suspect executed malicious software (e.g., malware, credential dumpers, or unauthorized apps) is critical. Even if an attacker deletes an executable from the filesystem, Windows maintains silent execution artifacts in the Registry.

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
- 🔓 **ROT13 Decryption:** Automatically decodes obfuscated UserAssist registry values.
- ⏱️ **Timestamp & Duration Decoding:** Translates 64-bit Windows `FILETIME` and microsecond focus times into human-readable timelines.
- 📋 **DFIR JSON Reporting:** Exports a forensic timeline report (`forensic_execution_timeline.json`) ready for timeline analysis and ingestion into SIEM tools.

## 🚀 Usage

```bash
# Clone the repository
git clone https://github.com/prox0959/ShadowTrace.git
cd ShadowTrace

# Run directly (No pip install needed!)
python shadowtrace.py
```

## 📊 Sample Output

```text
===============================================================================================
 [SHADOWTRACE] - WINDOWS PROGRAM CALISTIRMA VE GIZLI KULLANICI AKTIVITE KANITLARI
===============================================================================================
[*] Toplam 193 adet program calistirma izi cozumsuzlendi:

#   | Uygulama / Komut                              | Calisma | Odak(sn) | Son Calistirma     
-----------------------------------------------------------------------------------------------
1   | Run Command: cmd                              | 1+      | N/A      | Recent Session     
2   | Microsoft.VisualStudioCode                    | 3       | 82.4     | 2026-09-24 00:42:55
3   | SpotifyAB.SpotifyMusic                        | 2       | 789.6    | 2026-09-24 00:11:21
4   | OperaSoftware.OperaGXWebBrowser               | 2       | 4600.7   | 2026-09-23 21:20:53
5   | C:\Users\prox\Desktop\npcap-installer.exe     | 0       | 0.0      | 2026-09-21 23:17:31
...
===============================================================================================
[+] Tam adli analiz raporu basariyla kaydedildi: forensic_execution_timeline.json
```

## ⚖️ License
MIT License. Built for educational and digital forensics / incident response (DFIR) research.
