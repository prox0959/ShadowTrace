# ShadowTrace - Windows Program Execution & User Activity Forensics Tool
# TR: Windows Kayit Defteri'ndeki gizli UserAssist (ROT13) ve RunMRU (Calistir) izlerini cozumler.

import sys
import os
import winreg
import struct
import codecs
import datetime
import json
import argparse

# UTF-8 console output setup for Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

# Multilingual UI Dictionary (EN / TR)
STRINGS = {
    "en": {
        "title": " [SHADOWTRACE] - WINDOWS PROGRAM EXECUTION & FORENSIC ARTIFACTS",
        "no_records": "[-] No execution artifacts found.",
        "found_prefix": "[*] Decoded a total of",
        "found_suffix": "program execution forensic artifacts:\n",
        "col_num": "#",
        "col_prog": "Application / Command",
        "col_runs": "Runs",
        "col_focus": "Focus(s)",
        "col_last": "Last Execution (Local)",
        "more_records": "... and {count} older records exported to JSON.",
        "saved_report": "[+] Forensic timeline successfully saved to:",
        "unknown_time": "Unknown / Never",
        "invalid_time": "Invalid Time",
        "recent_session": "Recent Session"
    },
    "tr": {
        "title": " [SHADOWTRACE] - WINDOWS PROGRAM CALISTIRMA VE GIZLI KULLANICI AKTIVITE KANITLARI",
        "no_records": "[-] Analiz edilecek calistirma kaniti bulunamadi.",
        "found_prefix": "[*] Toplam",
        "found_suffix": "adet program calistirma izi cozumsuzlendi:\n",
        "col_num": "#",
        "col_prog": "Uygulama / Komut",
        "col_runs": "Calisma",
        "col_focus": "Odak(sn)",
        "col_last": "Son Calistirma (Yerel)",
        "more_records": "... ve {count} adet daha eski kayit JSON raporuna aktarildi.",
        "saved_report": "[+] Tam adli analiz raporu basariyla kaydedildi:",
        "unknown_time": "Bilinmiyor / Asla",
        "invalid_time": "Gecersiz Zaman",
        "recent_session": "Guncel Oturum"
    }
}

def filetime_to_dt(ft, lang="en"):
    """
    Translates Windows 64-bit FILETIME (100-ns intervals since Jan 1, 1601) to ISO datetime.
    """
    if ft == 0:
        return STRINGS[lang]["unknown_time"]
    try:
        epoch = (ft - 116444736000000000) / 10000000
        return datetime.datetime.fromtimestamp(epoch).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return STRINGS[lang]["invalid_time"]

def parse_userassist(lang="en"):
    r"""
    UserAssist Artifact Parser:
    Windows Explorer records launched applications under HKCU\...\UserAssist using ROT13.
    Extracts Run Count (DWORD), Focus Duration (DWORD ms), and Last Execution FILETIME.
    """
    evidence = []
    base_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
    
    try:
        ua_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, base_path, 0, winreg.KEY_READ)
    except Exception:
        return evidence

    num_guids = winreg.QueryInfoKey(ua_key)[0]
    
    for i in range(num_guids):
        guid = winreg.EnumKey(ua_key, i)
        count_path = f"{base_path}\\{guid}\\Count"
        
        try:
            count_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, count_path, 0, winreg.KEY_READ)
        except Exception:
            continue
            
        num_values = winreg.QueryInfoKey(count_key)[1]
        
        for v in range(num_values):
            try:
                raw_name, raw_data, _ = winreg.EnumValue(count_key, v)
                decoded_name = codecs.decode(raw_name, 'rot_13')
                
                # Filter out session metadata
                if "UEME_CTLSESSION" in decoded_name or "UEME_CTLCUACount" in decoded_name:
                    continue
                    
                if len(raw_data) >= 68:
                    run_count = struct.unpack_from('<I', raw_data, 4)[0]
                    focus_count = struct.unpack_from('<I', raw_data, 8)[0]
                    focus_time_ms = struct.unpack_from('<I', raw_data, 12)[0]
                    filetime = struct.unpack_from('<Q', raw_data, 60)[0]
                    
                    last_exec = filetime_to_dt(filetime, lang=lang)
                    
                    if last_exec not in [STRINGS["en"]["unknown_time"], STRINGS["tr"]["unknown_time"]]:
                        evidence.append({
                            "artifact": "UserAssist",
                            "program": decoded_name,
                            "run_count": run_count,
                            "active_duration_seconds": round(focus_time_ms / 1000, 1),
                            "timestamp": last_exec
                        })
            except Exception:
                continue
                
        winreg.CloseKey(count_key)
                
    winreg.CloseKey(ua_key)
    return evidence

def parse_run_mru(lang="en"):
    r"""
    RunMRU Artifact Parser:
    Tracks commands executed via Windows + R (Run prompt) and their MRU ordering.
    """
    mru_evidence = []
    run_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
    
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, run_path, 0, winreg.KEY_READ)
    except Exception:
        return mru_evidence
        
    try:
        num_vals = winreg.QueryInfoKey(key)[1]
        mru_list = ""
        entries = {}
        
        for i in range(num_vals):
            name, val, _ = winreg.EnumValue(key, i)
            if name == "MRUList":
                mru_list = val
            else:
                cleaned_cmd = val.split('\\1')[0] if isinstance(val, str) else str(val)
                entries[name] = cleaned_cmd
                
        for letter in mru_list:
            if letter in entries:
                prefix = "Run Komutu:" if lang == "tr" else "Run Command:"
                mru_evidence.append({
                    "artifact": "RunMRU (Win+R)",
                    "program": f"{prefix} {entries[letter]}",
                    "run_count": "1+",
                    "active_duration_seconds": "N/A",
                    "timestamp": STRINGS[lang]["recent_session"]
                })
        winreg.CloseKey(key)
    except Exception:
        pass
        
    return mru_evidence

def print_timeline_report(records, lang="en"):
    """
    Outputs the execution timeline in a DFIR tabular report.
    """
    t = STRINGS[lang]
    print("\n" + "="*95)
    print(t["title"])
    print("="*95)
    
    if not records:
        print(t["no_records"])
        return
        
    print(f"{t['found_prefix']} {len(records)} {t['found_suffix']}")
    print(f"{t['col_num']:<3} | {t['col_prog']:<45} | {t['col_runs']:<7} | {t['col_focus']:<8} | {t['col_last']:<19}")
    print("-" * 95)
    
    for idx, r in enumerate(records[:35], 1):
        prog_name = (r['program'][:42] + '...') if len(r['program']) > 45 else r['program']
        print(f"{idx:<3} | {prog_name:<45} | {str(r['run_count']):<7} | {str(r['active_duration_seconds']):<8} | {r['timestamp']:<19}")
        
    if len(records) > 35:
        print(t["more_records"].format(count=len(records) - 35))
        
    print("="*95)
    
    report_file = "forensic_execution_timeline.json"
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=4, ensure_ascii=False)
    print(f"\n{t['saved_report']} {report_file}\n")

def main():
    parser = argparse.ArgumentParser(description="ShadowTrace - Windows Execution Forensics Analyzer")
    parser.add_argument("-l", "--lang", choices=["en", "tr"], default="en", help="Language for output (en: English, tr: Turkish)")
    args = parser.parse_args()
    
    ua_records = parse_userassist(lang=args.lang)
    mru_records = parse_run_mru(lang=args.lang)
    
    all_records = ua_records + mru_records
    all_records.sort(key=lambda x: x["timestamp"], reverse=True)
    
    print_timeline_report(all_records, lang=args.lang)

if __name__ == "__main__":
    main()
