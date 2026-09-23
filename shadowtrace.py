# ShadowTrace - Windows Program Calistirma ve Kullanici Aktivitesi Adli Bilisim Araci
# TR: Windows Kayit Defteri'ndeki gizli UserAssist (ROT13 sifreli) ve RunMRU (Calistir gecmisi)
# izlerini cozumleyerek hangi programin ne zaman, kac kez ve ne kadar sure kullanildigini tespit eder.

import sys
import os
import winreg
import struct
import codecs
import datetime
import json

# Windows Turkce konsollarinda karakter ve emoji hatalarini onlemek icin UTF-8 yapilandirmasi
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

def filetime_to_dt(ft):
    """
    Windows 64-bit FILETIME (1 Ocak 1601'den bu yana 100-nanosaniyelik adimlar)
    yapilarini okunabilir standart tarih formatina cevirir.
    """
    if ft == 0:
        return "Bilinmiyor / Asla"
    try:
        # 116444736000000000 = 1601 ile 1970 (Unix Epoch) arasindaki 100-ns adim sayisi
        epoch = (ft - 116444736000000000) / 10000000
        return datetime.datetime.fromtimestamp(epoch).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return "Gecersiz Zaman"

def parse_userassist():
    r"""
    UserAssist Artefakti (Adli Kanit):
    Windows Explorer, kullanicinin baslattigi uygulamalari (Start Menu, Explorer, Masaustu)
    HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist
    altinda ROT13 (Sezar sifrelemesi varyanti) ile gizleyerek kaydeder.
    
    Veri yapisi (72 bayt binary):
    - Offset 4: Calistirilma Sayisi (Run Count - DWORD uint32)
    - Offset 8: Odaklanma Sayisi (Focus Count - DWORD uint32)
    - Offset 12: Odaklanma Suresi (Focus Time - DWORD uint32 milisaniye)
    - Offset 60: Son Calistirilma Zamani (Last Execution Time - FILETIME uint64)
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
                
                # ROT13 cozumleme (Orn: 'P:\Jvaqbjf\...' -> 'C:\Windows\...')
                decoded_name = codecs.decode(raw_name, 'rot_13')
                
                # Sistem oturum ve arayuz kayitlarini filtrele
                if "UEME_CTLSESSION" in decoded_name or "UEME_CTLCUACount" in decoded_name:
                    continue
                    
                # 72-baytlik Windows 7-11 binary yapisini parse et
                if len(raw_data) >= 68:
                    run_count = struct.unpack_from('<I', raw_data, 4)[0]
                    focus_count = struct.unpack_from('<I', raw_data, 8)[0]
                    focus_time_ms = struct.unpack_from('<I', raw_data, 12)[0]
                    filetime = struct.unpack_from('<Q', raw_data, 60)[0]
                    
                    last_exec = filetime_to_dt(filetime)
                    
                    # Sadece en az 1 kez calistirilmis veya gecerli tarihi olanlari al
                    if last_exec != "Bilinmiyor / Asla":
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

def parse_run_mru():
    r"""
    RunMRU Artefakti:
    Kullanicinin Windows + R (Calistir) penceresine yazdigi son komutlari
    ve calistirma siralamasini (MRUList) depolar.
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
                # '\1' sonlandirici karakterini temizle
                cleaned_cmd = val.split('\\1')[0] if isinstance(val, str) else str(val)
                entries[name] = cleaned_cmd
                
        # MRU siralamasina gore ekle (en son calistirilan en onde)
        for letter in mru_list:
            if letter in entries:
                mru_evidence.append({
                    "artifact": "RunMRU (Win+R)",
                    "program": f"Run Command: {entries[letter]}",
                    "run_count": "1+",
                    "active_duration_seconds": "N/A",
                    "timestamp": "Recent Session"
                })
        winreg.CloseKey(key)
    except Exception:
        pass
        
    return mru_evidence

def print_timeline_report(records):
    """
    Toplanan tum calistirma kanitlarini zamana gore siralayip DFIR tablosu halinde sunar.
    """
    print("\n" + "="*95)
    print(" [SHADOWTRACE] - WINDOWS PROGRAM CALISTIRMA VE GIZLI KULLANICI AKTIVITE KANITLARI")
    print("="*95)
    
    if not records:
        print("[-] Analiz edilecek calistirma kaniti bulunamadi.")
        return
        
    print(f"[*] Toplam {len(records)} adet program calistirma izi cozumsuzlendi:\n")
    print(f"{'#':<3} | {'Uygulama / Komut':<45} | {'Calisma':<7} | {'Odak(sn)':<8} | {'Son Calistirma':<19}")
    print("-" * 95)
    
    for idx, r in enumerate(records[:35], 1): # Konsolu bogmamak icin ilk 35 en guncel kayit
        prog_name = (r['program'][:42] + '...') if len(r['program']) > 45 else r['program']
        print(f"{idx:<3} | {prog_name:<45} | {str(r['run_count']):<7} | {str(r['active_duration_seconds']):<8} | {r['timestamp']:<19}")
        
    if len(records) > 35:
        print(f"... ve {len(records) - 35} adet daha eski kayit JSON raporuna aktarildi.")
        
    print("="*95)
    
    report_file = "forensic_execution_timeline.json"
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=4, ensure_ascii=False)
    print(f"\n[+] Tam adli analiz raporu basariyla kaydedildi: {report_file}\n")

if __name__ == "__main__":
    ua_records = parse_userassist()
    mru_records = parse_run_mru()
    
    all_records = ua_records + mru_records
    
    # Tarihe gore en yeniden eskiye sirala (Bilinmeyenleri sona at)
    all_records.sort(key=lambda x: x["timestamp"], reverse=True)
    
    print_timeline_report(all_records)
