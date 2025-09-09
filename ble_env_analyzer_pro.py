#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
BLE Environment Analyzer PRO for Kali Linux
- Multi-adapter support (hci0, hci1, ...)
- btmgmt environment scan
- Parallel bleah GATT-dump
- Optional tshark pcap capture
- Outputs: SUMMARY.md, summary.json, devices.csv, raw logs, *.pcapng
"""

import os
import re
import csv
import json
import time
import shutil
import signal
import socket
import subprocess
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# -------- Config --------
HCI_UP_TIMEOUT_S = 3
SCAN_SECONDS = 30
PCAP_SECONDS = 20
BLEAH_TIMEOUT = 25
MAX_DEVICES_FOR_BLEAH = 60
PARALLEL_BLEAH_WORKERS = 6
OUTPUT_BASE = Path.home() / "ble_scans"
DO_INSTALL = True    # Auto-install on Kali
DO_PCAP = True
# ------------------------

REQUIRED_CMDS = {"hciconfig":"bluez","btmgmt":"bluez","tshark":"tshark","bleah":"bleah"}

def which(x): return shutil.which(x)
def ensure_dir(p: Path): p.mkdir(parents=True, exist_ok=True)
def now_stamp(): return datetime.now().strftime("%Y%m%d_%H%M%S")
def now(): return datetime.now().isoformat(timespec="seconds")

def run_cmd(cmd, timeout=None, cwd=None):
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=cwd, preexec_fn=os.setsid)
        try:
            out, err = p.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgid(p.pid), signal.SIGTERM); time.sleep(0.2)
            try: os.killpg(os.getpgid(p.pid), signal.SIGKILL)
            except Exception: pass
            return 124, "", f"Timeout after {timeout}s: {' '.join(cmd)}"
        return p.returncode, out, err
    except FileNotFoundError:
        return 127, "", f"Command not found: {cmd[0]}"
    except Exception as e:
        return 1, "", f"Exception {e}"

def is_kali():
    try:
        txt = Path("/etc/os-release").read_text(encoding="utf-8").lower()
        return "kali" in txt
    except Exception:
        return False

def apt_install(pkgs, report):
    if not pkgs: return
    run_cmd(["apt-get","update"], timeout=180)
    missing=[]
    for p in pkgs:
        rc,_,_=run_cmd(["dpkg","-s",p])
        if rc!=0: missing.append(p)
    if not missing: return
    rc,out,err=run_cmd(["apt-get","install","-y"]+missing, timeout=900)
    if rc!=0: report["errors"].append(f"apt install failed: {err or out}".strip())
    else: report["notes"].append("Installed: "+", ".join(missing))

def set_tshark_caps(report):
    dumpcap = which("dumpcap")
    if not dumpcap:
        report["notes"].append("dumpcap not found (tshark install incomplete?)."); return
    rc,out,err = run_cmd(["setcap","cap_net_raw,cap_net_admin=eip", dumpcap])
    if rc!=0: report["notes"].append(f"setcap failed or not needed: {(err or out).strip()}")

def list_adapters(report):
    adapters=[]
    base=Path("/sys/class/bluetooth")
    if base.exists():
        adapters=[p.name for p in base.iterdir() if p.name.startswith("hci")]
    if not adapters and which("hciconfig"):
        rc,out,_=run_cmd(["hciconfig"])
        if rc==0:
            adapters=re.findall(r'^(hci\d+):', out, flags=re.MULTILINE) or []
    if not adapters: report["errors"].append("No HCI adapters found.")
    else: report["notes"].append("Adapters: "+", ".join(adapters))
    return adapters

def bring_up(hci, report):
    if not which("hciconfig"): 
        report["errors"].append("hciconfig missing to bring adapter up."); return
    run_cmd(["hciconfig",hci,"down"])
    time.sleep(0.2)
    rc,_,err=run_cmd(["hciconfig",hci,"up"], timeout=HCI_UP_TIMEOUT_S)
    if rc!=0: report["errors"].append(f"{hci} up failed: {err.strip()}")

def adapter_info():
    if not which("hciconfig"): return ""
    rc,out,_=run_cmd(["hciconfig","-a"])
    return out if rc==0 else ""

def btmgmt_find(hci, seconds, logfile, report):
    if not which("btmgmt"):
        report["errors"].append("btmgmt not found.")
        logfile.write_text("btmgmt not found.", encoding="utf-8"); 
        return ""
    p = subprocess.Popen(["btmgmt","-i",hci,"find"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, preexec_fn=os.setsid)
    out_lines, err_lines = [], []
    start=time.time()
    try:
        while True:
            line = p.stdout.readline() if p.stdout else ""
            if line: out_lines.append(line)
            el = p.stderr.readline() if p.stderr else ""
            if el: err_lines.append(el)
            if time.time()-start>seconds:
                os.killpg(os.getpgid(p.pid), signal.SIGINT); time.sleep(0.25); break
            if p.poll() is not None: break
    except Exception:
        try: os.killpg(os.getpgid(p.pid), signal.SIGTERM)
        except Exception: pass
    try:
        o,e = p.communicate(timeout=2)
        if o: out_lines.append(o)
        if e: err_lines.append(e)
    except Exception: pass
    raw="".join(out_lines); err="".join(err_lines)
    logfile.write_text(raw + ("\n# STDERR:\n"+err if err else ""), encoding="utf-8")
    if not raw.strip() and err: report["errors"].append(f"btmgmt {hci} error: {err.strip()}")
    return raw

def parse_btmgmt(raw):
    devices={}
    for line in raw.splitlines():
        if "dev_found:" not in line: continue
        m=re.search(r'([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})', line)
        if not m: continue
        mac=m.group(1).upper()
        mr=re.search(r'\brssi\s(-?\d+)', line); rssi=int(mr.group(1)) if mr else None
        mt=re.search(r'\btype\s(\w+)', line); typ=mt.group(1) if mt else None
        mf=re.search(r'\bflags\s(0x[0-9A-Fa-f]+)', line); flags=mf.group(1) if mf else None
        mn=re.search(r'name\s+"([^"]+)"', line); name=mn.group(1) if mn else None
        d = devices.get(mac, {"mac":mac,"best_rssi":None,"type":typ,"flags":flags,"names":set(),"seen":0})
        d["seen"]+=1
        if rssi is not None and (d["best_rssi"] is None or rssi>d["best_rssi"]): d["best_rssi"]=rssi
        if typ and not d.get("type"): d["type"]=typ
        if flags and not d.get("flags"): d["flags"]=flags
        if name: d["names"].add(name)
        devices[mac]=d
    for d in devices.values():
        d["names"]=sorted(d["names"]) if d["names"] else []
    return list(devices.values())

def bleah_dump(mac, outdir):
    log=outdir/f"bleah_{mac.replace(':','')}.log"
    if not which("bleah"): 
        log.write_text("bleah not available",encoding="utf-8")
        return {"ok":False,"error":"bleah not available","services":[]}
    rc,out,err=run_cmd(["bleah","-U","-d",mac], timeout=BLEAH_TIMEOUT)
    log.write_text(out+("\n# STDERR:\n"+err if err else ""), encoding="utf-8")
    if rc!=0: return {"ok":False,"error":f"rc={rc}: {(err or out).strip()}","services":[]}
    services=[]; service=None
    for line in out.splitlines():
        s=line.strip()
        m=re.match(r'^Service\s+(0x[0-9A-Fa-f]{4})\s*(?:\((.*?)\))?', s)
        if m:
            if service: services.append(service)
            service={"uuid":m.group(1),"name":(m.group(2) or "").strip(),"characteristics":[]}; 
            continue
        m=re.match(r'^Characteristic\s+(0x[0-9A-Fa-f]{4})\s*(?:\((.*?)\))?', s)
        if m and service is not None:
            service["characteristics"].append({"uuid":m.group(1),"name":(m.group(2) or "").strip()})
    if service: services.append(service)
    return {"ok":True,"error":None,"services":services}

def tshark_capture(hci, outpath):
    if not which("tshark"): return False, "tshark not found"
    rc,out,err=run_cmd(["tshark","-i",hci,"-a",f"duration:{PCAP_SECONDS}","-w",str(outpath)], timeout=PCAP_SECONDS+15)
    if rc!=0: return False, (err or out or "").strip()
    return True, str(outpath)

def write_csv(devs, outpath):
    fields=["mac","type","best_rssi","seen","names"]
    with outpath.open("w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f, fieldnames=fields); w.writeheader()
        for d in sorted(devs, key=lambda x:(x.get("best_rssi") or -9999), reverse=True):
            w.writerow({"mac":d["mac"],"type":d.get("type") or "","best_rssi":d.get("best_rssi"),
                        "seen":d.get("seen",0),"names":", ".join(d.get("names",[])) if d.get("names") else ""})

def write_md(outdir, host, adapters, adapter_info, devices_per_adapter, perdev_services, report, pcaps):
    parts=[]
    parts.append(f"# BLE Scan Summary (Kali)\n")
    parts.append(f"- **Host**: `{host}`  \n- **Timestamp**: `{now()}`  \n- **Adapter**: {', '.join(adapters) if adapters else '-'}\n")
    parts.append("## Adapter Info\n```\n"+(adapter_info.strip() or "n/a")+"\n```\n")
    for hci, devs in devices_per_adapter.items():
        parts.append(f"## Gefundene Geräte über `{hci}` ({len(devs)})\n")
        if not devs: parts.append("> Keine Geräte.\n"); continue
        parts.append("| MAC | Typ | Best RSSI | Seen | Namen |\n|---|---:|---:|---:|---|\n")
        for d in sorted(devs,key=lambda x:(x.get('best_rssi') or -9999), reverse=True):
            parts.append(f"| `{d['mac']}` | {d.get('type') or '-'} | {d.get('best_rssi') if d.get('best_rssi') is not None else '-'} | {d.get('seen',0)} | {', '.join(d.get('names',[])) or '-'} |")
        parts.append("")
    parts.append("## Services / Characteristics (aus bleah)\n")
    if not perdev_services:
        parts.append("_bleah nicht verfügbar oder keine Services ermittelt._\n")
    else:
        for mac, srv in perdev_services.items():
            parts.append(f"### {mac}\n")
            if not srv: parts.append("_Keine Services erkannt oder Fehler._\n"); continue
            for s in srv:
                sname=s.get('name') or ""
                parts.append(f"- **Service {s.get('uuid')}** {f'({sname})' if sname else ''}")
                for c in s.get('characteristics') or []:
                    cname=c.get('name') or ""
                    parts.append(f"  - Characteristic {c.get('uuid')} {f'({cname})' if cname else ''}")
            parts.append("")
    parts.append("## Tool-/Fehlerreport\n```json\n"+json.dumps(report,indent=2,ensure_ascii=False)+"\n```\n")
    if pcaps:
        parts.append("## Mitschnitte\n")
        for hci, p in pcaps.items(): parts.append(f"- `{hci}` → `{p}`")
    (outdir/"SUMMARY.md").write_text("\n".join(parts), encoding="utf-8")

def main():
    # prepare output
    ensure_dir(OUTPUT_BASE)
    outdir = OUTPUT_BASE / now_stamp()
    ensure_dir(outdir)

    host = socket.gethostname()
    report={"errors":[], "notes":[], "tools":{k:bool(which(k)) for k in REQUIRED_CMDS}}

    # auto-install on Kali (needs sudo/root). If not root, we just skip.
    if is_kali() and os.geteuid()==0:
        need=[]
        for c,pkg in REQUIRED_CMDS.items():
            if not which(c): need.append(pkg)
        need=sorted(set(need))
        if need: apt_install(need, report); set_tshark_caps(report)

    adapters = list_adapters(report)
    for hci in adapters: bring_up(hci, report)
    adp_info = adapter_info()
    (outdir/"hciconfig.log").write_text(adp_info, encoding="utf-8")

    devices_per_adapter={}
    unique={}
    for hci in (adapters or ["hci0"]):
        raw = btmgmt_find(hci, SCAN_SECONDS, outdir/f"btmgmt_find_{hci}.log", report)
        devs = parse_btmgmt(raw)
        devices_per_adapter[hci]=devs
        for d in devs:
            mac=d["mac"]
            if mac not in unique: unique[mac]=d
            else:
                cur=unique[mac]
                if d.get("best_rssi") is not None and (cur.get("best_rssi") is None or d["best_rssi"]>cur["best_rssi"]):
                    cur["best_rssi"]=d["best_rssi"]
                if d.get("type") and not cur.get("type"): cur["type"]=d["type"]
                if d.get("flags") and not cur.get("flags"): cur["flags"]=d["flags"]
                cur["seen"]=cur.get("seen",0)+d.get("seen",0)
                names=set(cur.get("names",[])); names.update(d.get("names",[])); cur["names"]=sorted(names)

    merged = sorted(unique.values(), key=lambda x:(x.get("best_rssi") or -9999), reverse=True)
    (outdir/"devices.csv").write_text("", encoding="utf-8")  # ensure file exists before write_csv
    # CSV write
    with (outdir/"devices.csv").open("w", newline="", encoding="utf-8") as f:
        w=csv.DictWriter(f, fieldnames=["mac","type","best_rssi","seen","names"]); w.writeheader()
        for d in merged:
            w.writerow({"mac":d["mac"],"type":d.get("type") or "","best_rssi":d.get("best_rssi"),
                        "seen":d.get("seen",0),"names":", ".join(d.get("names",[])) if d.get("names") else ""})

    perdev_services={}
    if which("bleah") and merged:
        targets = merged[:MAX_DEVICES_FOR_BLEAH]
        with ThreadPoolExecutor(max_workers=PARALLEL_BLEAH_WORKERS) as ex:
            fut2mac = {ex.submit(bleah_dump, d["mac"], outdir): d["mac"] for d in targets}
            for fut in as_completed(fut2mac):
                mac=fut2mac[fut]
                try:
                    res=fut.result()
                except Exception as e:
                    report["errors"].append(f"bleah {mac} exception: {e}"); res={"services":[]}
                perdev_services[mac]=res.get("services", [])
    else:
        for d in merged[:MAX_DEVICES_FOR_BLEAH]:
            (outdir/f"bleah_{d['mac'].replace(':','')}.log").write_text("bleah not available", encoding="utf-8")

    pcaps={}
    if DO_PCAP and which("tshark"):
        for hci in (adapters or ["hci0"]):
            p = outdir/f"capture_{hci}.pcapng"
            ok,msg = tshark_capture(hci, p)
            if ok: pcaps[hci]=str(p)
            else: report["notes"].append(f"tshark on {hci}: {msg}")

    summary = {
        "host": host, "timestamp": now(), "adapters": adapters,
        "devices_per_adapter": devices_per_adapter, "devices_merged_sorted": merged,
        "services": perdev_services, "pcaps": pcaps, "tools": report
    }
    (outdir/"summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    write_md(outdir, host, adapters, adp_info, devices_per_adapter, perdev_services, report, pcaps)
    print(f"[OK] BLE scan complete → {outdir}")

if __name__=="__main__":
    main()
