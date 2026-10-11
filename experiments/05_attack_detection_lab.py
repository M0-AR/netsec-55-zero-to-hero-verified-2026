"""Exp 05 — Attack-signal detection lab, SAFE + LOCAL ONLY (Videos 41-48).
No spoofing/flooding performed. We VALIDATE DETECTORS on:
 (a) live `ip neigh` (ARP stability: duplicate MAC? gateway flip?),
 (b) live DNS answers (does example.com/google.com resolve to sane IPs?),
 (c) synthetic attack traces (ARP flip, DNS hijack, DHCP rogue, SYN-scan burst, DoS volume).
Detectors: arp_flip, dns_anomaly, dhcp_rogue, scan_burst, volume_spike.
Writes results/05_attacks.json
"""
import subprocess, json, pathlib, re, collections

def sh(cmd, timeout=10):
    try:
        r=subprocess.run(cmd,shell=True,capture_output=True,text=True,timeout=timeout)
        return r.stdout+r.stderr
    except Exception as e: return str(e)

out={"experiment":"05_attack_detection","checks":[]}
def add(n,p,e): out["checks"].append({"name":n,"pass":bool(p),"evidence":str(e)[:900]})

# --- LIVE (a) ARP table sanity ---
neigh=sh("ip neigh")
lines=[l for l in neigh.splitlines() if "lladdr" in l]
mac_of_ip={}; mac_counts=collections.Counter()
for l in lines:
    m=re.search(r"(\S+)\s+dev\s+(\S+).*lladdr\s+(\S+)",l)
    if m: mac_of_ip[m.group(1)]=m.group(3).lower(); mac_counts[m.group(3).lower()]+=1
dup_macs=[m for m,c in mac_counts.items() if c>3]
add("LIVE_ARP_no_mass_duplicate_MAC", len(dup_macs)==0, f"entries={len(lines)} dup>{3}:{dup_macs[:3]}")
# gateway MAC stable? just report
gw=sh("ip route | grep default")
add("LIVE_gateway_known", "default via" in gw, gw[:200])

# --- LIVE (b) DNS sanity ---
for dom in ["example.com","google.com"]:
    ans=sh(f"dig +short {dom}", timeout=10)
    ips=re.findall(r"\d+\.\d+\.\d+\.\d+",ans)
    add(f"LIVE_DNS_{dom}_sane", len(ips)>=1, ips[:4])

# --- SYNTHETIC detector unit tests (deterministic) ---
# Detector functions (same logic a defender would deploy)
def detect_arp_flip(before, after):
    flips=[ip for ip in before if ip in after and before[ip]!=after[ip]]
    return flips

def detect_dns(legit_ips, observed_ips):
    return [ip for ip in observed_ips if ip not in legit_ips]

def detect_dhcp(known_server, offers):
    return [o for o in offers if o!=known_server]

def detect_scan(events, threshold=20, window=10):
    # events: list of (t, dst_port); burst if >threshold distinct ports in ANY sliding window
    if not events: return False
    ev=sorted(events)
    for i,(t0,_) in enumerate(ev):
        ports={p for t,p in ev[i:] if t-t0<=window}
        if len(ports)>threshold: return True
    return False

def detect_volume(baseline_pps, observed_pps, factor=5):
    return observed_pps>baseline_pps*factor

# tests
assert detect_arp_flip({"192.168.1.1":"aa:aa"},{"192.168.1.1":"bb:bb"})==["192.168.1.1"]
assert detect_arp_flip({"192.168.1.1":"aa:aa"},{"192.168.1.1":"aa:aa"})==[]
assert detect_dns({"93.184.216.34"},["203.0.113.50"])==["203.0.113.50"]
assert detect_dhcp("192.168.1.1",["192.168.1.1","192.168.1.50"])==["192.168.1.50"]
assert detect_scan([(i*0.2,1000+i) for i in range(30)])==True
assert detect_scan([(i,80) for i in range(30)])==False
assert detect_volume(100,800)==True and detect_volume(100,200)==False
add("SYNTH_detectors_unit_pass", True, "arp/dns/dhcp/scan/volume 7/7 assertions")

# synthetic DoS volume realism: benign 50pps vs attack 800pps
add("SYNTH_DoS_volume_detector", detect_volume(50,800), "50->800pps factor 16x >5x threshold")

out["all_pass"]=all(c["pass"] for c in out["checks"])
p=pathlib.Path(__file__).resolve().parents[1]/"results"/"05_attacks.json"
p.parent.mkdir(parents=True,exist_ok=True); p.write_text(json.dumps(out,indent=2))
print(json.dumps(out,indent=2))
assert out["all_pass"], "ATTACK LAB FAILED"
print("PASS: attack detectors validated (live sane + synth 100% detection on planted signals)")
