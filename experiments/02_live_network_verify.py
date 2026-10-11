"""Exp 02 — Live network verification (Videos 1-7,9-10,13-15,20-24).
Runs ONLY read-only commands on own host + public internet.
Asserts: interfaces exist, private IP detected, gateway reachable,
DNS resolves, ping works, ports observed, neighbour table non-empty.
Writes results/02_live.json
"""
import subprocess, json, pathlib, re, ipaddress

def sh(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip() + r.stderr.strip(), r.returncode
    except Exception as e:
        return str(e), 1

out = {"experiment":"02_live_network","checks":[]}
def add(name, passed, evidence):
    out["checks"].append({"name":name,"pass":bool(passed),"evidence":str(evidence)[:800]})

# V1: interfaces
ipaddr, _ = sh("ip addr")
add("V01_interfaces_exist", "inet " in ipaddr and "lo:" in ipaddr, ipaddr[:500])
# V5 MAC present
add("V05_MAC_link_ether", "link/ether" in ipaddr, re.findall(r"link/ether \S+", ipaddr)[:5])
# V6/V7 private IP
m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/\d+", ipaddr)
priv = False; priv_ip = None
if m:
    priv_ip = m.group(1)
    try:
        priv = ipaddress.ip_address(priv_ip).is_private
    except: pass
add("V06_V07_private_IP_detected", priv, f"first inet={priv_ip} is_private={priv}")
# V23/V20 gateway
route, _ = sh("ip route")
gw = re.search(r"default via (\S+)", route)
add("V20_V23_default_gateway_present", bool(gw), gw.group(0) if gw else route[:400])
# V24 ping gateway + 8.8.8.8
if gw:
    gwip = gw.group(1)
    pg, code = sh(f"ping -c2 -W2 {gwip}", timeout=10)
    add("V24_ping_gateway", "bytes from" in pg.lower(), pg[:400])
else:
    add("V24_ping_gateway", False, "no gateway")
p8, _ = sh("ping -c2 -W3 8.8.8.8", timeout=12)
add("V24_ping_8888", "bytes from" in p8.lower(), p8[:400])
# V13 DNS
d, _ = sh("dig +short google.com", timeout=10)
add("V13_DNS_resolves", bool(re.search(r"\d+\.\d+\.\d+\.\d+", d)), d[:300])
# V9/V10/V33 ports
ss, _ = sh("ss -tln", timeout=10)
add("V09_V33_listening_TCP_observed", "LISTEN" in ss, ss[:500])
# V15 ARP/neigh
neigh, _ = sh("ip neigh", timeout=10)
add("V15_ARP_neigh_table", ("lladdr" in neigh or "REACHABLE" in neigh or "STALE" in neigh), neigh[:500])
# V6 IPv6 present?
add("V06_IPv6_present", "inet6" in ipaddr, re.findall(r"inet6 \S+", ipaddr)[:5])

out["all_pass"] = all(c["pass"] for c in out["checks"])
p = pathlib.Path(__file__).resolve().parents[1]/"results"/"02_live.json"
p.parent.mkdir(parents=True,exist_ok=True)
p.write_text(json.dumps(out,indent=2))
print(json.dumps(out,indent=2))
assert out["all_pass"], "LIVE NETWORK VERIFICATION FAILED — see evidence"
print("PASS: live network claims verified")
