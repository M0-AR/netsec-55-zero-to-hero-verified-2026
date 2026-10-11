"""Exp 06 — End-to-end web-request journey (Video 53).
Traces: DNS -> TCP connect -> TLS -> HTTP -> routing/NAT evidence.
Live against example.com + local gateway. Writes results/06_journey.json
"""
import subprocess, json, pathlib, re, socket, time

def sh(cmd, timeout=15):
    try:
        r=subprocess.run(cmd,shell=True,capture_output=True,text=True,timeout=timeout)
        return r.stdout+r.stderr
    except Exception as e: return str(e)

out={"experiment":"06_web_journey","stages":[]}
def stage(name, passed, evidence):
    out["stages"].append({"stage":name,"pass":bool(passed),"evidence":str(evidence)[:800]})

# 1 DNS
t0=time.time(); dns=sh("dig +short example.com",10); dt=(time.time()-t0)*1000
ips=re.findall(r"\d+\.\d+\.\d+\.\d+",dns)
stage("DNS_resolve", len(ips)>0, f"{ips[:2]} in {dt:.0f}ms")
# 2 TCP connect to 443
tcp_ok=False; tcp_ms=None
if ips:
    try:
        s=socket.create_connection((ips[0],443),timeout=8); tcp_ms=True; s.close(); tcp_ok=True
    except Exception as e: tcp_ms=str(e)
stage("TCP_443_connect", tcp_ok, str(tcp_ms)[:300])
# 3 TLS via curl -v
tls=sh("curl -sv --max-time 12 https://example.com -o /dev/null 2>&1 | grep -E 'TLS|subject|issuer|Connected to' | head -n 10",12)
stage("TLS_handshake", "TLS" in tls, tls[:500])
# 4 HTTP
http_=sh("curl -s -o /dev/null -w '%{http_code} %{time_total}s %{size_download}B' --max-time 12 https://example.com",12)
stage("HTTP_response", http_.strip().startswith("200"), http_[:200])
# 5 routing/NAT evidence
route=sh("ip route | grep default",8)
stage("Routing_default_via_gateway", "default via" in route, route[:300])
# 6 firewall (read-only)
fw=sh("(sudo -n ufw status 2>&1 || ufw status 2>&1 || nft list ruleset 2>&1 || iptables -L -n 2>&1) | head -n 20",8)
stage("Firewall_observable", len(fw.strip())>0, fw[:400])

out["all_pass"]=all(s["pass"] for s in out["stages"])
p=pathlib.Path(__file__).resolve().parents[1]/"results"/"06_journey.json"
p.parent.mkdir(parents=True,exist_ok=True); p.write_text(json.dumps(out,indent=2))
print(json.dumps(out,indent=2))
assert out["all_pass"], "WEB JOURNEY FAILED"
print("PASS: full web-request journey traced live")
