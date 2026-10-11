"""Exp 01 — IPv4 subnetting verification (Videos 8 + 26).
Verifies claims: /24=256 total/254 usable, /26=64 total/62 usable,
block-size math, network/broadcast derivation. No hand-waving.
Writes results/01_subnet.json
"""
import ipaddress, json, pathlib

def check(cidr, exp_total, exp_usable, exp_net, exp_bcast):
    net = ipaddress.ip_network(cidr, strict=False)
    total = net.num_addresses
    usable = total - 2 if total >= 2 else total
    hosts = list(net.hosts())
    ok = (total==exp_total and usable==exp_usable
          and str(net.network_address)==exp_net
          and str(net.broadcast_address)==exp_bcast)
    return {"cidr":cidr,"total":total,"usable":usable,
            "network":str(net.network_address),"broadcast":str(net.broadcast_address),
            "first_usable":str(hosts[0]) if hosts else None,
            "last_usable":str(hosts[-1]) if hosts else None,
            "expected":{"total":exp_total,"usable":exp_usable},
            "pass":ok}

results = []
results.append(check("192.168.1.0/24",256,254,"192.168.1.0","192.168.1.255"))
results.append(check("192.168.1.0/26",64,62,"192.168.1.0","192.168.1.63"))
results.append(check("192.168.1.64/26",64,62,"192.168.1.64","192.168.1.127"))
results.append(check("192.168.1.128/26",64,62,"192.168.1.128","192.168.1.191"))
results.append(check("192.168.1.192/26",64,62,"192.168.1.192","192.168.1.255"))
# live host check: our observed /28 from `ip addr` (172.20.10.2/28)
live = ipaddress.ip_network("172.20.10.0/28", strict=False)
results.append({"cidr":"172.20.10.0/28 (LIVE observed wlo1)",
                "total":live.num_addresses,"usable":live.num_addresses-2,
                "network":str(live.network_address),
                "broadcast":str(live.broadcast_address),"pass":live.num_addresses==16})

allpass = all(r["pass"] for r in results)
out = {"experiment":"01_subnet","all_pass":allpass,"checks":results}
p = pathlib.Path(__file__).resolve().parents[1]/"results"/"01_subnet.json"
p.parent.mkdir(parents=True,exist_ok=True)
p.write_text(json.dumps(out,indent=2))
print(json.dumps(out,indent=2))
assert allpass, "SUBNET VERIFICATION FAILED"
print("PASS: video 8+26 subnet math verified")
