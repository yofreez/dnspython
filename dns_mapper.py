
import ipaddress
import dns.resolver
import dns.reversename
import argparse
import re 
import tldextract




def banner():
    print("""
====================================
           DNS MAPPER
====================================
""")

def resolve(domain, rtype):
    try:
        return dns.resolver.resolve(domain, rtype)
    except Exception:
        return []

def resolve_ips(domain):
    return {
        r.to_text()
        for t in ("A", "AAAA")
        for r in resolve(domain, t)
    }

def reverse_dns(ip):
    try:
        rev = dns.reversename.from_address(ip)
        return dns.resolver.resolve(rev, "PTR")[0].to_text().rstrip(".")
    except Exception:
        return None
    


#---------------------------
# Strategies de récup 
# -------------------------
def scan_ip_neighbors(ip):
    try:
        a = ipaddress.ip_address(ip)
        return [reverse_dns(str(a + d))
                 for d in (-1,1) 
                      if reverse_dns(str(a + d))]
    except: return []

def scan_srv(domain):
    services = ["_sip._tcp","_sip._udp","_ldap._tcp","_xmpp-server._tcp"]
    return {r.target.to_text().rstrip(".") for srv in services for r in resolve(f"{srv}.{domain}","SRV")}

def scan_mx(domain):
    return {r.exchange.to_text().rstrip(".") for r in resolve(domain,"MX")}

def parse_txt(domain):
    raw_txt = []
    extracted = set()
    pattern = r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"

    for r in resolve(domain, "TXT"):
        txt = r.to_text()
        raw_txt.append(txt)
        for match in re.findall(pattern, txt):
            extracted.add(match)

    return raw_txt, extracted



def enumerate_subdomains(domain):
    words = ["www","api","mail","shop","news","community"]
    return {f"{w}.{domain}" for w in words if resolve(f"{w}.{domain}","A") or resolve(f"{w}.{domain}","AAAA")}

def get_parent_domains(domain):
    ext = tldextract.extract(domain)
    if not ext.suffix or not ext.domain:
        return set()
    registered_domain = f"{ext.domain}.{ext.suffix}"
    parents = set()
    if domain == registered_domain:
        return parents

    if ext.subdomain:
        parts = ext.subdomain.split(".")
        current_suffix = registered_domain
        for part in reversed(parts):
            parent_candidate = f"{part}.{current_suffix}"
            if parent_candidate != domain:
                parents.add(parent_candidate)
            current_suffix = parent_candidate

    return parents



# -------------------------
# Graphviz 
# -------------------------
def export_graphviz(file, domain, data):
    with open(file,"w") as f:
        f.write("digraph DNS {\n rankdir=LR; node [fontname=Helvetica];\n")
        for k,shape in [("domains","ellipse"),("ips","box"),("parents","diamond")]:
            for n in data[k]: f.write(f' "{n}" [shape={shape}];\n')
        for ip in data["ips"]:
            f.write(f' "{domain}" -> "{ip}" [label="A/AAAA"];\n')
            if ip in data["reverse"]: f.write(f' "{ip}" -> "{data["reverse"][ip]}" [label="PTR"];\n')
            for n in data["neighbors"].get(ip,[]): f.write(f' "{ip}" -> "{n}" [label="neighbor"];\n')
        for s in data["srv"]: f.write(f' "{domain}" -> "{s}" [label="SRV"];\n')
        for s in data["subdomains"]: f.write(f' "{domain}" -> "{s}" [label="subdomain"];\n')
        for p in data["parents"]: f.write(f' "{domain}" -> "{p}" [label="parent"];\n')
        f.write("}\n")



#---------------------------
# main
# -------------------------


def main():
    banner()

    parser = argparse.ArgumentParser(description="DNS cartography tool")
    parser.add_argument("domain", nargs="?", help="Domain to analyze")
    parser.add_argument("--graphviz", help=".dot output")
    # Note: ces arguments sont déclarés mais non utilisés dans la logique,
    parser.add_argument("--ip","--reverse","--neighbors",
                        "--domains","--parents","--subdomains","--srv",
                        action="store_true")
    args = parser.parse_args()

    # recup le domaine 
    domain = args.domain
    if not domain:
        domain = input("Entrez le domaine à découvrir : ").strip()
        if not domain:
            print("[-] Aucun domaine fourni, arrêt.")
            return

    # regroupe tt les résultats
    results = {
        "ips": resolve_ips(domain),
        "reverse": {},
        "neighbors": {},
        "domains": set(),
        "subdomains": enumerate_subdomains(domain),
        "srv": scan_srv(domain),
        "parents": set(),
    }


    # Reverse + voisins
    for ip in results["ips"]:
        rdns = reverse_dns(ip)
        if rdns: results["reverse"][ip] = rdns
        results["neighbors"][ip] = scan_ip_neighbors(ip)

   # Domains (MX + SRV + TXT)
    results["domains"].update(scan_mx(domain))
    results["domains"].update(results["srv"])

    txt_raw, txt_extracted = parse_txt(domain)
    results["domains"].update(txt_extracted)


    # Parent domains
    # On scanne les parents de tout ce qu'on a trouvé
    full_list = results["domains"].union(results["subdomains"]).union({domain})
    for d in full_list:
        results["parents"].update(get_parent_domains(d))




#---------------------------
# sortie 
# -------------------------
    print(f"\n[*] DNS cartography for {domain}\n")
    for section, items in [("IPs",results["ips"]),("Reverse DNS",results["reverse"].values()),
                           ("IP neighbors",[n for ns in results["neighbors"].values() for n in ns]),
                           ("Domains discovered",results["domains"]),("Parent Domains",results["parents"]),
                           ("Subdomains",results["subdomains"]),("SRV",results["srv"])]:
        if items:
            print(f"=== {section} ===")
            for x in sorted(items): print(x)
            print()


    # Graphviz export if requested
    if args.graphviz:
        export_graphviz(args.graphviz, domain, results)
        print(f"[+] Graphviz file generated: {args.graphviz}")



if __name__ == "__main__":
    main()
