
import ipaddress
import dns.resolver
import dns.reversename
import dns.rdatatype
import argparse
import re 
import tldextract
from collections import defaultdict




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

def scan_ns(domain):
    return {r.to_text().rstrip(".") for r in resolve(domain,"NS")}

def scan_cname(domain):
    return {r.to_text().rstrip(".") for r in resolve(domain,"CNAME")}

def scan_soa(domain):
    try:
        return [r.to_text().rstrip(".") for r in resolve(domain,"SOA")]
    except: return []

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
    # Liste étendue de subdomains communs
    words = [
        "www","api","mail","shop","news","community",
        "admin","dashboard","dev","test","staging","prod","production",
        "app","web","backend","frontend","mobile","api-v1","api-v2",
        "blog","cdn","static","assets","images","files","download",
        "ftp","sftp","vpn","remote","secure",
        "mail","smtp","pop","imap","webmail",
        "dns","ns1","ns2","mx","ns",
        "git","gitlab","github","bitbucket",
        "jenkins","ci","cd","deploy",
        "monitor","metrics","logs","elastic","kibana",
        "db","database","mysql","postgres","mongo",
        "cache","redis","memcache",
        "auth","oauth","sso","ldap",
        "support","help","docs","documentation","wiki",
        "portal","panel","control","console",
        "internal","intranet","private",
        "legacy","old","archive","backup",
        "status","health","ping","heartbeat",
        "config","settings","preferences",
        "upload","download","share","sync"
    ]
    found = set()
    for w in words:
        subdomain = f"{w}.{domain}"
        try:
            if resolve(subdomain,"A") or resolve(subdomain,"AAAA"):
                found.add(subdomain)
        except:
            pass
    return found

def filter_interesting_data(all_data, base_domain):
    """
    Filtre les données intéressantes des résultats bruts.
    Supprime les doublons et les entrées peu pertinentes.
    """
    ext = tldextract.extract(base_domain)
    base_registered = f"{ext.domain}.{ext.suffix}" if ext.domain else base_domain
    
    filtered = {
        "ips": set(),
        "reverse_dns": {},
        "subdomains": set(),
        "domains_discovered": set(),
        "mx_records": set(),
        "ns_records": set(),
        "srv_records": set(),
        "cname_records": set(),
        "parent_domains": set(),
        "ip_neighbors": set(),
    }
    
    # Filtrer les IPs
    for ip in all_data.get("ips", []):
        try:
            ipobj = ipaddress.ip_address(ip)
            # Éviter localhost et private ranges trop évidentes
            if not ipobj.is_loopback:
                filtered["ips"].add(ip)
        except:
            pass
    
    # Filtrer les reverse DNS
    for ip, rdns in all_data.get("reverse", {}).items():
        if rdns and rdns not in ["localhost", "localhost.localdomain"]:
            filtered["reverse_dns"][ip] = rdns
    
    # Filtrer les subdomains (uniquement ceux du domaine principal)
    for subdomain in all_data.get("subdomains", []):
        if subdomain.endswith(base_registered):
            filtered["subdomains"].add(subdomain)
    
    # Filtrer les domaines découverts (peu pertinents pour le filtrage)
    filtered["domains_discovered"] = all_data.get("domains", set())
    
    # Ajouter les autres records
    filtered["mx_records"] = all_data.get("mx", set())
    filtered["ns_records"] = all_data.get("ns", set())
    filtered["srv_records"] = all_data.get("srv", set())
    filtered["cname_records"] = all_data.get("cname", set())
    filtered["parent_domains"] = all_data.get("parents", set())
    
    # Nettoyer les voisins d'IP
    all_neighbors = all_data.get("neighbors", {})
    for ip_neighbors in all_neighbors.values():
        filtered["ip_neighbors"].update(ip_neighbors if ip_neighbors else [])
    
    return filtered

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
    parser.add_argument("--raw", action="store_true", help="Show all raw data before filtering")
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

    print(f"\n[*] Collecting data for {domain}...")
    
    # ==========================================
    # PHASE 1: COLLECTE MASSIVE DE DONNEES
    # ==========================================
    raw_results = {
        "ips": resolve_ips(domain),
        "reverse": {},
        "neighbors": {},
        "domains": set(),
        "subdomains": enumerate_subdomains(domain),
        "srv": scan_srv(domain),
        "mx": scan_mx(domain),
        "ns": scan_ns(domain),
        "cname": scan_cname(domain),
        "soa": scan_soa(domain),
        "parents": set(),
    }

    print(f"[+] Found {len(raw_results['ips'])} IP address(es)")
    print(f"[+] Found {len(raw_results['subdomains'])} subdomain(s)")
    print(f"[+] Found {len(raw_results['mx'])} MX record(s)")
    print(f"[+] Found {len(raw_results['ns'])} NS record(s)")
    print(f"[+] Found {len(raw_results['srv'])} SRV record(s)")

    # Reverse DNS + voisins d'IP
    for ip in raw_results["ips"]:
        rdns = reverse_dns(ip)
        if rdns: raw_results["reverse"][ip] = rdns
        neighbors = scan_ip_neighbors(ip)
        if neighbors:
            raw_results["neighbors"][ip] = neighbors

    # Domains (MX + SRV + TXT)
    raw_results["domains"].update(raw_results["mx"])
    raw_results["domains"].update(raw_results["srv"])
    raw_results["domains"].update(raw_results["cname"])

    txt_raw, txt_extracted = parse_txt(domain)
    raw_results["domains"].update(txt_extracted)
    print(f"[+] Found {len(raw_results['domains'])} discovered domain(s) via MX/SRV/TXT")

    # Parent domains
    full_list = raw_results["domains"].union(raw_results["subdomains"]).union({domain})
    for d in full_list:
        raw_results["parents"].update(get_parent_domains(d))

    print(f"[+] Found {len(raw_results['parents'])} parent domain(s)")

    # ==========================================
    # PHASE 2: AFFICHAGE DES DONNEES BRUTES (optionnel)
    # ==========================================
    if args.raw:
        print(f"\n{'='*60}")
        print("DONNEES BRUTES COLLECTEES")
        print(f"{'='*60}\n")
        for section, items in [("IPs",raw_results["ips"]),("Reverse DNS",raw_results["reverse"].values()),
                               ("IP neighbors",[n for ns in raw_results["neighbors"].values() for n in ns]),
                               ("MX",raw_results["mx"]),("NS",raw_results["ns"]),
                               ("SRV",raw_results["srv"]),("CNAME",raw_results["cname"]),
                               ("Domains discovered",raw_results["domains"]),("Parent Domains",raw_results["parents"]),
                               ("Subdomains",raw_results["subdomains"])]:
            if items:
                print(f"=== {section} ===")
                for x in sorted(items): print(f"  {x}")
                print()

    # ==========================================
    # PHASE 3: FILTRAGE INTELLIGENT
    # ==========================================
    print(f"\n[*] Filtering data...")
    filtered_results = filter_interesting_data(raw_results, domain)

    # ==========================================
    # PHASE 4: AFFICHAGE FINAL
    # ==========================================
    print(f"\n{'='*60}")
    print(f"DNS CARTOGRAPHY FOR {domain.upper()}")
    print(f"{'='*60}\n")
    
    # Tableau récapitulatif
    print("\n[SUMMARY]")
    print(f"  • IP Addresses: {len(filtered_results['ips'])}")
    print(f"  • Subdomains: {len(filtered_results['subdomains'])}")
    print(f"  • MX Records: {len(filtered_results['mx_records'])}")
    print(f"  • NS Records: {len(filtered_results['ns_records'])}")
    print(f"  • SRV Records: {len(filtered_results['srv_records'])}")
    print(f"  • Parent Domains: {len(filtered_results['parent_domains'])}")
    print(f"  • Total Discovered: {len(filtered_results['domains_discovered'])}")
    print()
    
    # Affichage détaillé
    sections = [
        ("IPv4/IPv6 ADDRESSES", filtered_results["ips"]),
        ("REVERSE DNS", list(filtered_results["reverse_dns"].values())),
        ("SUBDOMAINS", filtered_results["subdomains"]),
        ("MX RECORDS", filtered_results["mx_records"]),
        ("NS RECORDS", filtered_results["ns_records"]),
        ("SRV RECORDS", filtered_results["srv_records"]),
        ("CNAME RECORDS", filtered_results["cname_records"]),
        ("PARENT DOMAINS", filtered_results["parent_domains"]),
        ("DISCOVERED DOMAINS (via TXT/MX/SRV)", filtered_results["domains_discovered"]),
    ]
    
    for section_name, items in sections:
        if items:
            print(f"\n[{section_name}] ({len(items)} found)")
            for x in sorted(items):
                print(f"  • {x}")

    # Graphviz export if requested
    if args.graphviz:
        export_graphviz(args.graphviz, domain, filtered_results)
        print(f"\n[+] Graphviz file generated: {args.graphviz}")
    else:
        # Génération automatique du graphviz
        graphviz_file = f"{domain.replace('.', '_')}_diagram.dot"
        export_graphviz(graphviz_file, domain, filtered_results)
        print(f"\n[+] Graphviz file auto-generated: {graphviz_file}")



if __name__ == "__main__":
    main()
