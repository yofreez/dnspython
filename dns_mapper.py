import ipaddress
import dns.resolver
import dns.reversename
import dns.rdatatype
import argparse
import re
import tldextract
from collections import defaultdict
import subprocess
import sys


def banner():
    print("""
====================================
           DNS MAPPER
====================================
""")


def resolve(domain, rtype):
    try:
        return dns.resolver.resolve(domain, rtype)
    except:
        return []


def resolve_ips(domain):
    return {r.to_text() for t in ("A", "AAAA") for r in resolve(domain, t)}


def reverse_dns(ip):
    try:
        rev = dns.reversename.from_address(ip)
        return dns.resolver.resolve(rev, "PTR")[0].to_text().rstrip(".")
    except:
        return None


def scan_ip_neighbors(ip):
    try:
        a = ipaddress.ip_address(ip)
        return [reverse_dns(str(a + d)) for d in (-1, 1) if reverse_dns(str(a + d))]
    except:
        return []


def scan_srv(domain):
    services = ["_sip._tcp", "_sip._udp", "_ldap._tcp", "_xmpp-server._tcp"]
    return {r.target.to_text().rstrip(".") for srv in services for r in resolve(f"{srv}.{domain}", "SRV")}


def scan_mx(domain):
    return {r.exchange.to_text().rstrip(".") for r in resolve(domain, "MX")}


def scan_ns(domain):
    return {r.to_text().rstrip(".") for r in resolve(domain, "NS")}


def scan_cname(domain):
    return {r.to_text().rstrip(".") for r in resolve(domain, "CNAME")}


def scan_soa(domain):
    try:
        return [r.to_text().rstrip(".") for r in resolve(domain, "SOA")]
    except:
        return []


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
    words = [
        "www",
        "api",
        "mail",
        "shop",
        "news",
        "community",
        "admin",
        "dashboard",
        "dev",
        "test",
        "staging",
        "prod",
        "production",
        "app",
        "web",
        "backend",
        "frontend",
        "mobile",
        "api-v1",
        "api-v2",
        "blog",
        "cdn",
        "static",
        "assets",
        "images",
        "files",
        "download",
        "ftp",
        "sftp",
        "vpn",
        "remote",
        "secure",
        "smtp",
        "pop",
        "imap",
        "webmail",
        "dns",
        "ns1",
        "ns2",
        "mx",
        "ns",
        "git",
        "gitlab",
        "github",
        "bitbucket",
        "jenkins",
        "ci",
        "cd",
        "deploy",
        "monitor",
        "metrics",
        "logs",
        "elastic",
        "kibana",
        "db",
        "database",
        "mysql",
        "postgres",
        "mongo",
        "cache",
        "redis",
        "memcache",
        "auth",
        "oauth",
        "sso",
        "ldap",
        "support",
        "help",
        "docs",
        "documentation",
        "wiki",
        "portal",
        "panel",
        "control",
        "console",
        "internal",
        "intranet",
        "private",
        "legacy",
        "old",
        "archive",
        "backup",
        "status",
        "health",
        "ping",
        "heartbeat",
        "config",
        "settings",
        "preferences",
        "upload",
        "share",
        "sync",
    ]
    found = set()
    for w in words:
        try:
            if resolve(f"{w}.{domain}", "A") or resolve(f"{w}.{domain}", "AAAA"):
                found.add(f"{w}.{domain}")
        except:
            pass
    return found


def filter_interesting_data(all_data, base_domain):
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

    for ip in all_data.get("ips", []):
        try:
            if not ipaddress.ip_address(ip).is_loopback:
                filtered["ips"].add(ip)
        except:
            pass

    for ip, rdns in all_data.get("reverse", {}).items():
        if rdns and rdns not in ["localhost", "localhost.localdomain"]:
            filtered["reverse_dns"][ip] = rdns

    for subdomain in all_data.get("subdomains", []):
        if subdomain.endswith(base_registered):
            filtered["subdomains"].add(subdomain)

    filtered["domains_discovered"] = all_data.get("domains", set())
    filtered["mx_records"] = all_data.get("mx", set())
    filtered["ns_records"] = all_data.get("ns", set())
    filtered["srv_records"] = all_data.get("srv", set())
    filtered["cname_records"] = all_data.get("cname", set())
    filtered["parent_domains"] = all_data.get("parents", set())

    for ip_neighbors in all_data.get("neighbors", {}).values():
        filtered["ip_neighbors"].update(ip_neighbors if ip_neighbors else [])

    return filtered


def get_parent_domains(domain):
    ext = tldextract.extract(domain)
    if not ext.suffix or not ext.domain:
        return set()
    registered_domain = f"{ext.domain}.{ext.suffix}"
    parents = set()
    if domain == registered_domain or not ext.subdomain:
        return parents
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
def find_graphviz():
    """Trouve le chemin vers dot.exe"""
    possible_paths = [
        "dot",
        r"C:\Program Files\Graphviz\bin\dot.exe",
        r"C:\Program Files (x86)\Graphviz\bin\dot.exe",
        r"C:\Program Files\Graphviz 2.46\bin\dot.exe",
        r"C:\Program Files\Graphviz 2.47\bin\dot.exe",
        r"C:\Program Files\Graphviz 2.48\bin\dot.exe",
        r"C:\Program Files\Graphviz 2.49\bin\dot.exe",
    ]

    for path in possible_paths:
        try:
            subprocess.run([path, "-V"], capture_output=True, timeout=2, check=False)
            return path
        except:
            continue

    return None


def export_graphviz(file, domain, data):
    with open(file, "w") as f:
        f.write("""digraph DNS {
    rankdir=TB;
    graph [bgcolor=white, fontname="Arial"];
    node [fontname="Arial", fontsize=10, shape=box, style=rounded, fillcolor=lightblue];
    edge [fontsize=8];
    
""")

        # Nœud principal
        f.write(f'    main [label="{domain}", fillcolor="#4A90E2", fontcolor=white, fontsize=12, fontweight=bold];\n\n')

        # IPs
        for ip in sorted(data.get("ips", [])):
            node_id = f"ip_{ip.replace('.', '_').replace(':', '_')}"
            f.write(f'    {node_id} [label="{ip}", fillcolor="#FFD4D4"];\n')
            f.write(f'    main -> {node_id} [label="A/AAAA"];\n')

        # Subdomains
        for sub in sorted(data.get("subdomains", [])):
            node_id = f"sub_{sub.replace('.', '_')}"
            f.write(f'    {node_id} [label="{sub}", fillcolor="#D4FFD4"];\n')
            f.write(f'    main -> {node_id} [label="subdomain"];\n')

        # MX Records
        for mx in sorted(data.get("mx_records", [])):
            node_id = f"mx_{mx.replace('.', '_')}"
            f.write(f'    {node_id} [label="{mx}", fillcolor="#FFFFD4"];\n')
            f.write(f'    main -> {node_id} [label="MX"];\n')

        # NS Records
        for ns in sorted(data.get("ns_records", [])):
            node_id = f"ns_{ns.replace('.', '_')}"
            f.write(f'    {node_id} [label="{ns}", fillcolor="#FFE8D4"];\n')
            f.write(f'    main -> {node_id} [label="NS"];\n')

        # SRV Records
        for srv in sorted(data.get("srv_records", [])):
            node_id = f"srv_{srv.replace('.', '_')}"
            f.write(f'    {node_id} [label="{srv}", fillcolor="#D4F4FF"];\n')
            f.write(f'    main -> {node_id} [label="SRV"];\n')

        # CNAME Records
        for cname in sorted(data.get("cname_records", [])):
            node_id = f"cname_{cname.replace('.', '_')}"
            f.write(f'    {node_id} [label="{cname}", fillcolor="#FFD4FF", shape=ellipse];\n')
            f.write(f'    main -> {node_id} [label="CNAME"];\n')

        # Parent Domains
        for parent in sorted(data.get("parent_domains", [])):
            node_id = f"parent_{parent.replace('.', '_')}"
            f.write(f'    {node_id} [label="{parent}", fillcolor="#FFA0A0", shape=diamond];\n')
            f.write(f'    main -> {node_id} [label="parent", style=dashed];\n')

        # Reverse DNS
        for ip, rdns in sorted(data.get("reverse_dns", {}).items()):
            ip_node = f"ip_{ip.replace('.', '_').replace(':', '_')}"
            rdns_node = f"rdns_{ip.replace('.', '_').replace(':', '_')}"
            f.write(f'    {rdns_node} [label="{rdns}", fillcolor="#D4E8FF", shape=ellipse];\n')
            f.write(f'    {ip_node} -> {rdns_node} [label="PTR"];\n')

        f.write("}\n")

    # Convertir automatiquement en JPG
    dot_cmd = find_graphviz()
    if dot_cmd:
        jpg_file = file.replace(".dot", ".jpg")
        try:
            subprocess.run(
                [dot_cmd, "-Tjpg", file, "-o", jpg_file],
                check=True,
                capture_output=True,
                timeout=10,
            )
            print(f"[+] JPG generated: {jpg_file}")
            return jpg_file
        except Exception as e:
            print(f"[!] Error converting to JPG: {e}")
            return None
    else:
        print("[!] Graphviz not found - JPG conversion skipped")
        print("[!] Download from: https://graphviz.org/download/")
        return None


# ---------------------------
# main
# -------------------------


def main():
    banner()

    parser = argparse.ArgumentParser(description="DNS cartography tool")
    parser.add_argument("domain", nargs="?", help="Domain to analyze")
    parser.add_argument("--graphviz", help=".dot output")
    parser.add_argument("--raw", action="store_true", help="Show all raw data before filtering")
    # Note: ces arguments sont déclarés mais non utilisés dans la logique,
    parser.add_argument(
        "--ip",
        "--reverse",
        "--neighbors",
        "--domains",
        "--parents",
        "--subdomains",
        "--srv",
        action="store_true",
    )
    args = parser.parse_args()

    # recup le domaine
    domain = args.domain
    if not domain:
        domain = input("Entrez le domaine à découvrir : ").strip()
        if not domain:
            print("[-] Aucun domaine fourni, arrêt.")
            return

    print(f"\n[*] Collecting data for {domain}...")

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

    print(
        f"[+] Found {len(raw_results['ips'])} IP(s) | {len(raw_results['subdomains'])} subdomain(s) | "
        f"{len(raw_results['mx'])} MX | {len(raw_results['ns'])} NS | {len(raw_results['srv'])} SRV"
    )

    for ip in raw_results["ips"]:
        rdns = reverse_dns(ip)
        if rdns:
            raw_results["reverse"][ip] = rdns
        neighbors = scan_ip_neighbors(ip)
        if neighbors:
            raw_results["neighbors"][ip] = neighbors

    raw_results["domains"].update(raw_results["mx"] | raw_results["srv"] | raw_results["cname"])
    txt_raw, txt_extracted = parse_txt(domain)
    raw_results["domains"].update(txt_extracted)
    print(f"[+] Found {len(raw_results['domains'])} discovered domain(s) | {len(raw_results['parents'])} parent(s)")

    for d in raw_results["domains"] | raw_results["subdomains"] | {domain}:
        raw_results["parents"].update(get_parent_domains(d))

    if args.raw:
        print(f"\n{'='*60}\nDONNEES BRUTES COLLECTEES\n{'='*60}\n")
        sections = [
            ("IPs", raw_results["ips"]),
            ("Reverse DNS", raw_results["reverse"].values()),
            (
                "IP neighbors",
                [n for ns in raw_results["neighbors"].values() for n in ns],
            ),
            ("MX", raw_results["mx"]),
            ("NS", raw_results["ns"]),
            ("SRV", raw_results["srv"]),
            ("CNAME", raw_results["cname"]),
            ("Domains discovered", raw_results["domains"]),
            ("Parent Domains", raw_results["parents"]),
            ("Subdomains", raw_results["subdomains"]),
        ]
        for section, items in sections:
            if items:
                print(f"=== {section} ===")
                for x in sorted(items):
                    print(f"  {x}")
                print()

    # ==========================================
    # PHASE 3: FILTRAGE INTELLIGENT
    # ==========================================
    print(f"\n[*] Filtering data...")
    filtered_results = filter_interesting_data(raw_results, domain)

    # ==========================================
    # PHASE 4: AFFICHAGE FINAL
    # ==========================================
    print(f"\n{'='*60}\nDNS CARTOGRAPHY FOR {domain.upper()}\n{'='*60}\n")
    print(f"\n[SUMMARY]")
    summary = [
        ("IP Addresses", len(filtered_results["ips"])),
        ("Subdomains", len(filtered_results["subdomains"])),
        ("MX Records", len(filtered_results["mx_records"])),
        ("NS Records", len(filtered_results["ns_records"])),
        ("SRV Records", len(filtered_results["srv_records"])),
        ("Parent Domains", len(filtered_results["parent_domains"])),
        ("Total Discovered", len(filtered_results["domains_discovered"])),
    ]
    for name, count in summary:
        print(f"  • {name}: {count}")

    print()
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
    else:
        # Génération automatique du graphviz en JPG
        graphviz_file = f"{domain.replace('.', '_')}_diagram.dot"
        export_graphviz(graphviz_file, domain, filtered_results)


if __name__ == "__main__":
    main()
