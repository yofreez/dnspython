import argparse
import ipaddress
import os
import re
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

import dns.resolver
import dns.reversename
import tldextract

# Config pour le resolveur
RESOLVER = dns.resolver.Resolver()
RESOLVER.timeout = 2.0
RESOLVER.lifetime = 2.0


def banner() -> None:
    """Affiche la bannière du programme."""
    print(r"""
====================================
           DNS MAPPER
====================================
""")


# -------------------------
#  Résolution DNS
# -------------------------


def resolve(domain: str, rtype: str) -> List[Any]:
    try:
        return list(RESOLVER.resolve(domain, rtype))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.resolver.Timeout):
        return []


def resolve_ips(domain: str) -> Set[str]:
    #  enregistrements A et AAAA pour un domaine
    return {r.to_text()
            for t in ("A", "AAAA")
            for r in resolve(domain, t)}


def reverse_dns(ip: str) -> Optional[str]:
    # Effectue une résolution DNS inverse pour une IP
    try:
        rev = dns.reversename.from_address(ip)
        res = resolve(str(rev), "PTR")
        return res[0].to_text().rstrip(".") if res else None
    except (ValueError, IndexError):
        return None


def scan_ip_neighbors(ip: str) -> List[str]:
    # Scan l'IP précédente et suivante
    neighbors = []
    try:
        addr = ipaddress.ip_address(ip)
        for delta in (-1, 1):
            neighbor_ip = str(addr + delta)
            rdns = reverse_dns(neighbor_ip)
            if rdns:
                neighbors.append(f"{neighbor_ip} ({rdns})")
    except ValueError:
        pass
    return neighbors


def resolve_cname(domain: str) -> Optional[str]:
    records = resolve(domain, "CNAME")
    return records[0].to_text().rstrip(".") if records else None


def scan_records(domain: str) -> Tuple[Set[str], Set[str], Set[str]]:
    # MX, NS et SRV.
    mx = {r.exchange.to_text().rstrip(".") for r in resolve(domain, "MX")}
    ns = {r.target.to_text().rstrip(".") for r in resolve(domain, "NS")}

    srv_services = ["_sip._tcp", "_sip._udp", "_ldap._tcp",
                    "_xmpp-server._tcp"]
    srv = set()
    for s in srv_services:
        for r in resolve(f"{s}.{domain}", "SRV"):
            srv.add(r.target.to_text().rstrip("."))

    return mx, ns, srv


def parse_txt(domain: str) -> Set[str]:
    extracted = set()
    pattern = re.compile(r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
    for r in resolve(domain, "TXT"):
        for match in pattern.findall(r.to_text()):
            if match != domain and "." in match:
                extracted.add(match)
    return extracted


def enumerate_subdomains(domain: str) -> Set[str]:
    # les ss-domaines courants
    words = [
        "www", "api", "mail", "shop", "admin", "dev", "test", "staging",
        "prod", "app", "web", "backend", "frontend", "mobile", "blog",
        "cdn", "static", "files", "ftp", "vpn", "remote", "secure",
        "smtp", "pop", "webmail", "ns1", "ns2", "mx", "git", "gitlab",
        "jenkins", "monitor", "db", "mysql", "redis", "auth", "sso",
        "ldap", "support", "wiki", "portal", "intranet"
    ]
    found = set()
    print(f"[*] Test de {len(words)} sous-domaines...")
    for w in words:
        full = f"{w}.{domain}"
        if resolve(full, "A") or resolve(full, "AAAA"):
            found.add(full)
    return found


def get_parent_domains(domain: str) -> Set[str]:
    ext = tldextract.extract(domain)
    if not ext.suffix or not ext.domain:
        return set()

    registered = f"{ext.domain}.{ext.suffix}"
    parents: Set[str] = set()
    if domain == registered:
        return parents

    parts = ext.subdomain.split(".")
    curr = registered
    for part in reversed(parts):
        candidate = f"{part}.{curr}"
        if candidate != domain:
            parents.add(candidate)
        curr = candidate
    return parents

# -------------------------
# Graphviz
# --------------


def export_graphviz(
    filename: str,
    main_domain: str,
    data: Dict[str, Any],
    styles: Dict[str, Tuple[str, str, str, str]] = {
        "ips": ("#FFD7D7", "#FF6B6B", "box", "IP"),
        "subdomains": ("#D7F9FF", "#4DA3FF", "ellipse", "Sub"),
        "domains": ("#D7FFD7", "#28A745", "hexagon", "Record"),
        "srv": ("#EAD7FF", "#6F42C1", "component", "SRV"),
        "cname": ("#FFE4B5", "#FFA500", "parallelogram", "CNAME"),
        "parents": ("#F0F0F0", "#6C757D", "diamond", "Parent"),
    },
) -> None:
    lines = [
        'digraph G {',
        '  rankdir=LR;',
        '  nodesep=0.6; ranksep=1.0;',
        '  graph [bgcolor="#FFFFFF", splines=curved, overlap=false];',
        '  node [fontname="Verdana", fontsize=10, '
        'style="filled,rounded", penwidth=1.5];',
        '  edge [fontname="Verdana", fontsize=8, penwidth=1.2, '
        'arrowsize=0.8];',
        f'  "{main_domain}" [shape=doubleoctagon, '
        f'fillcolor="#FFD670", color="#E67E22", fontsize=14, '
        f'fontcolor="#333333", width=2];'
    ]

    # on fait les branches
    for cat, (fill, stroke, shape, label) in styles.items():
        for item in data.get(cat, []):
            node_id = f'"{item}"'
            lines.append(
                f'  {node_id} [label="{item}", fillcolor="{fill}", '
                f'color="{stroke}", shape={shape}];'
            )
            lines.append(
                f'  "{main_domain}" -> {node_id} [color="{stroke}", '
                f'fontcolor="{stroke}", label="{label}"];'
            )

    # les voisins
    for ip, neighbors in data.get("neighbors", {}).items():
        for n in neighbors:
            n_clean = n.split()[0]
            lines.append(
                f'  "{n_clean}" [label="{n_clean}", '
                f'fillcolor="#FFF0F0", color="#FF6B6B", shape=box, '
                f'style="dashed,filled"];'
            )
            lines.append(
                f'  "{ip}" -> "{n_clean}" [color="#FF6B6B", '
                f'style=dashed, label="neighbor", constraint=false];'
            )

    lines.append("}")

    # Écriture du fichier .dot
    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    # RECHERCHE DE L'EXECUTABLE DOT (la galere)
    dot_cmd = shutil.which("dot")  # Cherche dans le PATH système

    # Si pas trouvé dans PATH, chercher dans dossiers Windows classiques
    if not dot_cmd:
        possible_paths = [
            r"C:\Program Files\Graphviz\bin\dot.exe",
            r"C:\Program Files (x86)\Graphviz\bin\dot.exe",
        ]
        # Ajoute dynamiquement d'autres versions
        versions = ["2.44", "2.45", "2.46", "2.47", "2.48", "2.49",
                    "2.50", "3.0", "4.0", "5.0", "6.0", "7.0",
                    "8.0", "9.0", "10.0"]
        for v in versions:
            possible_paths.append(
                rf"C:\Program Files\Graphviz {v}\bin\dot.exe"
            )

        for p in possible_paths:
            if os.path.exists(p):
                dot_cmd = p
                break

    # on compile
    if dot_cmd:
        jpg_file = filename.replace(".dot", ".jpg")
        print(f"[*] Exécution de Graphviz via : {dot_cmd}")
        try:
            subprocess.run(
                [dot_cmd, "-Tjpg", "-Gdpi=150", filename, "-o", jpg_file],
                capture_output=True,
                text=True,
                check=True
            )
            print(f"[+] Image générée avec succès : {jpg_file}")
        except subprocess.CalledProcessError as e:
            print("[!] Erreur lors de la génération JPG :")
            print(e.stderr)
    else:
        print("[!] Graphviz non trouvé. Installez-le et ajoutez-le au "
              "PATH, ou vérifiez C:\\Program Files\\Graphviz.")
        print(f"[!] Le fichier DOT est quand même sauvegardé : {filename}")


# -------------------------
# Scan Function
# -------------------------


def scan(domaine: str, profondeur: int) -> None:
    def is_ip(v):
        try: ipaddress.ip_address(v); return True
        except: return False
    
    file_attente = [domaine]
    already_seen = set()
    results = {"IPs": set(), "MX": set(), "SOA": set(), "CNAME": {}, "SRV": set(), 
               "TXT": set(), "NS": set(), "Parents": set(), "Sous-domaines": set(),
               "Reverse DNS": {}, "Voisins IP": {}}
    
    print(f"--- Scan en cours de {domaine} avec une profondeur de {profondeur} ---\n")

    while file_attente and len(already_seen) < profondeur:
        workon = file_attente.pop(0)
        if workon in already_seen: continue
        print(f"[+] Traitement : {workon}")
        already_seen.add(workon)
        
        if is_ip(workon):
            rdns = reverse_dns(workon)
            if rdns: 
                results["Reverse DNS"][workon] = rdns
                file_attente.append(rdns)
            neighbors = scan_ip_neighbors(workon)
            if neighbors:
                results["Voisins IP"][workon] = neighbors
        else:
            ips = resolve_ips(workon)
            if ips: 
                results["IPs"].update(ips)
                file_attente.extend(ips)
            
            mx_records = {r.exchange.to_text().rstrip(".") for r in resolve(workon, "MX")}
            if mx_records: 
                results["MX"].update(mx_records)
                file_attente.extend(mx_records)
            
            _, ns_records, _ = scan_records(workon)
            if ns_records: 
                results["NS"].update(ns_records)
                file_attente.extend(ns_records)
            
            soa = {r.to_text() for r in resolve(workon, "SOA")}
            results["SOA"].update(soa)
            
            cname = resolve_cname(workon)
            if cname: 
                results["CNAME"][workon] = cname
                file_attente.append(cname)
            
            _, _, srv_records = scan_records(workon)
            if srv_records: 
                results["SRV"].update(srv_records)
                file_attente.extend(srv_records)
            
            txt = parse_txt(workon)
            if txt: 
                results["TXT"].update(txt)
                file_attente.extend(txt)
            
            parents = get_parent_domains(workon)
            if parents: 
                results["Parents"].update(parents)
                file_attente.extend(parents)
            
            subs = enumerate_subdomains(workon)
            if subs: 
                results["Sous-domaines"].update(subs)
                file_attente.extend(subs)
    
    print(f"\n\n{'='*60}")
    print(f"RAPPORT POUR {domaine}")
    print(f"{'='*60}\n")
    
    print("--- DOMAINES ---")
    for key in ["Sous-domaines", "MX", "NS", "SRV", "TXT", "Parents"]:
        if results[key]:
            print(f"\n{key}:")
            for item in sorted(results[key]):
                print(f"  - {item}")
    
    if results["CNAME"]:
        print(f"\nCNAME:")
        for src, dst in sorted(results["CNAME"].items()):
            print(f"  - {src} -> {dst}")
    
    if results["SOA"]:
        print(f"\nSOA:")
        for item in sorted(results["SOA"]):
            print(f"  - {item}")
    
    print("\n--- IPs ---")
    if results["IPs"]:
        print(f"\nAdresses IP:")
        for ip in sorted(results["IPs"]):
            print(f"  - {ip}")
    
    if results["Reverse DNS"]:
        print(f"\nReverse DNS:")
        for ip, rdns in sorted(results["Reverse DNS"].items()):
            print(f"  - {ip} -> {rdns}")
    
    if results["Voisins IP"]:
        print(f"\nVoisins IP:")
        for ip, neighbors in sorted(results["Voisins IP"].items()):
            for n in neighbors:
                print(f"  - {ip} voisin: {n}")


# -------------------------
# Main
# -------------------------


def main():

    banner()
    parser = argparse.ArgumentParser()
    parser.add_argument("domain", nargs="?", help="Domaine cible")
    parser.add_argument("--graphviz", help="Fichier de sortie .dot")
    parser.add_argument("--ips", action="store_true", help="Afficher les IPs")
    parser.add_argument("--reverse", action="store_true", help="Afficher les reverse DNS")
    parser.add_argument("--neighbors", action="store_true", help="Afficher les voisins IP")
    parser.add_argument("--subdomains", action="store_true", help="Afficher les sous-domaines")
    parser.add_argument("--records", action="store_true", help="Afficher les records (MX/NS/TXT)")
    parser.add_argument("--srv", action="store_true", help="Afficher les records SRV")
    parser.add_argument("--cname", action="store_true", help="Afficher les CNAME")
    parser.add_argument("--parents", action="store_true", help="Afficher les domaines parents")
    parser.add_argument("--all", action="store_true", help="Afficher tous les résultats")
    args = parser.parse_args()

    domain = args.domain
    if not domain:
        domain = input("Domaine : ").strip()
        if not domain:
            return

    print(f"[*] Analyse de : {domain}\n")
    
    profondeur = getattr(args, 'profondeur', 100)
    scan(domain, profondeur)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\n[!] Arrêt.")
