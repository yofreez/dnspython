import argparse
import ipaddress
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

import dns.resolver
import dns.reversename
import tldextract


RESOLVER = dns.resolver.Resolver()
RESOLVER.timeout = 2.0
RESOLVER.lifetime = 2.0


def banner():
    print(r"""
   ___  _  _ ___   __  __  _  ___  ___ ___ ___
  |   \| \| / __| |  \/  |/_\ | _ \| _ \ __| _ \
  | |) | .` \__ \ | |\/| / _ \|  _/|  _/ _||   /
  |___/|_|\_|___/ |_|  |/_/ \_\_|  |_| |___|_|_\
    """)


# Fonctions DNS de base

def resolve(domain: str, rtype: str) -> List[Any]:
    try:
        return list(RESOLVER.resolve(domain, rtype))
    except:
        return []


def get_ips(d: str) -> Set[str]:
    return {r.to_text() for t in ("A", "AAAA") for r in resolve(d, t)}


def get_mx(d: str) -> Set[str]:
    return {r.exchange.to_text().rstrip(".") for r in resolve(d, "MX")}


def get_ns(d: str) -> Set[str]:
    return {r.target.to_text().rstrip(".") for r in resolve(d, "NS")}


def get_srv(d: str) -> Set[str]:
    srv = set()
    for s in ["_sip._tcp", "_sip._udp", "_ldap._tcp", "_xmpp-server._tcp"]:
        srv.update(r.target.to_text().rstrip(".") for r in resolve(f"{s}.{d}", "SRV"))
    return srv


def get_txt(d: str) -> Set[str]:
    """Extrait les domaines des enregistrements TXT."""
    extracted: Set[str] = set()
    # Pattern pour extraire les domaines des records TXT
    pattern = re.compile(r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
    for r in resolve(d, "TXT"):
        for match in pattern.findall(r.to_text()):
            if match != d and "." in match:
                extracted.add(match)
    return extracted


def get_cname(d: str) -> Optional[str]:
    res = resolve(d, "CNAME")
    return res[0].to_text().rstrip(".") if res else None


def get_reverse(ip: str) -> Optional[str]:
    try:
        res = resolve(str(dns.reversename.from_address(ip)), "PTR")
        return res[0].to_text().rstrip(".") if res else None
    except:
        return None


def get_neighbors(ip: str) -> List[str]:
    neigh = []
    try:
        addr = ipaddress.ip_address(ip)
        for d in (-1, 1):
            nip = str(addr + d)
            if r := get_reverse(nip):
                neigh.append(f"{nip} ({r})")
    except:
        pass
    return neigh


def get_subdomains(d: str) -> Set[str]:
    subs = set()
    for w in ["www", "api", "mail", "shop", "admin", "dev", "test", "app", "web", "cdn"]:
        full = f"{w}.{d}"
        if get_ips(full):
            subs.add(full)
    return subs


def get_parents(d: str) -> Set[str]:
    ext = tldextract.extract(d)
    if not ext.suffix:
        return set()
    reg, parents = f"{ext.domain}.{ext.suffix}", set() # domain racine 
    if d == reg:
        return parents
    parts, curr = ext.subdomain.split("."), reg
    for part in reversed(parts):   # boucle de reconstrution 
        candidate = f"{part}.{curr}"
        if candidate != d:
            parents.add(candidate)
        curr = candidate
    return parents


def scan(domain: str, depth: int = 100) -> dict:
    queue, seen = [domain], set() # fifo 
    results = {k: ({} if k in ["CNAME", "Reverse", "Neighbors"] else set())
               for k in ["IPs", "MX", "NS", "SRV", "TXT", "CNAME", "Parents", "Subs", "Reverse", "Neighbors"]}

    print(f"[*] Scan de {domain} (profondeur: {depth})...")

    #(Clé Résultats, Fonction, Est-ce une liste ?)
    domain_scanners = [
        ("IPs", get_ips, True), ("MX", get_mx, True), ("NS", get_ns, True),
        ("SRV", get_srv, True), ("TXT", get_txt, True), ("Parents", get_parents, True),
        ("Subs", get_subdomains, True), ("CNAME", get_cname, False)
    ]

    while queue and len(seen) < depth:
        curr = queue.pop(0)
        if curr in seen:
            continue
        seen.add(curr)
        print(f" -> {curr}")

        # Si c'est une IP
        try:
            ipaddress.ip_address(curr)
            if r := get_reverse(curr):
                results["Reverse"][curr] = r
                queue.append(r)
            if n := get_neighbors(curr):
                results["Neighbors"][curr] = n
            continue
        except ValueError:
            pass

        
        for key, func, is_list in domain_scanners:
            data = func(curr)
            if not data:
                continue
            
            if is_list:
                results[key].update(data)
                queue.extend(data)
            else:  #  (CNAME)
                results[key][curr] = data
                queue.append(data)

    return results


def generate_markdown(domain: str, res: dict, depth: int, args=None):
    fname = f"{domain.replace('.', '_')}_report.md"


    if args is None:
        show_all = True
    else:
        any_flag = (args.subs or args.mx or args.ns or args.srv or args.txt or args.cname or
                    args.parents or args.ips or args.reverse or args.neighbors or args.all)
        show_all = args.all if any_flag else True

    show = {
        "subs": show_all or (args and args.subs),
        "mx": show_all or (args and args.mx),
        "ns": show_all or (args and args.ns),
        "srv": show_all or (args and args.srv),
        "txt": show_all or (args and args.txt),
        "cname": show_all or (args and args.cname),
        "parents": show_all or (args and args.parents),
        "ips": show_all or (args and args.ips),
        "reverse": show_all or (args and args.reverse),
        "neighbors": show_all or (args and args.neighbors),
    }
    
    sections = []
    
    domain_subsections = []
    if show["subs"]:
        domain_subsections.append(("Subs", "Sous-domaines"))
    if show["mx"]:
        domain_subsections.append(("MX", "MX"))
    if show["ns"]:
        domain_subsections.append(("NS", "NS"))
    if show["srv"]:
        domain_subsections.append(("SRV", "SRV"))
    if show["txt"]:
        domain_subsections.append(("TXT", "TXT"))
    if show["cname"]:
        domain_subsections.append(("CNAME", "CNAME"))
    if show["parents"]:
        domain_subsections.append(("Parents", "Parents"))
    
    if domain_subsections:
        sections.append(("Domaines", domain_subsections))
    

    ip_subsections = []
    if show["ips"]:
        ip_subsections.append(("IPs", "IPs Résolues"))
    if show["reverse"]:
        ip_subsections.append(("Reverse", "Reverse DNS"))
    if show["neighbors"]:
        ip_subsections.append(("Neighbors", "Voisins IP"))
    
    if ip_subsections:
        sections.append(("IPs", ip_subsections))
    
    with open(fname, "w", encoding="utf-8") as f:
        f.write(f"# DNS Report: {domain}\n**Date:** {datetime.now()}\n\n")
        
        for head, subs in sections:
            f.write(f"## {head}\n")
            for k, title in subs:
                if res[k]:
                    f.write(f"### {title}\n")
                    if k in ["CNAME", "Reverse", "Neighbors"]:
                        # Tables spéciales
                        if k == "CNAME":
                            f.write("| Src | Tgt |\n|---|---|\n")
                            for s, t in res[k].items():
                                f.write(f"| {s} | {t} |\n")
                        elif k == "Reverse":
                            f.write("| IP | Host |\n|---|---|\n")
                            for i, h in res[k].items():
                                f.write(f"| {i} | {h} |\n")
                        elif k == "Neighbors":
                            for ip, neighbors in sorted(res[k].items()):
                                f.write(f"**{ip}**\n")
                                for n in neighbors:
                                    f.write(f"  - {n}\n")
                    else:
                        # Listes simples
                        for x in sorted(res[k]):
                            f.write(f"- `{x}`\n")
                    f.write("\n")

    print(f"[+] Rapport : {fname}")


# Graphviz

def export_graphviz(fname: str, main: str, data: dict):
    def cluster(name, color, nodes):
        if not nodes:
            return []
        lines = [f'subgraph cluster_{name} {{ label="{name.upper()}"; style=dashed; color="{color}";']
        for n in nodes:
            lines.append(f'"{n}" [style=filled, fillcolor="{color}20"];')
            lines.append(f'"{main}" -> "{n}";')
        lines.append("}")
        return lines

    lines = [
        'digraph G {',
        'rankdir=TB;',
        'nodesep=0.8;',
        'node [shape=ellipse, fontname="Verdana", fontsize=10];',
        f'"{main}" [shape=doubleoctagon, style=filled, fillcolor="#FFD670"];'
    ]

    lines += cluster("subdomains", "#4DA3FF", data.get("subdomains", []))
    lines += cluster("domains", "#28A745", data.get("domains", []))
    lines += cluster("ips", "#FF6B6B", data.get("ips", []))
    lines += cluster("parents", "#6C757D", data.get("parents", []))

    
    for s, t in data.get("cname_map", {}).items():
        lines.append(f'"{s}" -> "{t}" [label="CNAME", color="orange"];')

   
    for ip, neighs in data.get("neighbors", {}).items():
        for n in neighs:
            n_clean = n.split()[0]
            lines.append(f'"{ip}" -> "{n_clean}" [style=dashed, color="red"];')

    lines.append("}")
    
    with open(fname, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    

    paths = [r"C:\Program Files\Graphviz\bin\dot.exe", r"C:\Program Files (x86)\Graphviz\bin\dot.exe"]
    dot = shutil.which("dot") or next((p for p in paths if os.path.exists(p)), None)

    if dot:
        jpg = fname.replace(".dot", ".jpg")
        try:
            subprocess.run([dot, "-Tjpg", "-Gdpi=150", fname, "-o", jpg], check=True, capture_output=True)
            print(f"[+] Image : {jpg}")
        except:
            print("[!] Erreur compilation JPG.")
    else:
        print("[!] Graphviz introuvable.")


# Main
def main():
    banner()
    parser = argparse.ArgumentParser()
    parser.add_argument("domain", help="Domaine cible")
    parser.add_argument("--scan", type=int, default=100, help="Profondeur du scan (défaut: 100)")
    parser.add_argument("--graphviz", help="Sortie .dot personnalisée")
    parser.add_argument("--subs", action="store_true", help="Afficher les sous-domaines")
    parser.add_argument("--mx", action="store_true", help="Afficher les records MX")
    parser.add_argument("--ns", action="store_true", help="Afficher les records NS")
    parser.add_argument("--srv", action="store_true", help="Afficher les records SRV")
    parser.add_argument("--txt", action="store_true", help="Afficher les records TXT")
    parser.add_argument("--cname", action="store_true", help="Afficher les CNAME")
    parser.add_argument("--parents", action="store_true", help="Afficher les domaines parents")
    parser.add_argument("--ips", action="store_true", help="Afficher les IPs")
    parser.add_argument("--reverse", action="store_true", help="Afficher les reverse DNS")
    parser.add_argument("--neighbors", action="store_true", help="Afficher les voisins IP")
    parser.add_argument("--all", action="store_true", help="Afficher tous les résultats")
    args = parser.parse_args()

    res = scan(args.domain, args.scan)
    generate_markdown(args.domain, res, args.scan, args)


    graph_data = {
        "ips": list(res["IPs"])[:15],
        "subdomains": [s for s in res["Subs"] if args.domain in s][:15],
        "domains": list((res["MX"] | res["NS"] | res["TXT"]) - res["Parents"])[:15],
        "srv": list(res["SRV"])[:5],
        "parents": list(res["Parents"])[:5],
        "cname_map": dict(list(res["CNAME"].items())[:10]),
        "neighbors": dict(list(res["Neighbors"].items())[:5])
    }
    
    dot_file = args.graphviz if args.graphviz else f"{args.domain.replace('.', '_')}_map.dot"
    export_graphviz(dot_file, args.domain, graph_data)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\n[!] Arrêt.")
