
import ipaddress
import dns.resolver
import dns.reversename
import argparse
import re 

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
# Strategies
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
    pattern = r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    return {d for r in resolve(domain,"TXT") for d in re.findall(pattern,r.to_text())}

def enumerate_subdomains(domain):
    words = ["www","api","mail","shop","news","community"]
    return {f"{w}.{domain}" for w in words if resolve(f"{w}.{domain}","A") or resolve(f"{w}.{domain}","AAAA")}



def main():
    banner()

    parser = argparse.ArgumentParser()
    parser.add_argument("domain", nargs="?")
    args = parser.parse_args()

    domain = args.domain or input("Entrez le domaine : ").strip()
    if not domain:
        print("[-] Aucun domaine fourni.")
        return

    # Collecte de toutes les données
    ips = resolve_ips(domain)
    srv_records = scan_srv(domain)
    mx_records = scan_mx(domain)
    txt_domains = parse_txt(domain)
    subdomains = enumerate_subdomains(domain)

    print(f"\nAnalyse de {domain}\n")
    
    # IPs avec le reverse DNS
    if ips:
        print("=== Adresses IP ===")
        for ip in sorted(ips):
            rdns = reverse_dns(ip)
            suffix = f" ({rdns})" if rdns else ""
            print(f" - {ip}{suffix}")
        
        # Voisins IP
        print("\n=== Voisins IP ===")
        neighbor_found = False
        for ip in sorted(ips):
            neighbors = scan_ip_neighbors(ip)
            if neighbors:
                neighbor_found = True
                print(f"  {ip}:")
                for neighbor in neighbors:
                    print(f"    -> {neighbor}")
        
        if not neighbor_found:
            print("  Aucun voisin trouvé")
    else:
        print("=== Adresses IP ===")
        print("  Aucune adresse IP trouvée")
    
    # Enregistrements SRV
    print("\n=== Enregistrements SRV ===")
    if srv_records:
        for srv in sorted(srv_records):
            print(f" - {srv}")
    else:
        print("  Aucun enregistrement SRV trouvé")
    
    # Serveurs MX
    print("\n=== Serveurs Mail (MX) ===")
    if mx_records:
        for mx in sorted(mx_records):
            print(f" - {mx}")
    else:
        print("  Aucun serveur MX trouvé")
    
    # Domaines dans les TXT
    print("\n=== Domaines trouvés dans TXT ===")
    if txt_domains:
        for txt_domain in sorted(txt_domains):
            print(f" - {txt_domain}")
    else:
        print("  Aucun domaine trouvé dans les enregistrements TXT")
    
    # Sous-domaines
    print("\n=== Sous-domaines découverts ===")
    if subdomains:
        for sub in sorted(subdomains):
            print(f" - {sub}")
    else:
        print("  Aucun sous-domaine trouvé")
    
    # Résumé de tout
    print(f"\n[*] Résumé pour {domain}:")
    print(f"    - {len(ips)} adresse(s) IP trouvée(s)")
    print(f"    - {len(srv_records)} enregistrement(s) SRV trouvé(s)")
    print(f"    - {len(mx_records)} serveur(s) MX trouvé(s)")
    print(f"    - {len(txt_domains)} domaine(s) dans TXT trouvé(s)")
    print(f"    - {len(subdomains)} sous-domaine(s) découvert(s)")

if __name__ == "__main__":
    main()