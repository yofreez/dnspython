
import ipaddress
import dns.resolver
import dns.reversename
import argparse

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
        return [reverse_dns(str(a + d)) for d in (-1,1) if reverse_dns(str(a + d))]
    except: return []

def scan_srv(domain):
    services = ["_sip._tcp","_sip._udp","_ldap._tcp","_xmpp-server._tcp"]
    return {r.target.to_text().rstrip(".") for srv in services for r in resolve(f"{srv}.{domain}","SRV")}



def main():
    banner()

    parser = argparse.ArgumentParser()
    parser.add_argument("domain", nargs="?")
    args = parser.parse_args()

    domain = args.domain or input("Entrez le domaine : ").strip()
    if not domain:
        return

    ips = resolve_ips(domain)
    srv_records = scan_srv(domain)

    print(f"\nAnalyse de {domain}\n")
    
    # ipavec le reverse 
    if ips:
        print("=== Adresses IP ===")
        for ip in sorted(ips):
            rdns = reverse_dns(ip)
            suffix = f" ({rdns})" if rdns else ""
            print(f" - {ip}{suffix}")
        
        
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
    
    #  enregistrements SRV
    if srv_records:
        print("\n=== Enregistrements SRV ===")
        for srv in sorted(srv_records):
            print(f" - {srv}")
    else:
        print("\n=== Enregistrements SRV ===")
        print("  Aucun enregistrement SRV trouvé")
    
    # résumé de tt 
    print(f"\n[*] Résumé pour {domain}:")
    print(f"    - {len(ips)} adresse(s) IP trouvée(s)")
    print(f"    - {len(srv_records)} enregistrement(s) SRV trouvé(s)")

if __name__ == "__main__":
    main()

