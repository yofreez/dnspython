
import dns.resolver
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

def main():
    banner()

    parser = argparse.ArgumentParser(description="DNS mapper")
    parser.add_argument("domain", nargs="?")
    args = parser.parse_args()

    domain = args.domain
    if not domain:
        domain = input("Entrez le domaine : ").strip()
        if not domain:
            print("Aucun domaine fourni.")
            return

    print(f"\nAnalyse de {domain}\n")

    ips = {r.to_text() for r in resolve(domain, "A")}

    if ips:
        print("IPs trouvées :")
        for ip in ips:
            print(f" - {ip}")
    else:
        print("Aucune IP trouvée.")

if __name__ == "__main__":
    main()

