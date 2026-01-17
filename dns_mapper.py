
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

def resolve_ips(domain):
    return {
        r.to_text()
        for t in ("A", "AAAA")
        for r in resolve(domain, t)
    }

def main():
    banner()

    parser = argparse.ArgumentParser()
    parser.add_argument("domain", nargs="?")
    args = parser.parse_args()

    domain = args.domain or input("Entrez le domaine : ").strip()
    if not domain:
        return

    ips = resolve_ips(domain)

    print(f"\nAnalyse de {domain}\n")
    for ip in ips:
        print(f" - {ip}")

if __name__ == "__main__":
    main()

