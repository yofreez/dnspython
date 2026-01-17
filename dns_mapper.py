
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
        rdns = reverse_dns(ip)
        suffix = f" ({rdns})" if rdns else ""
        print(f" - {ip}{suffix}")

if __name__ == "__main__":
    main()

