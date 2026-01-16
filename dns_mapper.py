

import dns.resolver
import dns.reversename

# ==========================================
# DNS
# ==========================================

def resolve(domain, rtype):
    try:
        return dns.resolver.resolve(domain, rtype, lifetime=1)
    except Exception:
        return []

def resolve_ips(domain):
    ips = set()
    for rtype in ["A", "AAAA"]:
        for r in resolve(domain, rtype):
            ips.add(r.to_text())
    return ips

def reverse_dns(ip):
    try:
        rev = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(rev, "PTR", lifetime=1)
        return answers[0].to_text().rstrip(".")
    except Exception:
        return None

# ==========================================
# (MAIN)
# ==========================================

if __name__ == "__main__":
    print("--- SCANNER DNS SIMPLE ---")
    saisie = input(
        "Entrez le(s) domaine(s) à analyser (séparés par des virgules) : "
    ).strip()

    if not saisie:
        print("[-] Erreur : aucun domaine saisi.")
        exit(1)

    domaines = [d.strip() for d in saisie.split(",") if d.strip()]

    for domaine in domaines:
        print(f"\n[+] Analyse du domaine : {domaine}")
        ips = resolve_ips(domaine)

        if not ips:
            print("[-] Aucune adresse IP trouvée.")
            continue

        print(f"[+] {len(ips)} IP(s) trouvée(s)")
        print(f"{'ADRESSE IP':<25} | {'REVERSE DNS'}")
        print("-" * 60)

        for ip in ips:
            rdns = reverse_dns(ip) or "N/A"
            print(f"{ip:<25} | {rdns}")

        print("-" * 60)

    print("\nAnalyse terminée.")