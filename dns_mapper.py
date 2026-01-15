import dns.resolver
import dns.reversename

# -------------------------
# Config TLDs 
# -------------------------
TLDs = ["com", "org", "net", "fr", "gouv.fr", "co.uk", "edu", "gov", "io"]

# -------------------------
# Utils DNS
# -------------------------

def resolve(domain, rtype):
    try:
        return dns.resolver.resolve(domain, rtype, lifetime=0.5)
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
        answers = dns.resolver.resolve(rev, "PTR", lifetime=0.5)
        return answers[0].to_text().rstrip(".")
    except Exception:
        return None