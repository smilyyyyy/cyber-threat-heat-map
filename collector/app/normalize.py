"""Helpers that clean data coming from different feeds into one format."""
import ipaddress
import re

_MITRE_SUFFIX = re.compile(r"\s+-\s+S\d{3,5}$")          # "Cobalt Strike - S0154" -> "Cobalt Strike"
_GALAXY_TAG = re.compile(
    r'misp-galaxy:(malpedia|mitre-malware|ransomware|rat|banker|stealer|botnet|'
    r'backdoor|android|tool|mitre-tool|exploit-kit)="([^"]+)"', re.I)


def family(name):
    """Normalise a malware family name so the same family from OTX and CIRCL matches."""
    if not name:
        return None
    n = _MITRE_SUFFIX.sub("", str(name).strip())
    n = re.sub(r"\s+", " ", n)
    return n[:120] or None


def families_from_tags(tag_names):
    """Extract malware family names from MISP galaxy tags."""
    out = set()
    for t in tag_names or []:
        m = _GALAXY_TAG.search(t or "")
        if m:
            f = family(m.group(2))
            if f:
                out.add(f)
    return out


def public_ipv4(value):
    """Return the IP as a string if it is a valid, public IPv4 address, else None."""
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    return str(ip) if ip.version == 4 and ip.is_global else None
