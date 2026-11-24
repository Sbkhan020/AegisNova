import hashlib, ipaddress, re
from urllib.parse import urlsplit

SUSPICIOUS_TLDS = {"zip", "mov", "top", "click", "work", "country", "gq", "tk"}
def url_analysis(raw: str):
    candidate = raw.strip()
    if "://" not in candidate: candidate = "https://" + candidate
    p = urlsplit(candidate)
    if p.scheme not in {"http", "https"} or not p.hostname or any(c.isspace() for c in candidate):
        raise ValueError("Enter a valid HTTP or HTTPS URL")
    # Explicit checks keep findings deterministic and avoid network requests.
    host = p.hostname.lower()
    flags = []
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host): flags.append("IP address used as hostname")
    if "@" in candidate: flags.append("URL contains an @ symbol")
    if "xn--" in host: flags.append("Punycode hostname")
    if len(host.split(".")) >= 5: flags.append("Unusually many subdomains")
    if host.rsplit(".",1)[-1] in SUSPICIOUS_TLDS: flags.append("Non-standard or commonly abused TLD")
    if re.search(r"(password|passwd|token|login)=", candidate, re.I): flags.append("Sensitive-looking query parameter")
    if len(candidate) > 120: flags.append("Unusually long URL")
    if p.scheme == "http": flags.append("Connection does not use HTTPS")
    score = min(95, len(flags) * 15)
    return result("url", candidate, score, flags, "URL inspection is heuristic only; no network request was made.")

def email_analysis(content: str):
    rules = [
      ("Urgent or threatening language", r"\b(urgent|immediately|within 24 hours|suspended|blocked|act now)\b"),
      ("Credential or password request", r"\b(password|login|verify your account|credentials|one.time.password|otp)\b"),
      ("Financial or prize lure", r"\b(prize|winner|claim|refund|payment|bank transfer|gift card)\b"),
      ("Link-shortener or redirect wording", r"\b(bit\.ly|tinyurl|shorturl|click here)\b"),
      ("Attachment pressure", r"\b(open the attachment|enable macros|invoice attached)\b"),
    ]
    flags = [name for name, pat in rules if re.search(pat, content, re.I)]
    score = min(95, len(flags) * 18)
    return result("email", "Email text analysis", score, flags, "Text-only analysis. Sender identity, headers, and actual links were not verified.")

def network_analysis(scope: str):
    try: net = ipaddress.ip_network(scope.strip(), strict=False)
    except ValueError: raise ValueError("Enter a valid IP address or CIDR range")
    if net.is_multicast or net.is_unspecified: raise ValueError("Multicast and unspecified ranges are not accepted")
    if net.num_addresses > 65536: raise ValueError("Scope is too large; maximum supported range is 65,536 addresses")
    flags = []
    if not (net.is_private or net.is_loopback or net.is_link_local): flags.append("Public address range — confirm written authorization before any assessment")
    if net.num_addresses > 256: flags.append("Large scope — verify ownership and minimize assessment scope")
    return {"type":"network","subject":str(net),"score":min(60,len(flags)*25+5),"risk":"MEDIUM" if flags else "LOW","findings":flags or ["Scope syntax valid","No hosts or ports were contacted"],"summary":"Passive scope validation only. No packets were sent and no devices were probed.","metadata":{"version":net.version,"addresses":net.num_addresses,"is_private":net.is_private}}

def file_analysis(data: bytes, filename: str):
    digest = hashlib.sha256(data).hexdigest()
    flags=[]
    ext = filename.rsplit(".",1)[-1].lower() if "." in filename else ""
    risky = {"exe","dll","scr","bat","cmd","ps1","vbs","js","jar","msi","sh"}
    if ext in risky: flags.append(f"Potentially executable file type: .{ext}")
    if data[:2] == b"MZ": flags.append("Windows PE executable signature detected")
    if data.startswith(b"\x7fELF"): flags.append("ELF executable signature detected")
    score = min(85, len(flags)*35)
    return {"type":"file","subject":filename[:200],"score":score,"risk":risk_level(score),"findings":flags or ["No simple executable indicator detected"],"summary":"SHA-256 computed locally in memory. File was not executed, stored, or uploaded to a third party.","metadata":{"size_bytes":len(data),"sha256":digest,"extension":ext or "none"}}

def risk_level(score): return "HIGH" if score >= 60 else "MEDIUM" if score >= 25 else "LOW"
def result(kind, subject, score, flags, summary):
    return {"type":kind,"subject":subject[:500],"score":score,"risk":risk_level(score),"findings":flags or ["No configured heuristic matched"],"summary":summary,"metadata":{}}
