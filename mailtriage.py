#!/usr/bin/env python3
"""mailtriage - triage the headers of a suspicious e-mail, offline.

Paste or pipe the raw headers of a message (in your mail client: "Show original" /
"View source") and get SPF/DKIM/DMARC results, From/Reply-To/Return-Path mismatches,
the relay path and a risk verdict. Only headers are examined; nothing is sent
anywhere and no links are opened. Standard library only.
Exit code 0 = no red flags, 1 = findings at MEDIUM or above, 2 = unreadable input.
"""
import argparse
import email.utils
import re
import sys
from email.parser import HeaderParser

__version__ = "1.0.0"
SEV = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
EMAIL_IN_TEXT = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
IP = re.compile(r"\[(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{3,})\]")


def domain_of(address):
    addr = email.utils.parseaddr(address or "")[1]
    return addr.rsplit("@", 1)[-1].lower() if "@" in addr else ""


def org_domain(domain):
    """Rough organisational domain: last two labels (good enough for alignment hints)."""
    labels = domain.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else domain


def parse_auth_results(msg):
    """Use the topmost Authentication-Results header (added by your own receiver)."""
    res = {"spf": None, "dkim": [], "dmarc": None, "raw": None, "dkim_domains": [], "spf_domain": ""}
    headers = msg.get_all("Authentication-Results") or []
    if headers:
        raw = " ".join(headers[0].split())
        res["raw"] = raw
        for method, result in re.findall(r"\b(spf|dkim|dmarc)=(\w+)", raw, re.I):
            method, result = method.lower(), result.lower()
            if method == "dkim":
                res["dkim"].append(result)
            elif res[method] is None:
                res[method] = result
        res["dkim_domains"] = [d.lower() for d in re.findall(r"header\.d=([\w.-]+)", raw, re.I)]
        m = re.search(r"smtp\.mailfrom=(?:[^@\s;]*@)?([\w.-]+)", raw, re.I)
        res["spf_domain"] = m.group(1).lower() if m else ""
    if res["spf"] is None:
        rs = (msg.get("Received-SPF") or "").strip().split()
        if rs and rs[0].lower() in ("pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"):
            res["spf"] = rs[0].lower()
    return res


def relay_hops(msg):
    hops = []
    for raw in msg.get_all("Received") or []:
        text = " ".join(raw.split())
        m_from = re.search(r"\bfrom\s+(\S+)", text)
        m_by = re.search(r"\bby\s+(\S+)", text)
        m_ip = IP.search(text)
        date = None
        if ";" in text:
            try:
                date = email.utils.parsedate_to_datetime(text.rsplit(";", 1)[1].strip())
            except (TypeError, ValueError):
                date = None
        hops.append({"from": m_from.group(1) if m_from else "?", "by": m_by.group(1) if m_by else "?",
                     "ip": m_ip.group(1) if m_ip else None, "date": date})
    return hops  # newest first, as in the message


def analyze(raw):
    """Return dict(summary, auth, hops, findings, verdict)."""
    msg = HeaderParser().parsestr(raw)
    findings = []
    add = lambda sev, rule, text, fix="": findings.append((sev, rule, text, fix))
    froms = msg.get_all("From") or []
    from_hdr = froms[0] if froms else ""
    from_dom = domain_of(from_hdr)
    name, addr = email.utils.parseaddr(from_hdr)
    reply_dom = domain_of(msg.get("Reply-To"))
    ret_dom = domain_of(msg.get("Return-Path"))
    mid = msg.get("Message-ID", "")
    msgid_dom = mid.rsplit("@", 1)[-1].strip("<> \t").lower() if "@" in mid else ""
    auth = parse_auth_results(msg)
    hops = relay_hops(msg)

    if not froms:
        add("MEDIUM", "no-from", "message has no From header")
    if len(froms) > 1:
        add("HIGH", "multiple-from", "message has %d From headers, a known spoofing trick" % len(froms))
    shown = EMAIL_IN_TEXT.findall(name or "")
    if shown and addr and shown[0].lower() != addr.lower():
        add("HIGH", "display-name-spoof", "display name shows %s but the real sender is %s" % (shown[0], addr),
            "do not trust the display name; verify the real address")
    if from_dom.startswith("xn--") or ".xn--" in from_dom:
        add("MEDIUM", "punycode-domain", "sender domain %s uses punycode (possible look-alike characters)" % from_dom)
    if reply_dom and from_dom and org_domain(reply_dom) != org_domain(from_dom):
        add("MEDIUM", "reply-to-mismatch", "Reply-To domain (%s) differs from From domain (%s)" % (reply_dom, from_dom),
            "replies would go to a different organisation")
    if ret_dom and from_dom and org_domain(ret_dom) != org_domain(from_dom):
        add("LOW", "return-path-mismatch", "Return-Path domain (%s) differs from From domain (%s)" % (ret_dom, from_dom),
            "common for mailing services, suspicious otherwise")
    if msgid_dom and from_dom and org_domain(msgid_dom) != org_domain(from_dom):
        add("LOW", "message-id-mismatch", "Message-ID domain (%s) differs from From domain (%s)" % (msgid_dom, from_dom))
    if not msg.get("Date"):
        add("LOW", "no-date", "message has no Date header")

    if auth["raw"] is None and auth["spf"] is None:
        add("INFO", "no-auth-results", "no Authentication-Results or Received-SPF header, so SPF/DKIM/DMARC cannot be judged",
            "use headers from the receiving mailbox, not a forwarded copy")
    else:
        spf, dmarc = auth["spf"], auth["dmarc"]
        if spf in ("fail", "permerror"):
            add("HIGH", "spf-fail", "SPF %s: the sending server is not authorised for the domain" % spf)
        elif spf == "softfail":
            add("MEDIUM", "spf-softfail", "SPF softfail: the sending server is probably not authorised")
        elif spf in (None, "none", "neutral"):
            add("LOW", "spf-missing", "no meaningful SPF result (%s)" % (spf or "absent"))
        if "fail" in auth["dkim"] or "permerror" in auth["dkim"]:
            add("HIGH", "dkim-fail", "DKIM signature failed verification: the message may have been altered or forged")
        elif not auth["dkim"] or all(r in ("none", "neutral") for r in auth["dkim"]):
            add("LOW", "dkim-missing", "no valid DKIM signature")
        elif "pass" in auth["dkim"] and auth["dkim_domains"] and from_dom and \
                all(org_domain(d) != org_domain(from_dom) for d in auth["dkim_domains"]):
            add("LOW", "dkim-misaligned", "DKIM passed for %s, not the From domain %s" % (
                ",".join(sorted(set(auth["dkim_domains"]))), from_dom))
        if dmarc == "fail":
            add("HIGH", "dmarc-fail", "DMARC failed: the From domain is not authenticated for this message")
        elif dmarc in (None, "none"):
            add("LOW", "dmarc-missing", "no DMARC pass for the From domain")
    dates = [h["date"] for h in hops if h["date"]]
    if len(dates) >= 2 and any(newer < older for newer, older in zip(dates, dates[1:])):
        add("LOW", "timestamps-out-of-order", "relay timestamps go backwards, which can indicate tampering or clock errors")

    worst = min((SEV[f[0]] for f in findings if f[0] != "INFO"), default=9)
    verdict = ("HIGH RISK: strong signs of spoofing or forgery" if worst == 0 else
               "SUSPICIOUS: review before trusting" if worst == 1 else
               "minor oddities only" if worst == 2 else
               "no red flags in the headers (this does not prove the message is safe)")
    summary = {"From": from_hdr, "Reply-To": msg.get("Reply-To"), "Return-Path": msg.get("Return-Path"),
               "Subject": msg.get("Subject"), "Date": msg.get("Date"), "Message-ID": msg.get("Message-ID")}
    return {"summary": summary, "auth": auth, "hops": hops,
            "findings": sorted(findings, key=lambda f: SEV[f[0]]), "verdict": verdict}


def render(result):
    out = ["== Message =="]
    out += ["%-12s %s" % (k, " ".join(str(v).split())) for k, v in result["summary"].items() if v]
    a = result["auth"]
    out.append("\n== Authentication ==")
    out.append("SPF: %s   DKIM: %s   DMARC: %s" % (a["spf"] or "n/a", ",".join(a["dkim"]) or "n/a", a["dmarc"] or "n/a"))
    if result["hops"]:
        out.append("\n== Relay path (oldest first) ==")
        for i, h in enumerate(reversed(result["hops"]), 1):
            out.append("%d. from %s%s -> by %s%s" % (i, h["from"], " [%s]" % h["ip"] if h["ip"] else "", h["by"],
                                                    "  (%s)" % h["date"].strftime("%Y-%m-%d %H:%M %z") if h["date"] else ""))
    out.append("\n== Findings ==")
    if not result["findings"]:
        out.append("none")
    for sev, rule, text, fix in result["findings"]:
        out.append("%-6s %-24s %s%s" % (sev, rule, text, "\n         note: " + fix if fix else ""))
    out.append("\nVerdict: %s" % result["verdict"])
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Triage e-mail headers offline.")
    ap.add_argument("file", nargs="?", default="-", help="file with raw headers or a full message (default: stdin)")
    ap.add_argument("--version", action="version", version=__version__)
    args = ap.parse_args(argv)
    try:
        if args.file == "-":
            raw = sys.stdin.read()
        else:
            with open(args.file, errors="replace") as fh:
                raw = fh.read()
    except OSError as exc:
        print("mailtriage: %s" % exc, file=sys.stderr)
        return 2
    if ":" not in raw.split("\n\n", 1)[0]:
        print("mailtriage: input does not look like e-mail headers", file=sys.stderr)
        return 2
    result = analyze(raw)
    print(render(result))
    return 1 if any(f[0] in ("HIGH", "MEDIUM") for f in result["findings"]) else 0


if __name__ == "__main__":
    sys.exit(main())
