# mailtriage

Triage the headers of a suspicious e-mail, **offline**. Paste or pipe the raw headers
(in your mail client: *Show original* / *View source*) and get SPF, DKIM and DMARC
results, From / Reply-To / Return-Path mismatches, the relay path and a risk verdict.
Only headers are examined: nothing is sent anywhere and no links are opened.
One file, standard library only.

## Usage

```bash
python3 mailtriage.py message.eml
pbpaste | python3 mailtriage.py -          # macOS: headers from the clipboard
```

Example output (abridged):

```
== Authentication ==
SPF: fail   DKIM: none   DMARC: fail

== Findings ==
HIGH   spf-fail           SPF fail: the sending server is not authorised for the domain
HIGH   dmarc-fail         DMARC failed: the From domain is not authenticated for this message
HIGH   display-name-spoof display name shows ceo@example.com but the real sender is x@example.org
MEDIUM reply-to-mismatch  Reply-To domain (example.net) differs from From domain (example.com)

Verdict: HIGH RISK: strong signs of spoofing or forgery
```

## What it checks

| Rule | Severity | Meaning |
|------|----------|---------|
| `spf-fail`, `dkim-fail`, `dmarc-fail`, `multiple-from`, `display-name-spoof` | HIGH | failed authentication, several `From` headers, a display name that shows a different address than the real one |
| `spf-softfail`, `reply-to-mismatch`, `punycode-domain`, `no-from` | MEDIUM | probable unauthorised sender, replies routed to another organisation, look-alike (punycode) domains |
| `return-path-mismatch`, `message-id-mismatch`, `dkim-misaligned`, `spf/dkim/dmarc-missing`, `timestamps-out-of-order`, `no-date` | LOW | oddities that are common in legitimate bulk mail but worth a look |
| `no-auth-results` | INFO | no authentication headers present, so authenticity cannot be judged |

It reads the **topmost** `Authentication-Results` header, which is the one added by your
own receiving server, and falls back to `Received-SPF`. The relay path is listed oldest hop first.

Exit codes: `0` no findings at MEDIUM or above, `1` MEDIUM/HIGH findings, `2` unreadable input.

## Limits

- Headers only: it does not look at the body, links or attachments, so "no red flags" is
  not proof that a message is safe.
- Headers from a forwarded copy or a different mailbox may lack the original authentication results.
- Domain alignment uses the last two labels (it does not know public suffixes such as `co.uk`).
- It trusts the receiving server's results; it does not query DNS itself.

## Tests

```bash
python3 -m unittest -v
```

## License

MIT (c) TPOALOS
