import os
import tempfile
import unittest

import mailtriage as mt

GOOD = """Return-Path: <news@example.com>
Received: from mail.example.com (mail.example.com [203.0.113.10])
 by mx.example.net with ESMTPS; Tue, 5 Mar 2030 10:00:05 +0000
Received: from app01.example.com (app01 [10.0.0.5])
 by mail.example.com with SMTP; Tue, 5 Mar 2030 10:00:01 +0000
Authentication-Results: mx.example.net;
 spf=pass smtp.mailfrom=example.com;
 dkim=pass header.d=example.com;
 dmarc=pass header.from=example.com
From: Example News <news@example.com>
To: you@example.net
Subject: Weekly update
Date: Tue, 5 Mar 2030 10:00:00 +0000
Message-ID: <abc123@example.com>

body ignored
"""


def rules(raw):
    return {(f[0], f[1]) for f in mt.analyze(raw)["findings"]}


def variant(old, new):
    assert old in GOOD, old
    return GOOD.replace(old, new)


class AnalyzeTests(unittest.TestCase):
    def test_good_message_clean(self):
        r = mt.analyze(GOOD)
        self.assertEqual(r["findings"], [])
        self.assertTrue(r["verdict"].startswith("no red flags"))
        self.assertEqual(r["auth"]["spf"], "pass")
        self.assertEqual(r["auth"]["dkim"], ["pass"])
        self.assertEqual(len(r["hops"]), 2)
        self.assertEqual(r["hops"][0]["ip"], "203.0.113.10")

    def test_spf_dkim_dmarc_failures(self):
        bad = variant("spf=pass", "spf=fail").replace("dkim=pass", "dkim=fail").replace("dmarc=pass", "dmarc=fail")
        r = rules(bad)
        for e in (("HIGH", "spf-fail"), ("HIGH", "dkim-fail"), ("HIGH", "dmarc-fail")):
            self.assertIn(e, r)
        self.assertTrue(mt.analyze(bad)["verdict"].startswith("HIGH RISK"))

    def test_softfail(self):
        self.assertIn(("MEDIUM", "spf-softfail"), rules(variant("spf=pass", "spf=softfail")))

    def test_received_spf_fallback(self):
        raw = "Received-SPF: pass (example)\nFrom: a@example.com\nDate: x\n\n"
        self.assertEqual(mt.analyze(raw)["auth"]["spf"], "pass")

    def test_no_auth_headers_is_info(self):
        raw = "From: a@example.com\nDate: Tue, 5 Mar 2030 10:00:00 +0000\n\n"
        self.assertIn(("INFO", "no-auth-results"), rules(raw))

    def test_reply_to_mismatch(self):
        self.assertIn(("MEDIUM", "reply-to-mismatch"),
                      rules(variant("To: you@example.net", "Reply-To: boss@example.org\nTo: you@example.net")))

    def test_subdomains_are_aligned(self):
        r = rules(variant("To: you@example.net", "Reply-To: help@support.example.com\nTo: you@example.net"))
        self.assertNotIn(("MEDIUM", "reply-to-mismatch"), r)

    def test_display_name_spoof(self):
        r = rules(variant("From: Example News <news@example.com>", 'From: "ceo@example.com" <x@example.org>'))
        self.assertIn(("HIGH", "display-name-spoof"), r)

    def test_multiple_from(self):
        self.assertIn(("HIGH", "multiple-from"), rules(variant("To: you", "From: other@example.org\nTo: you")))

    def test_punycode(self):
        self.assertIn(("MEDIUM", "punycode-domain"),
                      rules(variant("news@example.com>", "news@xn--exmple-cua.com>").replace("Return-Path: <news@example.com>", "Return-Path: <news@xn--exmple-cua.com>")))

    def test_return_path_and_message_id_mismatch_are_low(self):
        r = rules(variant("Return-Path: <news@example.com>", "Return-Path: <b@mailer.example.org>")
                  .replace("<abc123@example.com>", "<abc123@other.example.org>"))
        self.assertIn(("LOW", "return-path-mismatch"), r)
        self.assertIn(("LOW", "message-id-mismatch"), r)

    def test_dkim_misaligned(self):
        self.assertIn(("LOW", "dkim-misaligned"), rules(variant("header.d=example.com", "header.d=esp.example.org")))

    def test_timestamps_out_of_order(self):
        bad = variant("10:00:01 +0000", "11:30:00 +0000")
        self.assertIn(("LOW", "timestamps-out-of-order"), rules(bad))

    def test_missing_dkim_and_dmarc(self):
        raw = variant("dkim=pass header.d=example.com;\n dmarc=pass header.from=example.com", "dkim=none")
        r = rules(raw)
        self.assertIn(("LOW", "dkim-missing"), r)
        self.assertIn(("LOW", "dmarc-missing"), r)

    def test_render_has_sections(self):
        text = mt.render(mt.analyze(GOOD))
        for part in ("== Message ==", "== Authentication ==", "== Relay path", "Verdict:"):
            self.assertIn(part, text)


class CliTests(unittest.TestCase):
    def test_cli(self):
        with tempfile.TemporaryDirectory() as d:
            ok = os.path.join(d, "ok.eml")
            bad = os.path.join(d, "bad.eml")
            with open(ok, "w") as fh:
                fh.write(GOOD)
            with open(bad, "w") as fh:
                fh.write(variant("spf=pass", "spf=fail"))
            self.assertEqual(mt.main([ok]), 0)
            self.assertEqual(mt.main([bad]), 1)
            junk = os.path.join(d, "junk.txt")
            with open(junk, "w") as fh:
                fh.write("hello world without headers")
            self.assertEqual(mt.main([junk]), 2)
            self.assertEqual(mt.main([os.path.join(d, "nope")]), 2)


if __name__ == "__main__":
    unittest.main()
