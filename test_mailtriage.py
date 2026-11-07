import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock

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


class SuffixTests(unittest.TestCase):
    def test_org_domain_handles_two_level_suffixes(self):
        self.assertEqual(mt.org_domain("mail.example.co.uk"), "example.co.uk")
        self.assertEqual(mt.org_domain("example.co.uk"), "example.co.uk")
        self.assertEqual(mt.org_domain("news.example.com.tr"), "example.com.tr")
        self.assertEqual(mt.org_domain("a.b.example.com"), "example.com")
        self.assertEqual(mt.org_domain("example.com"), "example.com")
        self.assertEqual(mt.org_domain("localhost"), "localhost")

    def test_two_organisations_under_the_same_suffix_are_different(self):
        raw = variant("Return-Path: <news@example.com>", "Return-Path: <x@attacker.co.uk>").replace(
            "From: Example News <news@example.com>", "From: Example News <news@victim.co.uk>")
        self.assertIn(("LOW", "return-path-mismatch"), rules(raw))

    def test_same_organisation_under_co_uk_is_aligned(self):
        raw = variant("Return-Path: <news@example.com>", "Return-Path: <b@bounce.example.co.uk>").replace(
            "From: Example News <news@example.com>", "From: Example News <news@mail.example.co.uk>")
        self.assertNotIn("return-path-mismatch", {r for _, r in rules(raw)})


class LookalikeTests(unittest.TestCase):
    def test_typos_and_confusables(self):
        for dom in ("paypa1.com", "paypall.com", "rnicrosoft.com", "arnazon.com", "gooogle.com", "mail.paypa1.com"):
            self.assertIsNotNone(mt.lookalike_of(dom), dom)

    def test_real_domains_and_unrelated_domains_are_fine(self):
        for dom in ("paypal.com", "mail.google.com", "example.com", "mycompany.io", "paypal.com.evil.example"):
            self.assertIsNone(mt.lookalike_of(dom), dom)

    def test_short_domains_are_skipped(self):
        self.assertIsNone(mt.lookalike_of("x.us"))

    def test_rule_fires_in_analysis(self):
        raw = GOOD.replace("example.com", "paypa1.com")
        self.assertIn(("MEDIUM", "lookalike-domain"), rules(raw))

    def test_clean_message_has_no_lookalike(self):
        self.assertNotIn("lookalike-domain", {r for _, r in rules(GOOD)})

    def test_idna_display(self):
        self.assertEqual(mt.decode_idna("xn--e1afmkfd.xn--p1ai"), "пример.рф")
        self.assertEqual(mt.decode_idna("plain.example"), "plain.example")
        self.assertEqual(mt.decode_idna("xn--!!!"), "xn--!!!")

    def test_punycode_finding_shows_unicode_form(self):
        raw = GOOD.replace("news@example.com", "news@xn--e1afmkfd.xn--p1ai")
        found = [f for f in mt.analyze(raw)["findings"] if f[1] == "punycode-domain"]
        self.assertIn("пример.рф", found[0][2])


class SpfAlignmentTests(unittest.TestCase):
    def test_spf_pass_for_other_domain(self):
        raw = variant("spf=pass smtp.mailfrom=example.com", "spf=pass smtp.mailfrom=bounce.sender.example")
        self.assertIn(("LOW", "spf-misaligned"), rules(raw))

    def test_aligned_spf_is_fine(self):
        self.assertNotIn("spf-misaligned", {r for _, r in rules(GOOD)})

    def test_subdomain_alignment_is_fine(self):
        raw = variant("smtp.mailfrom=example.com", "smtp.mailfrom=bounces.example.com")
        self.assertNotIn("spf-misaligned", {r for _, r in rules(raw)})


def run_main(*argv, stdin=""):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), mock.patch("sys.stdin", io.StringIO(stdin)):
        code = mt.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    BAD = GOOD.replace("spf=pass", "spf=fail").replace("dmarc=pass", "dmarc=fail")

    def test_json_single_message(self):
        code, out, _ = run_main("--json", stdin=self.BAD)
        data = json.loads(out)
        self.assertEqual(code, 1)
        self.assertEqual(data["auth"]["spf"], "fail")
        self.assertEqual(data["hops"][0]["ip"], "203.0.113.10")
        self.assertIn("T", data["hops"][0]["date"])  # ISO timestamps
        self.assertIn("spf-fail", {f["rule"] for f in data["findings"]})
        self.assertTrue(data["verdict"].startswith("HIGH RISK"))
        self.assertNotIn("raw", data["auth"])

    def test_json_clean(self):
        code, out, _ = run_main("--json", stdin=GOOD)
        self.assertEqual((code, json.loads(out)["findings"]), (0, []))

    def test_several_files(self):
        with tempfile.TemporaryDirectory() as d:
            a, b = os.path.join(d, "a.eml"), os.path.join(d, "b.eml")
            for path, text in ((a, GOOD), (b, self.BAD)):
                with open(path, "w") as fh:
                    fh.write(text)
            code, out, _ = run_main(a, b, "--json")
            data = json.loads(out)
            self.assertEqual((code, len(data)), (1, 2))
            self.assertEqual([d_["file"] for d_ in data], [a, b])
            code, out, _ = run_main(a, b)
            self.assertIn("######## " + a, out)
            self.assertEqual(run_main(a)[0], 0)

    def test_one_bad_input_stops_with_exit_2(self):
        with tempfile.TemporaryDirectory() as d:
            a = os.path.join(d, "a.eml")
            with open(a, "w") as fh:
                fh.write(GOOD)
            self.assertEqual(run_main(a, os.path.join(d, "missing.eml"))[0], 2)

    def test_not_headers(self):
        code, _, err = run_main(stdin="just some prose without headers")
        self.assertEqual(code, 2)
        self.assertIn("does not look like", err)

    def test_text_output_unchanged_for_single_input(self):
        _, out, _ = run_main(stdin=GOOD)
        self.assertTrue(out.startswith("== Message =="))
        self.assertNotIn("########", out)


if __name__ == "__main__":
    unittest.main()
