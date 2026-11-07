from backend.virustotal import _result_from_stats


def test_ratio_score_accounts_for_total_vendor_votes():
    result = _result_from_stats({
        "malicious": 2, "suspicious": 2, "harmless": 16,
        "undetected": 40, "timeout": 3,
    })
    assert result["total_votes"] == 20
    assert result["score"] == 1.5
    assert result["status"] == "mixed"
    assert result["checked"] is True


def test_all_malicious_votes_score_ten():
    result = _result_from_stats({"malicious": 8, "suspicious": 0, "harmless": 0})
    assert result["score"] == 10.0
    assert result["status"] == "malicious"


def test_all_harmless_votes_score_zero_and_are_clean():
    result = _result_from_stats({"malicious": 0, "suspicious": 0, "harmless": 12})
    assert result["score"] == 0.0
    assert result["status"] == "clean"


def test_zero_vote_report_is_not_treated_as_clean():
    result = _result_from_stats({"malicious": 0, "suspicious": 0, "harmless": 0})
    assert result["status"] == "insufficient"
    assert result["error"] == "insufficient_votes"
    assert result["checked"] is True
    assert result["total_votes"] == 0



def test_six_malicious_and_fifty_nine_harmless_votes_score_ratio():
    result = _result_from_stats({
        "malicious": 6, "suspicious": 0, "harmless": 59,
    })
    assert result["total_votes"] == 65
    assert result["score"] == 0.92
    assert result["status"] == "mixed"



def test_brand_in_subdomain_of_unrelated_domain_is_flagged():
    from backend.features import fake_domain_score

    assert fake_domain_score("https://google.account-security.verify-login.top/reset") >= 3


def test_google_owned_domain_is_not_flagged_as_brand_spoof():
    from backend.features import fake_domain_score

    assert fake_domain_score("https://google.com") == 0


def test_url_guardrail_overrides_safe_for_brand_spoof_and_suspicious_tld():
    from backend.predict import apply_url_verdict_guardrail

    analyses = [{
        "domain": "drive-google-docs-secure.site",
        "brand_spoof": "google",
        "suspicious_tld": True,
        "uses_ip": False,
        "is_shortened": False,
        "many_subdomains": False,
        "has_at_symbol": False,
        "has_hex_encoding": False,
        "is_http": False,
        "fake_brand_score": 3,
    }]
    label, confidence, note = apply_url_verdict_guardrail("SAFE", 0.73, analyses, 9)
    assert label == "PHISHING"
    assert confidence >= 0.85
    assert note


def test_shortened_url_is_eligible_for_reputation_lookup():
    from backend.predict import should_scan_url

    assert should_scan_url({
        "uses_ip": False, "is_shortened": True, "suspicious_tld": False,
        "many_subdomains": False, "has_at_symbol": False,
        "has_hex_encoding": False, "is_long": False, "is_http": False,
        "fake_brand_score": 0, "brand_spoof": None,
    }, 0)
