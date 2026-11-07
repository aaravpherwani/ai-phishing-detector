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
