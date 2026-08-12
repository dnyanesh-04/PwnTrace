from app.services.risk_service import calculate_priority


def test_kev_and_exploit_evidence_raise_priority():
    cve = {
        "cvss": 8.8,
        "attack_vector": "NETWORK",
        "privileges_required": "NONE",
        "user_interaction": "NONE",
        "match_score": 8,
    }

    without_evidence = calculate_priority(
        cve,
        {"kev": False, "exploitdb_references": []},
    )
    with_evidence = calculate_priority(
        cve,
        {"kev": True, "exploitdb_references": ["https://www.exploit-db.com/"]},
    )

    assert with_evidence > without_evidence
