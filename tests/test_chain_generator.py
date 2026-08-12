from app.services.chain_generator import generate_attack_paths


def test_attack_path_does_not_fabricate_missing_phases():
    cves = [
        {
            "id": "CVE-TEST-1",
            "priority_score": 80,
            "host": "127.0.0.1",
            "port": 80,
            "service": "http",
        }
    ]

    mappings = [
        {
            "cve": "CVE-TEST-1",
            "host": "127.0.0.1",
            "port": 80,
            "service": "http",
            "techniques": [
                {
                    "id": "T1190",
                    "name": "Exploit Public-Facing Application",
                    "tactic": "Initial Access",
                    "confidence": "Medium",
                    "confidence_score": 0.65,
                    "evidence": "test",
                }
            ],
        }
    ]

    result = generate_attack_paths([], cves, mappings, [])
    assert len(result["paths"]) == 1
    assert len(result["paths"][0]["steps"]) == 1
    assert result["paths"][0]["complete"] is False
