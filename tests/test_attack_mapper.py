from app.services.attack_mapper import map_attack


def test_command_injection_maps_to_execution():
    cves = [
        {
            "id": "CVE-TEST-1",
            "description": "A remote code execution vulnerability allows command injection.",
            "service": "http",
            "port": 80,
            "attack_vector": "NETWORK",
            "cwe": ["CWE-78"],
        }
    ]

    result = map_attack(cves)
    ids = {x["id"] for x in result[0]["techniques"]}

    assert "T1059" in ids
    assert "T1190" in ids
