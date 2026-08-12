import json

import pandas as pd
from flask import current_app


def export_results(
    target,
    scan_results,
    cves,
    exploits,
    mitre,
    attack_paths,
):
    export_dir = (
        current_app.config[
            "EXPORT_DIR"
        ]
    )

    export_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    payload = {
        "tool": "PwnTrace",
        "version": "2.1",
        "target": target,
        "scan_results": scan_results,
        "cve_candidates": cves,
        "exploit_intelligence": exploits,
        "mitre_attack_hypotheses": mitre,
        "potential_attack_paths": attack_paths,
        "methodology": {
            "cve_correlation": (
                "NVD keyword retrieval followed by "
                "affected-CPE evidence analysis."
            ),
            "attack_mapping": (
                "Heuristic ATT&CK hypotheses based "
                "on NVD description, CWE and service "
                "evidence."
            ),
            "exploitation": (
                "No automatic exploitation is performed."
            ),
        },
    }

    with current_app.config[
        "JSON_PATH"
    ].open(
        "w",
        encoding="utf-8",
    ) as handle:
        json.dump(
            payload,
            handle,
            indent=2,
            ensure_ascii=False,
            default=str,
        )

    rows = []

    exploit_by_cve = {
        item["cve"]: item
        for item in exploits
    }

    technique_by_cve = {}

    for mapping in mitre:
        technique_by_cve[
            mapping["cve"]
        ] = mapping.get(
            "techniques",
            [],
        )

    for cve in cves:
        exploit = exploit_by_cve.get(
            cve["id"],
            {},
        )

        techniques = (
            technique_by_cve.get(
                cve["id"],
                [],
            )
        )

        rows.append(
            {
                "CVE": cve["id"],
                "Host": cve.get(
                    "host"
                ),
                "Port": cve.get(
                    "port"
                ),
                "Protocol": cve.get(
                    "protocol"
                ),
                "Service": cve.get(
                    "service"
                ),
                "Product": cve.get(
                    "product"
                ),
                "Version": cve.get(
                    "version"
                ),
                "Correlation Status": cve.get(
                    "correlation_status"
                ),
                "Correlation Confidence": cve.get(
                    "correlation_confidence"
                ),
                "Match Score": cve.get(
                    "match_score"
                ),
                "Match Reason": cve.get(
                    "match_reason"
                ),
                "Matched CPE": cve.get(
                    "matched_cpe"
                ),
                "CVSS": cve.get(
                    "cvss"
                ),
                "CVSS Version": cve.get(
                    "cvss_version"
                ),
                "Severity": cve.get(
                    "severity"
                ),
                "Attack Vector": cve.get(
                    "attack_vector"
                ),
                "Privileges Required": cve.get(
                    "privileges_required"
                ),
                "User Interaction": cve.get(
                    "user_interaction"
                ),
                "Priority Score": cve.get(
                    "priority_score"
                ),
                "KEV": cve.get(
                    "kev"
                ),
                "Exploit Intelligence": exploit.get(
                    "status"
                ),
                "ATT&CK Hypotheses": "; ".join(
                    (
                        f"{item['id']} "
                        f"{item['name']} "
                        f"({item['confidence']})"
                    )
                    for item in techniques
                ),
                "NVD URL": cve.get(
                    "nvd_url"
                ),
            }
        )

    pd.DataFrame(
        rows
    ).to_csv(
        current_app.config[
            "CSV_PATH"
        ],
        index=False,
    )

    return current_app.config[
        "JSON_PATH"
    ]