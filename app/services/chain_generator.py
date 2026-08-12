PHASE_ORDER = [
    "Initial Access",
    "Execution",
    "Privilege Escalation",
    "Credential Access",
    "Lateral Movement",
]


PHASE_TECHNIQUES = {
    "Initial Access": {"T1190"},
    "Execution": {"T1059"},
    "Privilege Escalation": {"T1068"},
    "Credential Access": {"T1552.001"},
    "Lateral Movement": {"T1210"},
}


def _confidence_label(value):
    if value >= 0.80:
        return "High"

    if value >= 0.60:
        return "Medium"

    return "Low"


def _technique_index(mappings):
    index = {}

    for mapping in mappings:
        for technique in mapping.get(
            "techniques",
            [],
        ):
            index.setdefault(
                technique["id"],
                [],
            ).append(
                {
                    "cve": mapping["cve"],
                    "host": mapping.get("host"),
                    "port": mapping.get("port"),
                    "service": mapping.get("service"),
                    "technique": technique,
                    "correlation_confidence": mapping.get(
                        "correlation_confidence",
                        "low",
                    ),
                }
            )

    return index


def _cve_priority(
    cves,
    cve_id,
):
    for cve in cves:
        if cve["id"] == cve_id:
            return float(
                cve.get(
                    "priority_score",
                    0,
                )
            )

    return 0.0


def _candidate_score(
    candidate,
    cves,
    initial_host=None,
):
    technique = candidate["technique"]

    correlation_weight = {
        "high": 1.0,
        "medium": 0.75,
        "low": 0.40,
    }.get(
        candidate.get(
            "correlation_confidence",
            "low",
        ),
        0.40,
    )

    host_continuity = (
        1.0
        if (
            initial_host
            and candidate.get("host")
            == initial_host
        )
        else 0.0
    )

    priority = _cve_priority(
        cves,
        candidate["cve"],
    )

    return (
        priority
        * technique.get(
            "confidence_score",
            0.40,
        )
        * correlation_weight
        + host_continuity * 5
    )


def _best_candidate(
    candidates,
    cves,
    initial_host=None,
):
    if not candidates:
        return None

    return max(
        candidates,
        key=lambda item: _candidate_score(
            item,
            cves,
            initial_host,
        ),
    )


def _step(candidate, number, phase):
    technique = candidate["technique"]

    return {
        "step": number,
        "phase": phase,
        "cve": candidate["cve"],
        "technique_id": technique["id"],
        "technique": technique["name"],
        "host": candidate.get("host"),
        "port": candidate.get("port"),
        "service": candidate.get("service"),
        "confidence": _confidence_label(
            technique.get(
                "confidence_score",
                0.40,
            )
        ),
        "evidence": technique.get(
            "evidence",
            "",
        ),
        "mapping_type": technique.get(
            "mapping_type",
            "heuristic",
        ),
    }


def _build_path(
    initial,
    cves,
    index,
    path_number,
):
    steps = []

    initial_host = initial.get("host")

    steps.append(
        _step(
            initial,
            1,
            "Initial Access",
        )
    )

    for phase in PHASE_ORDER[1:]:
        candidates = []

        for technique_id in PHASE_TECHNIQUES[
            phase
        ]:
            candidates.extend(
                index.get(
                    technique_id,
                    [],
                )
            )

        candidate = _best_candidate(
            candidates,
            cves,
            initial_host,
        )

        if candidate is None:
            continue

        steps.append(
            _step(
                candidate,
                len(steps) + 1,
                phase,
            )
        )

    confidences = [
        {
            "High": 1.0,
            "Medium": 0.65,
            "Low": 0.40,
        }.get(
            step["confidence"],
            0.40,
        )
        for step in steps
    ]

    priorities = [
        _cve_priority(
            cves,
            step["cve"],
        )
        for step in steps
    ]

    average_priority = (
        sum(priorities)
        / len(priorities)
        if priorities
        else 0
    )

    path_score = round(
        average_priority
        * min(confidences),
        2,
    )

    phases_present = [
        step["phase"]
        for step in steps
    ]

    complete = (
        phases_present
        == PHASE_ORDER
    )

    if complete:
        label = (
            f"Potential multi-stage attack path "
            f"{path_number}"
        )

    elif len(steps) > 1:
        label = (
            f"Partial potential attack path "
            f"{path_number}"
        )

    else:
        label = (
            f"Single-technique hypothesis "
            f"{path_number}"
        )

    assumptions = [
        "Nmap service and version identification "
        "is assumed to be accurate.",
        "CVE correlation is based on NVD evidence "
        "and may still require manual validation.",
        "ATT&CK mappings are heuristic hypotheses, "
        "not official CVE-to-technique assertions.",
        "No exploitation or post-compromise state "
        "was verified by PwnTrace.",
    ]

    if any(
        step["phase"]
        == "Lateral Movement"
        for step in steps
    ):
        assumptions.append(
            "Lateral movement represents a potential "
            "remote-service opportunity. A second "
            "compromised host is not inferred."
        )

    return {
        "path_id": f"P{path_number}",
        "label": label,
        "score": path_score,
        "confidence": _confidence_label(
            min(confidences)
        ),
        "complete": complete,
        "step_count": len(steps),
        "phases": phases_present,
        "steps": steps,
        "assumptions": assumptions,
    }


def generate_attack_paths(
    scan_results,
    cves,
    mappings,
    exploits,
):
    """
    Generate potential attack-path hypotheses.

    This function deliberately does NOT claim exploitation.

    A complete path requires evidence-backed hypotheses for all
    configured phases. Otherwise the result is explicitly partial
    or a single-technique hypothesis.
    """
    index = _technique_index(
        mappings
    )

    paths = []

    initial_candidates = list(
        index.get(
            "T1190",
            [],
        )
    )

    initial_candidates.sort(
        key=lambda item: (
            _cve_priority(
                cves,
                item["cve"],
            ),
            item["technique"].get(
                "confidence_score",
                0,
            ),
        ),
        reverse=True,
    )

    for number, initial in enumerate(
        initial_candidates[:3],
        start=1,
    ):
        paths.append(
            _build_path(
                initial,
                cves,
                index,
                number,
            )
        )

    # If no Initial Access hypothesis exists, do not manufacture one.
    if not paths:
        partial_candidates = []

        for phase in PHASE_ORDER[1:]:
            for technique_id in PHASE_TECHNIQUES[
                phase
            ]:
                partial_candidates.extend(
                    index.get(
                        technique_id,
                        [],
                    )
                )

        if partial_candidates:
            partial_candidates.sort(
                key=lambda item: (
                    _cve_priority(
                        cves,
                        item["cve"],
                    ),
                    item["technique"].get(
                        "confidence_score",
                        0,
                    ),
                ),
                reverse=True,
            )

            candidate = (
                partial_candidates[0]
            )

            technique = candidate[
                "technique"
            ]

            confidence = technique.get(
                "confidence_score",
                0.40,
            )

            paths.append(
                {
                    "path_id": "P1",
                    "label": (
                        "Partial post-exposure "
                        "hypothesis"
                    ),
                    "score": round(
                        _cve_priority(
                            cves,
                            candidate["cve"],
                        )
                        * confidence,
                        2,
                    ),
                    "confidence": _confidence_label(
                        confidence
                    ),
                    "complete": False,
                    "step_count": 1,
                    "phases": [
                        technique["tactic"]
                    ],
                    "steps": [
                        _step(
                            candidate,
                            1,
                            technique[
                                "tactic"
                            ],
                        )
                    ],
                    "assumptions": [
                        "No evidence-backed Initial "
                        "Access mapping was found.",
                        "This is a partial analytical "
                        "hypothesis, not a confirmed "
                        "attack chain.",
                    ],
                }
            )

    return {
        "paths": paths,
        "limitations": [
            "PwnTrace performs reconnaissance and "
            "vulnerability intelligence correlation; "
            "it does not execute exploits.",
            "CVE candidates require manual validation "
            "against the actual installed product and "
            "version.",
            "ATT&CK mappings are heuristic hypotheses.",
            "Network topology, credentials, firewall "
            "rules and successful compromise are not "
            "established by this scan alone.",
        ],
    }