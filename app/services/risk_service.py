def _exploit_for(
    exploits,
    cve_id,
):
    return next(
        (
            item
            for item in exploits
            if item.get("cve")
            == cve_id
        ),
        {},
    )


def calculate_priority(
    cve,
    exploit,
):
    """
    Contextual prioritization.

    This is NOT CVSS.

    CVSS remains the vulnerability severity.
    PwnTrace priority adds evidence about:
    - correlation quality
    - network reachability
    - exploit intelligence
    - KEV
    - privileges
    - user interaction
    """
    cvss = cve.get("cvss")

    try:
        cvss = float(cvss)
    except (
        TypeError,
        ValueError,
    ):
        cvss = 0.0

    cvss_component = (
        cvss / 10.0
    ) * 55.0

    evidence_component = 0.0

    if exploit.get("kev"):
        evidence_component += 15.0

    if exploit.get(
        "exploitdb_references"
    ):
        evidence_component += 10.0

    if cve.get(
        "attack_vector"
    ) == "NETWORK":
        evidence_component += 8.0

    if cve.get(
        "privileges_required"
    ) == "NONE":
        evidence_component += 5.0

    if cve.get(
        "user_interaction"
    ) == "NONE":
        evidence_component += 5.0

    correlation_confidence = cve.get(
        "correlation_confidence",
        "low",
    )

    correlation_weight = {
        "high": 1.0,
        "medium": 0.70,
        "low": 0.25,
    }.get(
        correlation_confidence,
        0.25,
    )

    match_component = (
        min(
            float(
                cve.get(
                    "match_score",
                    0,
                )
            )
            / 10.0,
            1.0,
        )
        * 7.0
        * correlation_weight
    )

    return round(
        min(
            100.0,
            cvss_component
            + evidence_component
            + match_component,
        ),
        2,
    )


def enrich_risk(
    cves,
    exploits,
):
    for cve in cves:
        exploit = _exploit_for(
            exploits,
            cve["id"],
        )

        cve["priority_score"] = (
            calculate_priority(
                cve,
                exploit,
            )
        )

    cves.sort(
        key=lambda item: item.get(
            "priority_score",
            0,
        ),
        reverse=True,
    )

    return cves