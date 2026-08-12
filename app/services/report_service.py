import html

from flask import current_app
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import (
    ParagraphStyle,
    getSampleStyleSheet,
)
from reportlab.lib.units import mm
from reportlab.platypus import (
    Image,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.services.visualization_service import (
    create_cvss_chart,
)


def _p(text, style):
    return Paragraph(
        html.escape(
            str(text)
        ),
        style,
    )


def generate_report(
    target,
    scan_results,
    cves,
    exploits,
    mitre,
    attack_paths,
):
    report_dir = (
        current_app.config[
            "REPORT_DIR"
        ]
    )

    report_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    chart_path = (
        report_dir
        / "cvss_distribution.png"
    )

    create_cvss_chart(
        cves,
        chart_path,
    )

    doc = SimpleDocTemplate(
        str(
            current_app.config[
                "REPORT_PATH"
            ]
        ),
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm,
    )

    styles = getSampleStyleSheet()

    styles.add(
        ParagraphStyle(
            name="CenteredTitle",
            parent=styles["Title"],
            alignment=TA_CENTER,
            spaceAfter=10,
        )
    )

    styles.add(
        ParagraphStyle(
            name="Small",
            parent=styles["BodyText"],
            fontSize=8,
            leading=10,
        )
    )

    elements = [
        _p(
            "PwnTrace — Security Assessment Report",
            styles["CenteredTitle"],
        ),
        _p(
            f"Target: {target}",
            styles["Heading2"],
        ),
        Spacer(1, 8),
        _p(
            "Scope note: PwnTrace performs service "
            "discovery and vulnerability intelligence "
            "correlation. It does not execute exploits "
            "or claim that a generated path was "
            "successfully compromised.",
            styles["BodyText"],
        ),
        Spacer(1, 10),
        _p(
            "Executive Summary",
            styles["Heading2"],
        ),
    ]

    strong = sum(
        1
        for cve in cves
        if cve.get(
            "correlation_confidence"
        )
        == "high"
    )

    candidates = sum(
        1
        for cve in cves
        if cve.get(
            "correlation_confidence"
        )
        == "medium"
    )

    keyword_candidates = sum(
        1
        for cve in cves
        if cve.get(
            "correlation_confidence"
        )
        == "low"
    )

    summary = [
        ["Metric", "Value"],
        [
            "Discovered services",
            len(scan_results),
        ],
        [
            "CVE candidates",
            len(cves),
        ],
        [
            "Strong CPE candidates",
            strong,
        ],
        [
            "Medium-confidence candidates",
            candidates,
        ],
        [
            "Keyword-only candidates",
            keyword_candidates,
        ],
        [
            "Critical CVEs",
            sum(
                1
                for x in cves
                if x.get(
                    "severity"
                )
                == "CRITICAL"
            ),
        ],
        [
            "High CVEs",
            sum(
                1
                for x in cves
                if x.get(
                    "severity"
                )
                == "HIGH"
            ),
        ],
        [
            "CISA KEV CVEs",
            sum(
                1
                for x in cves
                if x.get("kev")
            ),
        ],
        [
            "Potential paths",
            len(
                attack_paths.get(
                    "paths",
                    [],
                )
            ),
        ],
    ]

    table = Table(
        summary,
        repeatRows=1,
        colWidths=[
            85 * mm,
            30 * mm,
        ],
    )

    table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor(
                        "#1f2937"
                    ),
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white,
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.4,
                    colors.grey,
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold",
                ),
                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
            ]
        )
    )

    elements += [
        table,
        Spacer(1, 12),
    ]

    if (
        chart_path.exists()
        and cves
    ):
        elements += [
            _p(
                "CVSS Distribution",
                styles["Heading2"],
            ),
            Image(
                str(chart_path),
                width=150 * mm,
                height=86 * mm,
            ),
            Spacer(1, 10),
        ]

    elements.append(
        _p(
            "Discovered Services",
            styles["Heading2"],
        )
    )

    service_rows = [
        [
            "Host",
            "Port",
            "Service",
            "Product",
            "Version",
        ]
    ]

    for item in scan_results:
        service_rows.append(
            [
                item.get("host"),
                item.get("port"),
                item.get("service"),
                item.get("product"),
                item.get("version"),
            ]
        )

    service_table = Table(
        service_rows,
        repeatRows=1,
    )

    service_table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor(
                        "#1f2937"
                    ),
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white,
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.3,
                    colors.grey,
                ),
                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
            ]
        )
    )

    elements += [
        service_table,
        Spacer(1, 12),
    ]

    elements.append(
        _p(
            "Vulnerability Correlation",
            styles["Heading2"],
        )
    )

    elements.append(
        _p(
            "CVE entries are candidates derived from "
            "NVD data. Correlation confidence indicates "
            "how strongly the observed service/product/"
            "version corresponds to NVD affected-CPE "
            "evidence. A candidate is not equivalent to "
            "a confirmed vulnerability.",
            styles["Small"],
        )
    )

    vuln_rows = [
        [
            "CVE",
            "CVSS",
            "Severity",
            "Correlation",
            "Match",
            "Priority",
        ]
    ]

    for cve in cves:
        vuln_rows.append(
            [
                cve.get("id"),
                cve.get(
                    "cvss",
                    "N/A",
                ),
                cve.get(
                    "severity"
                ),
                cve.get(
                    "correlation_confidence",
                    "low",
                ),
                cve.get(
                    "match_score",
                    0,
                ),
                cve.get(
                    "priority_score",
                    0,
                ),
            ]
        )

    vuln_table = Table(
        vuln_rows,
        repeatRows=1,
    )

    vuln_table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor(
                        "#1f2937"
                    ),
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white,
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.3,
                    colors.grey,
                ),
                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
            ]
        )
    )

    elements += [
        vuln_table,
        Spacer(1, 12),
    ]

    elements.append(
        _p(
            "Exploit Intelligence",
            styles["Heading2"],
        )
    )

    exploit_by_cve = {
    item.get("cve"): item
    for item in exploits
    if item.get("cve")
}

    for cve in cves:
        exploit = exploit_by_cve.get(
            cve["id"],
            {},
        )

        elements.append(
            _p(
                f"{cve['id']}: "
                f"{exploit.get('status', 'Unknown')}",
                styles["Small"],
            )
        )

    elements += [
        Spacer(1, 12),
        _p(
            "MITRE ATT&CK Hypotheses",
            styles["Heading2"],
        ),
    ]

    for mapping in mitre:
        if not mapping.get(
            "techniques"
        ):
            continue

        elements.append(
            _p(
                (
                    f"{mapping['cve']} — "
                    f"{mapping.get('service')}:"
                    f"{mapping.get('port')} — "
                    f"CVE correlation: "
                    f"{mapping.get('correlation_confidence')}"
                ),
                styles["Heading3"],
            )
        )

        for technique in mapping[
            "techniques"
        ]:
            elements.append(
                _p(
                    (
                        f"{technique['id']} "
                        f"{technique['name']} | "
                        f"{technique['tactic']} | "
                        f"Confidence: "
                        f"{technique['confidence']} | "
                        f"Type: "
                        f"{technique['mapping_type']} | "
                        f"Basis: "
                        f"{technique['evidence']}"
                    ),
                    styles["Small"],
                )
            )

    elements += [
        Spacer(1, 12),
        _p(
            "Potential Attack Paths",
            styles["Heading2"],
        ),
    ]

    for path in attack_paths.get(
        "paths",
        [],
    ):
        elements.append(
            _p(
                (
                    f"{path['path_id']} — "
                    f"{path['label']} | "
                    f"Score: {path['score']} | "
                    f"Confidence: "
                    f"{path['confidence']} | "
                    f"Complete: "
                    f"{path['complete']}"
                ),
                styles["Heading3"],
            )
        )

        for step in path.get(
            "steps",
            [],
        ):
            elements.append(
                _p(
                    (
                        f"Step {step['step']}: "
                        f"{step['phase']} — "
                        f"{step['cve']} — "
                        f"{step['technique_id']} "
                        f"{step['technique']} — "
                        f"{step['confidence']}"
                    ),
                    styles["Small"],
                )
            )

        for assumption in path.get(
            "assumptions",
            [],
        ):
            elements.append(
                _p(
                    f"Assumption: {assumption}",
                    styles["Small"],
                )
            )

        elements.append(
            Spacer(1, 6)
        )

    elements += [
        Spacer(1, 10),
        _p(
            "Methodology & Limitations",
            styles["Heading2"],
        ),
    ]

    for limitation in attack_paths.get(
        "limitations",
        [],
    ):
        elements.append(
            _p(
                f"• {limitation}",
                styles["Small"],
            )
        )

    doc.build(
        elements
    )

    return current_app.config[
        "REPORT_PATH"
    ]