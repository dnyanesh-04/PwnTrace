from flask import (
    Blueprint,
    current_app,
    flash,
    render_template,
    request,
    send_file,
)

from app.services.attack_mapper import map_attack
from app.services.chain_generator import (
    generate_attack_paths,
)
from app.services.cve_service import search_cves
from app.services.export_service import (
    export_results,
)
from app.services.exploit_service import (
    search_exploits,
)
from app.services.graph_service import (
    build_graph,
)
from app.services.nmap_service import (
    run_nmap_scan,
)
from app.services.report_service import (
    generate_report,
)
from app.services.risk_service import (
    enrich_risk,
)


main = Blueprint(
    "main",
    __name__,
)


def _merge_cves(cves):
    """
    Deduplicate CVEs while retaining all discovered
    asset contexts.
    """
    merged = {}

    for cve in cves:
        cve_id = cve["id"]

        if cve_id not in merged:
            cve["matched_assets"] = list(
                cve.get(
                    "matched_assets",
                    [],
                )
            )

            merged[cve_id] = cve
            continue

        existing = merged[cve_id]

        assets = existing.setdefault(
            "matched_assets",
            [],
        )

        for asset in cve.get(
            "matched_assets",
            [],
        ):
            if asset not in assets:
                assets.append(asset)

        if cve.get(
            "match_score",
            0,
        ) > existing.get(
            "match_score",
            0,
        ):
            existing[
                "match_score"
            ] = cve[
                "match_score"
            ]

            existing[
                "match_reason"
            ] = cve.get(
                "match_reason",
                existing.get(
                    "match_reason"
                ),
            )

            existing[
                "correlation_confidence"
            ] = cve.get(
                "correlation_confidence",
                existing.get(
                    "correlation_confidence",
                    "low",
                ),
            )

            existing[
                "correlation_status"
            ] = cve.get(
                "correlation_status",
                existing.get(
                    "correlation_status"
                ),
            )

            existing[
                "matched_cpe"
            ] = cve.get(
                "matched_cpe",
                existing.get(
                    "matched_cpe"
                ),
            )

    return sorted(
        merged.values(),
        key=lambda item: (
            item.get(
                "priority_score",
                0,
            ),
            item.get(
                "match_score",
                0,
            ),
            item.get(
                "cvss",
                0,
            )
            or 0,
        ),
        reverse=True,
    )


@main.route(
    "/",
    methods=["GET", "POST"],
)
def home():
    if request.method == "POST":
        target = (
            request.form.get(
                "target",
                "",
            )
            .strip()
        )

        if not target:
            flash(
                "Please enter a target.",
                "error",
            )

            return render_template(
                "index.html",
                data=None,
                graph_html="",
            )

        try:
            scan_results = (
                run_nmap_scan(target)
            )

            if not scan_results:
                flash(
                    "Nmap completed but no services "
                    "were discovered.",
                    "error",
                )

                return render_template(
                    "index.html",
                    data=None,
                    graph_html="",
                )

            discovered_cves = []

            for item in scan_results:
                discovered_cves.extend(
                    search_cves(
                        service=item.get(
                            "service",
                            "",
                        ),
                        version=item.get(
                            "version",
                            "",
                        ),
                        product=item.get(
                            "product",
                            "",
                        ),
                        host=item.get(
                            "host",
                            "",
                        ),
                        port=item.get(
                            "port"
                        ),
                        protocol=item.get(
                            "protocol",
                            "tcp",
                        ),
                    )
                )

            cves = _merge_cves(
                discovered_cves
            )

            exploits = search_exploits(
                cves
            )

            enrich_risk(
                cves,
                exploits,
            )

            cves = cves[
                : current_app.config[
                    "MAX_CVES"
                ]
            ]

            selected_ids = {
                cve["id"]
                for cve in cves
            }

            exploits = [
                item
                for item in exploits
                if item.get(
                    "cve"
                )
                in selected_ids
            ]

            mitre = map_attack(
                cves
            )

            attack_paths = (
                generate_attack_paths(
                    scan_results=scan_results,
                    cves=cves,
                    mappings=mitre,
                    exploits=exploits,
                )
            )

            graph_html = build_graph(
                scan_results=scan_results,
                cves=cves,
                mappings=mitre,
                attack_paths=attack_paths,
            )

            export_results(
                target=target,
                scan_results=scan_results,
                cves=cves,
                exploits=exploits,
                mitre=mitre,
                attack_paths=attack_paths,
            )

            generate_report(
                target=target,
                scan_results=scan_results,
                cves=cves,
                exploits=exploits,
                mitre=mitre,
                attack_paths=attack_paths,
            )

            data = {
                "target": target,
                "scan_results": scan_results,
                "cves": cves,
                "exploits": exploits,
                "mitre": mitre,
                "attack_paths": attack_paths,
                "summary": {
                    "hosts": len(
                        {
                            x["host"]
                            for x in scan_results
                        }
                    ),
                    "services": len(
                        scan_results
                    ),
                    "cves": len(cves),
                    "strong_candidates": sum(
                        1
                        for x in cves
                        if x.get(
                            "correlation_confidence"
                        )
                        == "high"
                    ),
                    "candidate_cves": sum(
                        1
                        for x in cves
                        if x.get(
                            "correlation_confidence"
                        )
                        == "medium"
                    ),
                    "keyword_candidates": sum(
                        1
                        for x in cves
                        if x.get(
                            "correlation_confidence"
                        )
                        == "low"
                    ),
                    "critical": sum(
                        1
                        for x in cves
                        if x.get(
                            "severity"
                        )
                        == "CRITICAL"
                    ),
                    "high": sum(
                        1
                        for x in cves
                        if x.get(
                            "severity"
                        )
                        == "HIGH"
                    ),
                    "kev": sum(
                        1
                        for x in cves
                        if x.get(
                            "kev"
                        )
                    ),
                    "paths": len(
                        attack_paths.get(
                            "paths",
                            [],
                        )
                    ),
                },
            }

            return render_template(
                "index.html",
                data=data,
                graph_html=graph_html,
            )

        except ValueError as exc:
            flash(
                str(exc),
                "error",
            )

        except Exception as exc:
            current_app.logger.exception(
                "PwnTrace analysis failed"
            )

            flash(
                f"Analysis failed: {exc}",
                "error",
            )

    return render_template(
        "index.html",
        data=None,
        graph_html="",
    )


@main.get(
    "/download/pdf"
)
def download_pdf():
    return send_file(
        current_app.config[
            "REPORT_PATH"
        ],
        as_attachment=True,
        download_name="pwntrace-report.pdf",
    )


@main.get(
    "/download/json"
)
def download_json():
    return send_file(
        current_app.config[
            "JSON_PATH"
        ],
        as_attachment=True,
        download_name="pwntrace-results.json",
    )


@main.get(
    "/download/csv"
)
def download_csv():
    return send_file(
        current_app.config[
            "CSV_PATH"
        ],
        as_attachment=True,
        download_name="pwntrace-cves.csv",
    )


@main.get(
    "/health"
)
def health():
    return {
        "status": "ok",
        "service": "PwnTrace",
    }