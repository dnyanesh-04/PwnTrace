import re
from functools import lru_cache

import nvdlib
from flask import current_app


CPE_PATTERN = re.compile(
    r"cpe:2\.3:[^:\s]+:"
    r"(?P<vendor>[^:\s]+):"
    r"(?P<product>[^:\s]+):"
    r"(?P<version>[^:\s]+)"
    r"(?::[^:\s]*){7}",
    flags=re.IGNORECASE,
)


def _value(obj, key, default=None):
    if isinstance(obj, dict):
        return obj.get(key, default)

    return getattr(obj, key, default)


def _description(cve):
    descriptions = _value(cve, "descriptions", []) or []

    for item in descriptions:
        if _value(item, "lang") == "en":
            return _value(item, "value", "") or ""

    if descriptions:
        return _value(descriptions[0], "value", "") or ""

    return ""


def _extract_cwes(cve):
    raw = _value(cve, "cwe", []) or []
    text = str(raw)

    return sorted(
        set(
            re.findall(
                r"CWE-\d+",
                text,
                flags=re.IGNORECASE,
            )
        )
    )


def _extract_reference_urls(cve):
    urls = []

    for ref in _value(cve, "references", []) or []:
        url = _value(ref, "url")

        if url and url not in urls:
            urls.append(url)

    return urls


def _extract_cpes(cve):
    """
    Extract CPE 2.3 strings from nvdlib's CVE object.

    nvdlib versions can expose configuration information slightly
    differently, so this intentionally walks the object recursively.
    """
    found = set()

    def walk(value):
        if value is None:
            return

        if isinstance(value, str):
            for match in re.findall(
                r"cpe:2\.3:[^'\"\s,}\]]+",
                value,
                flags=re.IGNORECASE,
            ):
                found.add(match.rstrip(".,;"))

            return

        if isinstance(value, dict):
            for child in value.values():
                walk(child)

            return

        if isinstance(value, (list, tuple, set)):
            for child in value:
                walk(child)

            return

        # nvdlib objects generally expose useful attributes through __dict__.
        try:
            for child in vars(value).values():
                walk(child)
        except TypeError:
            pass

    walk(cve)

    return sorted(found)


def _parse_cpe(cpe):
    """
    Return the vendor/product/version portion of a CPE 2.3 name.

    Example:
    cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*
    """
    match = CPE_PATTERN.search(cpe or "")

    if not match:
        return None

    return {
        "vendor": match.group("vendor").lower(),
        "product": match.group("product").lower(),
        "version": match.group("version").lower(),
    }


def _normalise(value):
    value = (value or "").lower().strip()

    return re.sub(
        r"[^a-z0-9]+",
        "_",
        value,
    ).strip("_")


def _product_tokens(value):
    value = _normalise(value)

    if not value:
        return set()

    return {
        token
        for token in value.split("_")
        if len(token) >= 3
    }


def _version_matches(observed_version, cpe_version):
    """
    Conservative version comparison.

    We intentionally do NOT claim that an observed version is affected
    when the CPE only contains a wildcard or an unknown version.
    """
    observed = (observed_version or "").strip().lower()
    affected = (cpe_version or "").strip().lower()

    if not observed or not affected:
        return False

    if affected in {"*", "-", ""}:
        return False

    return observed == affected


def _cpe_match_score(
    service,
    product,
    observed_version,
    cpes,
):
    """
    Score how strongly an NVD CVE's affected CPE data corresponds
    to the service/product/version discovered by Nmap.

    Maximum: 10.

    10 = vendor/product/version evidence
    8  = product + exact version
    5  = product evidence only
    0  = no useful CPE evidence
    """
    observed_product_tokens = _product_tokens(product)
    observed_service_tokens = _product_tokens(service)

    best_score = 0
    reasons = []
    matched_cpe = None

    for cpe in cpes:
        parsed = _parse_cpe(cpe)

        if not parsed:
            continue

        cpe_product = _normalise(parsed["product"])
        cpe_vendor = _normalise(parsed["vendor"])

        cpe_tokens = _product_tokens(cpe_product)

        product_match = bool(
            observed_product_tokens
            and (
                observed_product_tokens.intersection(cpe_tokens)
                or cpe_product in observed_product_tokens
            )
        )

        service_match = bool(
            observed_service_tokens
            and (
                observed_service_tokens.intersection(cpe_tokens)
                or cpe_product in observed_service_tokens
            )
        )

        exact_version = _version_matches(
            observed_version,
            parsed["version"],
        )

        score = 0
        local_reasons = []

        if product_match:
            score += 5
            local_reasons.append("product matches affected CPE")

        elif service_match:
            score += 3
            local_reasons.append("service matches affected CPE")

        if exact_version:
            score += 5
            local_reasons.append("exact observed version matches affected CPE")

        if score > best_score:
            best_score = score
            reasons = local_reasons
            matched_cpe = cpe

    return min(best_score, 10), reasons, matched_cpe


def _cvss(cve):
    candidates = [
        ("3.1", "v31score", "v31severity", "v31vector"),
        ("3.0", "v30score", "v30severity", "v30vector"),
        ("2.0", "v2score", "v2severity", "v2vector"),
    ]

    for version, score_key, severity_key, vector_key in candidates:
        score = _value(cve, score_key)

        if score is None:
            continue

        try:
            score = float(score)
        except (TypeError, ValueError):
            score = None

        attack_vector_key = {
            "3.1": "v31attackVector",
            "3.0": "v30attackVector",
            "2.0": "v2accessVector",
        }[version]

        privileges_key = {
            "3.1": "v31privilegesRequired",
            "3.0": "v30privilegesRequired",
        }.get(version)

        interaction_key = {
            "3.1": "v31userInteraction",
            "3.0": "v30userInteraction",
        }.get(version)

        exploitability_key = {
            "3.1": "v31exploitability",
            "3.0": "v30exploitability",
            "2.0": "v2exploitability",
        }[version]

        impact_key = {
            "3.1": "v31impactScore",
            "3.0": "v30impactScore",
            "2.0": "v2impactScore",
        }[version]

        return {
            "score": score,
            "severity": str(
                _value(cve, severity_key, "UNKNOWN")
            ).upper(),
            "version": version,
            "vector": _value(cve, vector_key, ""),
            "attack_vector": _value(
                cve,
                attack_vector_key,
            ),
            "privileges_required": (
                _value(cve, privileges_key)
                if privileges_key
                else None
            ),
            "user_interaction": (
                _value(cve, interaction_key)
                if interaction_key
                else None
            ),
            "exploitability": _value(
                cve,
                exploitability_key,
            ),
            "impact_score": _value(
                cve,
                impact_key,
            ),
        }

    return {
        "score": None,
        "severity": "UNKNOWN",
        "version": None,
        "vector": "",
        "attack_vector": None,
        "privileges_required": None,
        "user_interaction": None,
        "exploitability": None,
        "impact_score": None,
    }


@lru_cache(maxsize=128)
def _query_nvd(
    keyword,
    api_key,
    limit,
    delay,
):
    kwargs = {
        "keywordSearch": keyword,
        "noRejected": True,
        "limit": limit,
        "key": api_key or None,
    }

    kwargs["delay"] = (
        delay
        if api_key
        else max(delay, 6.0)
    )

    return nvdlib.searchCVE(**kwargs)


def search_cves(
    service,
    version,
    product="",
    host="",
    port=None,
    protocol="tcp",
):
    """
    Find candidate CVEs for a discovered service.

    IMPORTANT:
    A CVE is only classified as a strong candidate when the NVD
    record contains affected CPE evidence matching the observed
    product/service and exact version.

    Keyword-only matches are retained as weak candidates so the
    researcher can inspect them, but they are NOT treated as
    confirmed vulnerabilities.
    """
    service = (service or "").strip()
    version = (version or "").strip()
    product = (product or "").strip()

    if not service and not product:
        return []

    keyword_parts = []

    if product:
        keyword_parts.append(product)
    elif service:
        keyword_parts.append(service)

    if version:
        keyword_parts.append(version)

    keyword = " ".join(keyword_parts)

    try:
        results = _query_nvd(
            keyword,
            current_app.config["NVD_API_KEY"],
            current_app.config["NVD_RESULTS_PER_SERVICE"],
            current_app.config["NVD_DELAY"],
        )

    except Exception as exc:
        current_app.logger.warning(
            "NVD lookup failed for %s: %s",
            keyword,
            exc,
        )
        return []

    output = []

    for item in results:
        cve_id = _value(
            item,
            "id",
            "UNKNOWN",
        )

        description = _description(item)
        cpes = _extract_cpes(item)

        cpe_score, cpe_reasons, matched_cpe = (
            _cpe_match_score(
                service=service,
                product=product,
                observed_version=version,
                cpes=cpes,
            )
        )

        # A keyword result with no CPE match is explicitly weak.
        if cpe_score >= 10:
            confidence = "high"
            correlation_status = "strong_candidate"

        elif cpe_score >= 5:
            confidence = "medium"
            correlation_status = "candidate"

        else:
            confidence = "low"
            correlation_status = "keyword_candidate"

        cvss = _cvss(item)
        exploit_add = _value(
            item,
            "exploitAdd",
        )

        references = _extract_reference_urls(item)

        output.append(
            {
                "id": cve_id,
                "description": description,
                "cvss": cvss["score"],
                "cvss_version": cvss["version"],
                "cvss_vector": cvss["vector"],
                "severity": cvss["severity"],
                "attack_vector": cvss["attack_vector"],
                "privileges_required": cvss[
                    "privileges_required"
                ],
                "user_interaction": cvss[
                    "user_interaction"
                ],
                "cvss_exploitability": cvss[
                    "exploitability"
                ],
                "cvss_impact": cvss["impact_score"],
                "cwe": _extract_cwes(item),
                "references": references,
                "nvd_url": (
                    "https://nvd.nist.gov/vuln/detail/"
                    f"{cve_id}"
                ),
                "kev": bool(exploit_add),
                "kev_date": exploit_add,

                "host": host,
                "port": port,
                "protocol": protocol,
                "service": service or product,
                "product": product,
                "version": version,

                "matched_assets": [
                    {
                        "host": host,
                        "port": port,
                        "protocol": protocol,
                        "service": service or product,
                        "product": product,
                        "version": version,
                    }
                ],

                "cpes": cpes,
                "matched_cpe": matched_cpe,

                "match_score": cpe_score,
                "match_reason": (
                    "; ".join(cpe_reasons)
                    if cpe_reasons
                    else (
                        "NVD keyword result without "
                        "verified affected-CPE match"
                    )
                ),

                "correlation_status": correlation_status,
                "correlation_confidence": confidence,
            }
        )

    # Strong CPE evidence first.
    # Weak keyword-only candidates are pushed to the bottom.
    output.sort(
        key=lambda item: (
            {
                "high": 3,
                "medium": 2,
                "low": 1,
            }.get(
                item.get(
                    "correlation_confidence",
                    "low",
                ),
                1,
            ),
            item.get("match_score", 0),
            item.get("cvss") or 0,
        ),
        reverse=True,
    )

    return output[
        : current_app.config[
            "NVD_RESULTS_PER_SERVICE"
        ]
    ]