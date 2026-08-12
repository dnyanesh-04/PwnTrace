TECHNIQUES = {
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
    },
    "T1068": {
        "name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
    },
    "T1552.001": {
        "name": "Unsecured Credentials: Credentials In Files",
        "tactic": "Credential Access",
    },
    "T1210": {
        "name": "Exploitation of Remote Services",
        "tactic": "Lateral Movement",
    },
}


REMOTE_SERVICES = {
    "ssh",
    "smb",
    "microsoft-ds",
    "rdp",
    "ms-wbt-server",
    "winrm",
    "ftp",
    "telnet",
}


WEB_SERVICES = {
    "http",
    "https",
    "http-proxy",
    "http-alt",
    "apache",
    "nginx",
    "iis",
}


def _confidence_score(level):
    return {
        "high": 0.90,
        "medium": 0.65,
        "low": 0.40,
    }.get(level, 0.40)


def _add(
    mapping,
    technique_id,
    confidence,
    evidence,
):
    technique = TECHNIQUES[technique_id]

    mapping.append(
        {
            "id": technique_id,
            "name": technique["name"],
            "tactic": technique["tactic"],
            "confidence": confidence,
            "confidence_score": _confidence_score(
                confidence
            ),
            "evidence": evidence,
            "mapping_type": "heuristic",
        }
    )


def _execution_mapping(
    description,
    cwes,
):
    """
    Map execution-related evidence conservatively.

    Generic "code execution" is no longer automatically considered
    high-confidence T1059.
    """
    execution_terms = (
        "command injection",
        "arbitrary command",
        "os command",
        "shell command",
        "command execution",
    )

    strong_cwes = {
        "CWE-78",
        "CWE-77",
    }

    if any(
        term in description
        for term in execution_terms
    ) or cwes.intersection(strong_cwes):
        return (
            "high",
            "NVD evidence specifically indicates "
            "command/shell execution behavior."
        )

    generic_execution_terms = (
        "remote code execution",
        "arbitrary code execution",
        "execute arbitrary code",
        "code execution",
    )

    if any(
        term in description
        for term in generic_execution_terms
    ):
        return (
            "medium",
            "NVD indicates code execution, but the "
            "specific command interpreter mechanism is "
            "not established."
        )

    return None


def _privilege_mapping(
    description,
    cwes,
):
    strong_cwes = {
        "CWE-269",
        "CWE-250",
    }

    terms = (
        "privilege escalation",
        "gain privileges",
        "elevate privileges",
        "local privilege escalation",
        "root privilege",
        "administrator privilege",
    )

    if any(term in description for term in terms):
        return (
            "high",
            "NVD description explicitly indicates "
            "privilege escalation behavior."
        )

    if cwes.intersection(strong_cwes):
        return (
            "medium",
            "CWE evidence indicates improper privilege "
            "management; exact ATT&CK behavior is inferred."
        )

    return None


def _credential_mapping(
    description,
):
    terms = (
        "credential disclosure",
        "credentials exposed",
        "password disclosure",
        "passwords exposed",
        "hard-coded password",
        "hardcoded password",
        "credential file",
        "credentials in a file",
    )

    if any(
        term in description
        for term in terms
    ):
        return (
            "medium",
            "NVD description indicates possible "
            "credential exposure in application data/files."
        )

    return None


def map_attack(cves):
    """
    Generate ATT&CK hypotheses from vulnerability evidence.

    These are NOT official MITRE CVE mappings.

    The mapper deliberately avoids treating every remote/code-execution
    CVE as T1059 with high confidence.
    """
    output = []

    for cve in cves:
        description = (
            cve.get("description") or ""
        ).lower()

        service = (
            cve.get("service") or ""
        ).lower()

        attack_vector = cve.get(
            "attack_vector"
        )

        cwes = {
            item.upper()
            for item in cve.get("cwe", [])
        }

        techniques = []

        # Initial Access:
        # Only make this a hypothesis for web-facing services.
        if (
            attack_vector == "NETWORK"
            and service in WEB_SERVICES
            and cve.get("correlation_confidence")
            in {"high", "medium"}
        ):
            _add(
                techniques,
                "T1190",
                "medium",
                "Network-reachable web service with "
                "supporting vulnerability correlation. "
                "Internet exposure is not independently verified."
            )

        # Lateral Movement:
        # Remote services are a potential opportunity,
        # not proof of lateral movement.
        if (
            service in REMOTE_SERVICES
            and cve.get("correlation_confidence")
            in {"high", "medium"}
        ):
            _add(
                techniques,
                "T1210",
                "medium",
                "Remote-service exposure creates a potential "
                "lateral-movement opportunity. Internal "
                "reachability and a second host are not verified."
            )

        execution = _execution_mapping(
            description,
            cwes,
        )

        if execution:
            confidence, evidence = execution

            _add(
                techniques,
                "T1059",
                confidence,
                evidence,
            )

        privilege = _privilege_mapping(
            description,
            cwes,
        )

        if privilege:
            confidence, evidence = privilege

            _add(
                techniques,
                "T1068",
                confidence,
                evidence,
            )

        credential = _credential_mapping(
            description,
        )

        if credential:
            confidence, evidence = credential

            _add(
                techniques,
                "T1552.001",
                confidence,
                evidence,
            )

        # Keep only the strongest hypothesis for each technique.
        best = {}

        for technique in techniques:
            previous = best.get(
                technique["id"]
            )

            if (
                previous is None
                or technique["confidence_score"]
                > previous["confidence_score"]
            ):
                best[
                    technique["id"]
                ] = technique

        output.append(
            {
                "cve": cve["id"],
                "host": cve.get("host"),
                "port": cve.get("port"),
                "service": cve.get("service"),
                "correlation_confidence": cve.get(
                    "correlation_confidence",
                    "low",
                ),
                "techniques": list(
                    best.values()
                ),
            }
        )

    return output