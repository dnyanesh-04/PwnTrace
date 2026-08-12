from pathlib import Path

import matplotlib.pyplot as plt


def create_cvss_chart(cves, output_path: Path):
    """Create a simple CVSS distribution chart for the PDF report."""
    scores = [
        float(cve["cvss"])
        for cve in cves
        if isinstance(cve.get("cvss"), (int, float))
    ]

    if not scores:
        return None

    output_path.parent.mkdir(parents=True, exist_ok=True)

    plt.figure(figsize=(7, 4))
    plt.hist(scores, bins=[0, 2, 4, 6, 8, 10], edgecolor="black")
    plt.xlabel("CVSS base score")
    plt.ylabel("Number of CVEs")
    plt.title("PwnTrace CVSS Distribution")
    plt.xlim(0, 10)
    plt.tight_layout()
    plt.savefig(output_path, dpi=160)
    plt.close()

    return output_path
