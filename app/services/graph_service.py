import networkx as nx
import plotly.graph_objects as go


NODE_META = {
    "asset": ("Asset", 18),
    "cve": ("Candidate CVE", 16),
    "technique": ("ATT&CK Hypothesis", 18),
}


def _add_node(
    graph,
    node_id,
    node_type,
    label,
    hover,
):
    if node_id not in graph:
        graph.add_node(
            node_id,
            node_type=node_type,
            label=label,
            hover=hover,
        )


def build_graph(
    scan_results,
    cves,
    mappings,
    attack_paths,
):
    """
    Build:

    Asset
      ↓
    Candidate CVE
      ↓
    ATT&CK hypothesis

    and overlay potential path relationships.
    """
    graph = nx.DiGraph()

    # Assets
    for item in scan_results:
        asset_id = (
            f"asset:"
            f"{item.get('host')}:"
            f"{item.get('protocol', 'tcp')}:"
            f"{item.get('port')}"
        )

        label = (
            f"{item.get('service')}:"
            f"{item.get('port')}"
        )

        hover = (
            f"Host: {item.get('host')}<br>"
            f"Service: {item.get('service')}<br>"
            f"Product: {item.get('product')}<br>"
            f"Version: {item.get('version')}"
        )

        _add_node(
            graph,
            asset_id,
            "asset",
            label,
            hover,
        )

    # CVEs
    for cve in cves:
        cve_id = f"cve:{cve['id']}"

        _add_node(
            graph,
            cve_id,
            "cve",
            cve["id"],
            (
                f"{cve['id']}<br>"
                f"CVSS: {cve.get('cvss', 'N/A')}<br>"
                f"Severity: "
                f"{cve.get('severity', 'UNKNOWN')}<br>"
                f"Correlation: "
                f"{cve.get('correlation_confidence', 'low')}<br>"
                f"Match score: "
                f"{cve.get('match_score', 0)}<br>"
                f"Priority: "
                f"{cve.get('priority_score', 0)}"
            ),
        )

        for asset in cve.get(
            "matched_assets",
            [],
        ):
            asset_id = (
                f"asset:"
                f"{asset.get('host')}:"
                f"{asset.get('protocol', 'tcp')}:"
                f"{asset.get('port')}"
            )

            if asset_id in graph:
                graph.add_edge(
                    asset_id,
                    cve_id,
                    relation="CVE candidate correlation",
                )

    # ATT&CK hypotheses
    for mapping in mappings:
        cve_id = f"cve:{mapping['cve']}"

        for technique in mapping.get(
            "techniques",
            [],
        ):
            tech_id = (
                f"tech:"
                f"{technique['id']}:"
                f"{mapping['cve']}"
            )

            _add_node(
                graph,
                tech_id,
                "technique",
                technique["id"],
                (
                    f"{technique['id']} — "
                    f"{technique['name']}<br>"
                    f"Tactic: "
                    f"{technique['tactic']}<br>"
                    f"Confidence: "
                    f"{technique['confidence']}<br>"
                    f"Evidence: "
                    f"{technique['evidence']}"
                ),
            )

            if cve_id in graph:
                graph.add_edge(
                    cve_id,
                    tech_id,
                    relation="ATT&CK hypothesis",
                )

    # Potential attack paths
    for path in attack_paths.get(
        "paths",
        [],
    ):
        previous = None

        for step in path.get(
            "steps",
            [],
        ):
            node_id = (
                f"tech:"
                f"{step['technique_id']}:"
                f"{step['cve']}"
            )

            if node_id not in graph:
                _add_node(
                    graph,
                    node_id,
                    "technique",
                    step["technique_id"],
                    (
                        f"{step['technique_id']} — "
                        f"{step['technique']}<br>"
                        f"Phase: {step['phase']}<br>"
                        f"Confidence: "
                        f"{step['confidence']}"
                    ),
                )

            if previous is not None:
                graph.add_edge(
                    previous,
                    node_id,
                    relation=(
                        f"{path['path_id']} "
                        f"potential sequence"
                    ),
                )

            previous = node_id

    if not graph.nodes:
        return (
            "<div class='empty-graph'>"
            "No graph data was generated."
            "</div>"
        )

    pos = nx.spring_layout(
        graph,
        seed=42,
        k=1.4,
    )

    edge_x = []
    edge_y = []

    for source, target, data in graph.edges(
        data=True
    ):
        x0, y0 = pos[source]
        x1, y1 = pos[target]

        edge_x.extend(
            [x0, x1, None]
        )
        edge_y.extend(
            [y0, y1, None]
        )

    edge_trace = go.Scatter(
        x=edge_x,
        y=edge_y,
        line=dict(width=1),
        hoverinfo="none",
        mode="lines",
        name="Relationships",
    )

    node_traces = []

    for node_type in NODE_META:
        nodes = [
            node
            for node, data
            in graph.nodes(
                data=True
            )
            if data.get(
                "node_type"
            ) == node_type
        ]

        if not nodes:
            continue

        x = [
            pos[node][0]
            for node in nodes
        ]

        y = [
            pos[node][1]
            for node in nodes
        ]

        labels = [
            graph.nodes[node][
                "label"
            ]
            for node in nodes
        ]

        hovers = [
            graph.nodes[node][
                "hover"
            ]
            for node in nodes
        ]

        node_traces.append(
            go.Scatter(
                x=x,
                y=y,
                mode="markers+text",
                text=labels,
                textposition="top center",
                hovertext=hovers,
                hoverinfo="text",
                marker=dict(
                    size=NODE_META[
                        node_type
                    ][1]
                ),
                name=NODE_META[
                    node_type
                ][0],
            )
        )

    fig = go.Figure(
        data=[
            edge_trace,
            *node_traces,
        ]
    )

    fig.update_layout(
        title=(
            "PwnTrace Evidence & "
            "Potential Attack-Path Graph"
        ),
        showlegend=True,
        hovermode="closest",
        margin=dict(
            l=20,
            r=20,
            t=60,
            b=20,
        ),
        xaxis=dict(
            showgrid=False,
            zeroline=False,
            visible=False,
        ),
        yaxis=dict(
            showgrid=False,
            zeroline=False,
            visible=False,
        ),
        height=650,
    )

    return fig.to_html(
        full_html=False,
        include_plotlyjs=False,
    )