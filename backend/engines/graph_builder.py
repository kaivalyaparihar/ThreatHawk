#backend\engines\graph_builder.py


def build_graph(ioc: str, ioc_type: str, results: dict) -> dict:
    """
    Build a relationship graph from investigation results.
    Returns: { nodes: [{id, label, type, data}], edges: [{source, target, label}] }

    Node types: ip (blue), domain (green), hash (orange), malware_family (red)
    Edge types: resolves_to, associated_with, communicates_with
    """

    nodes = {}
    edges = []

    def add_node(node_id: str, label: str, node_type: str, data: dict = None):
        if node_id and node_id not in nodes:
            nodes[node_id] = {
                "id": node_id,
                "label": label,
                "type": node_type,
                "data": data or {}
            }

    def add_edge(source: str, target: str, label: str):
        if source and target and source != target:
            edge_key = f"{source}->{target}->{label}"
            # Avoid duplicate edges
            for e in edges:
                if f"{e['source']}->{e['target']}->{e['label']}" == edge_key:
                    return
            edges.append({"source": source, "target": target, "label": label})

    # Add the primary IOC node
    add_node(ioc, ioc, ioc_type, {"primary": True})

    # === VirusTotal data ===
    vt = results.get("virustotal", {})
    if vt.get("success") and vt.get("data"):
        vt_data = vt["data"]

        # Malware families as nodes
        for family in vt_data.get("malware_families", [])[:10]:
            family_id = f"malware:{family}"
            add_node(family_id, family, "malware_family")
            add_edge(ioc, family_id, "detected_as")

        # For IP: extract AS owner
        if ioc_type == "ip":
            as_owner = vt_data.get("as_owner")
            if as_owner and as_owner != "Unknown":
                as_id = f"org:{as_owner}"
                add_node(as_id, as_owner, "organization")
                add_edge(ioc, as_id, "belongs_to")

        # For domain: extract DNS records
        if ioc_type == "domain":
            for record in vt_data.get("last_dns_records", []):
                if record.get("type") == "A" and record.get("value"):
                    ip_val = record["value"]
                    add_node(ip_val, ip_val, "ip")
                    add_edge(ioc, ip_val, "resolves_to")

    # === DNS data ===
    dns_result = results.get("dns", {})
    if dns_result.get("success") and dns_result.get("data"):
        dns_data = dns_result["data"]

        # A records → IP nodes
        for ip_val in dns_data.get("a_records", []):
            add_node(ip_val, ip_val, "ip")
            add_edge(ioc, ip_val, "resolves_to")

        # MX records
        for mx in dns_data.get("mx_records", []):
            # MX format: "10 mail.example.com."
            mx_domain = mx.split()[-1].rstrip(".") if " " in mx else mx.rstrip(".")
            if mx_domain:
                add_node(mx_domain, mx_domain, "domain")
                add_edge(ioc, mx_domain, "mail_handled_by")

        # NS records
        for ns in dns_data.get("ns_records", []):
            ns_domain = ns.rstrip(".")
            if ns_domain:
                add_node(ns_domain, ns_domain, "domain")
                add_edge(ioc, ns_domain, "nameserver")

    # === WHOIS data ===
    whois_result = results.get("whois", {})
    if whois_result.get("success") and whois_result.get("data"):
        whois_data = whois_result["data"]
        registrar = whois_data.get("registrar")
        if registrar and registrar != "Unknown":
            reg_id = f"registrar:{registrar}"
            add_node(reg_id, registrar, "organization")
            add_edge(ioc, reg_id, "registered_by")

    # === Shodan data ===
    shodan = results.get("shodan", {})
    if shodan.get("success") and shodan.get("data"):
        shodan_data = shodan["data"]

        # Hostnames
        for hostname in shodan_data.get("hostnames", [])[:5]:
            add_node(hostname, hostname, "domain")
            add_edge(ioc, hostname, "resolves_to")

        # Vulnerabilities
        for vuln in shodan_data.get("vulns", [])[:5]:
            vuln_id = f"vuln:{vuln}"
            add_node(vuln_id, vuln, "vulnerability")
            add_edge(ioc, vuln_id, "has_vulnerability")

    # === AbuseIPDB data ===
    abuse = results.get("abuseipdb", {})
    if abuse.get("success") and abuse.get("data"):
        abuse_data = abuse["data"]
        domain_name = abuse_data.get("domain")
        if domain_name and domain_name != ioc:
            add_node(domain_name, domain_name, "domain")
            add_edge(ioc, domain_name, "associated_with")

    # === GeoIP data ===
    geoip = results.get("ip_api", {})
    if geoip.get("success") and geoip.get("data"):
        geo_data = geoip["data"]
        country = geo_data.get("country")
        if country and country != "Unknown":
            country_id = f"geo:{country}"
            add_node(country_id, country, "location")
            add_edge(ioc, country_id, "located_in")

    return {
        "nodes": list(nodes.values()),
        "edges": edges
    }
