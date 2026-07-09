import xml.etree.ElementTree as ET
from datetime import datetime


def parse_nmap_xml(xml_path: str) -> dict:
    """
    Parses an Nmap XML file and returns structured scan data:
    {
        "nmap_start_time": datetime or None,
        "hosts": [
            {
                "ip_address": str,
                "hostname": str or None,
                "state": str,
                "services": [
                    {
                        "port": str,
                        "protocol": str,
                        "service_name": str or None,
                        "product": str or None,
                        "version": str or None,
                        "cpe": str or None,
                    },
                    ...
                ]
            },
            ...
        ]
    }
    """
    tree = ET.parse(xml_path)
    root = tree.getroot()

    # Top-level scan start time, e.g. <nmaprun start="1720549020" ...>
    start_epoch = root.attrib.get("start")
    nmap_start_time = (
        datetime.utcfromtimestamp(int(start_epoch)) if start_epoch else None
    )

    hosts = []

    for host_el in root.findall("host"):
        # Host state, e.g. <status state="up".../>
        status_el = host_el.find("status")
        state = status_el.attrib.get("state") if status_el is not None else None

        # IP address, e.g. <address addr="45.33.32.156" addrtype="ipv4"/>
        ip_address = None
        for addr_el in host_el.findall("address"):
            if addr_el.attrib.get("addrtype") in ("ipv4", "ipv6"):
                ip_address = addr_el.attrib.get("addr")
                break

        # Hostname, e.g. <hostnames><hostname name="scanme.nmap.org" .../></hostnames>
        hostname = None
        hostnames_el = host_el.find("hostnames")
        if hostnames_el is not None:
            hostname_el = hostnames_el.find("hostname")
            if hostname_el is not None:
                hostname = hostname_el.attrib.get("name")

        services = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                port_id = port_el.attrib.get("portid")
                protocol = port_el.attrib.get("protocol")

                port_state_el = port_el.find("state")
                port_state = (
                    port_state_el.attrib.get("state")
                    if port_state_el is not None
                    else None
                )

                # Skip ports that aren't actually open (filtered/closed)
                if port_state != "open":
                    continue

                service_el = port_el.find("service")
                service_name = None
                product = None
                version = None
                cpe = None

                if service_el is not None:
                    service_name = service_el.attrib.get("name")
                    product = service_el.attrib.get("product")
                    version = service_el.attrib.get("version")

                    # Take the first CPE tag as the service's identity
                    cpe_el = service_el.find("cpe")
                    if cpe_el is not None:
                        cpe = cpe_el.text

                services.append({
                    "port": port_id,
                    "protocol": protocol,
                    "service_name": service_name,
                    "product": product,
                    "version": version,
                    "cpe": cpe,
                })

        hosts.append({
            "ip_address": ip_address,
            "hostname": hostname,
            "state": state,
            "services": services,
        })

    return {
        "nmap_start_time": nmap_start_time,
        "hosts": hosts,
    }


if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) < 2:
        print("Usage: python3 app/parser.py <path_to_xml>")
        sys.exit(1)

    result = parse_nmap_xml(sys.argv[1])
    # datetime isn't JSON serializable by default, so convert for printing
    result["nmap_start_time"] = str(result["nmap_start_time"])
    print(json.dumps(result, indent=2))
