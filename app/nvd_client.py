import os
import time
import requests

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def query_cves_by_cpe(cpe: str, max_results: int = 20) -> list[dict]:
    """
    Queries the NVD API for CVEs matching a given CPE string.
    Nmap gives CPEs in the short form (cpe:/a:vendor:product:version),
    but the NVD API expects CPE 2.3 format (cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*).
    """
    formatted_cpe = _convert_cpe_short_to_23(cpe)

    headers = {}
    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    params = {
        "cpeName": formatted_cpe,
        "resultsPerPage": max_results,
    }

    response = requests.get(NVD_BASE_URL, headers=headers, params=params, timeout=15)

    if response.status_code != 200:
        print(f"NVD API error {response.status_code} for {formatted_cpe}: {response.text[:200]}")
        return []

    data = response.json()
    vulnerabilities = data.get("vulnerabilities", [])

    results = []
    for vuln in vulnerabilities:
        cve = vuln.get("cve", {})
        cve_id = cve.get("id")

        # Description (English)
        description = None
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value")
                break

        # CVSS score - try v3.1 first, fall back to v3.0, then v2
        cvss_score = None
        severity = None
        metrics = cve.get("metrics", {})

        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metric_key in metrics and metrics[metric_key]:
                metric_data = metrics[metric_key][0]
                cvss_score = metric_data.get("cvssData", {}).get("baseScore")
                severity = metric_data.get("baseSeverity") or metric_data.get("cvssData", {}).get("baseSeverity")
                break

        results.append({
            "cve_id": cve_id,
            "cvss_score": cvss_score,
            "severity": severity,
            "description": description,
        })

    return results


def _convert_cpe_short_to_23(short_cpe: str) -> str:
    """
    Converts Nmap's short CPE format to full CPE 2.3 format.
    e.g. cpe:/a:apache:http_server:2.4.7
      -> cpe:2.3:a:apache:http_server:2.4.7:*:*:*:*:*:*:*
    """
    if short_cpe.startswith("cpe:2.3:"):
        return short_cpe  # already in the right format

    parts = short_cpe.replace("cpe:/", "").split(":")
    # pad to 5 parts minimum: part, vendor, product, version, update
    while len(parts) < 5:
        parts.append("*")

    part_type = parts[0]
    vendor = parts[1]
    product = parts[2]
    version = parts[3] if len(parts) > 3 and parts[3] else "*"

    return f"cpe:2.3:{part_type}:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) < 2:
        print("Usage: python3 app/nvd_client.py <cpe_string>")
        sys.exit(1)

    from dotenv import load_dotenv
    load_dotenv()

    results = query_cves_by_cpe(sys.argv[1])
    print(json.dumps(results, indent=2))
