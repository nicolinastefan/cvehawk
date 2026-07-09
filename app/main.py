import os
import uuid
import shutil
from datetime import datetime

from fastapi import FastAPI, UploadFile, File, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import Base, engine, get_db
from app.models import Scan, Host, Service, CVEMatch
from app.parser import parse_nmap_xml
from app.cpe_matcher import resolve_cpe
from app.nvd_client import query_cves_by_cpe

app = FastAPI(title="CVEHawk")

STORAGE_DIR = "storage/scans"


@app.post("/scans")
def upload_scan(file: UploadFile = File(...), db: Session = Depends(get_db)):
    if not file.filename.endswith(".xml"):
        raise HTTPException(status_code=400, detail="Only .xml files are accepted")

    # Save the raw uploaded file to disk
    scan_id = uuid.uuid4()
    saved_path = os.path.join(STORAGE_DIR, f"{scan_id}.xml")
    os.makedirs(STORAGE_DIR, exist_ok=True)
    with open(saved_path, "wb") as f:
        shutil.copyfileobj(file.file, f)

    # Parse the XML
    parsed = parse_nmap_xml(saved_path)

    # Create the Scan row
    scan = Scan(
        id=scan_id,
        filename=file.filename,
        uploaded_at=datetime.utcnow(),
        nmap_start_time=parsed["nmap_start_time"],
        raw_xml_path=saved_path,
    )
    db.add(scan)
    db.flush()  # so scan.id is usable for FKs below

    total_hosts = 0
    total_services = 0
    total_cve_matches = 0

    for host_data in parsed["hosts"]:
        host = Host(
            scan_id=scan.id,
            ip_address=host_data["ip_address"],
            hostname=host_data["hostname"],
            state=host_data["state"],
        )
        db.add(host)
        db.flush()
        total_hosts += 1

        for svc_data in host_data["services"]:
            service = Service(
                host_id=host.id,
                port=svc_data["port"],
                protocol=svc_data["protocol"],
                service_name=svc_data["service_name"],
                product=svc_data["product"],
                version=svc_data["version"],
                cpe=svc_data["cpe"],
            )
            db.add(service)
            db.flush()
            total_services += 1

            # Resolve a CPE (exact or generic) and look up CVEs if possible
            resolved = resolve_cpe(svc_data)
            if resolved["cpe"] is None:
                continue  # not enough data to match CVEs for this service

            cves = query_cves_by_cpe(resolved["cpe"])
            for cve in cves:
                match = CVEMatch(
                    service_id=service.id,
                    cve_id=cve["cve_id"],
                    cvss_score=cve["cvss_score"],
                    severity=cve["severity"],
                    confidence=resolved["confidence"],
                    description=cve["description"],
                    matched_at=datetime.utcnow(),
                )
                db.add(match)
                total_cve_matches += 1

    db.commit()

    return {
        "scan_id": str(scan.id),
        "hosts_found": total_hosts,
        "services_found": total_services,
        "cve_matches_found": total_cve_matches,
    }


@app.get("/scans/{scan_id}")
def get_scan(scan_id: str, severity: str = "high_critical", db: Session = Depends(get_db)):
    """
    severity options:
      - "high_critical" (default) -- only HIGH and CRITICAL findings
      - "all" -- everything
      - "critical", "high", "medium", "low" -- a single severity level
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    severity = severity.lower()
    valid_options = {"high_critical", "all", "critical", "high", "medium", "low"}
    if severity not in valid_options:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid severity filter. Choose from: {', '.join(sorted(valid_options))}",
        )

    def matches_filter(match_severity: str | None) -> bool:
        if match_severity is None:
            return False
        match_severity = match_severity.lower()
        if severity == "all":
            return True
        if severity == "high_critical":
            return match_severity in ("high", "critical")
        return match_severity == severity

    result = {
        "scan_id": str(scan.id),
        "filename": scan.filename,
        "uploaded_at": str(scan.uploaded_at),
        "severity_filter": severity,
        "hosts": [],
    }

    for host in scan.hosts:
        host_data = {
            "ip_address": host.ip_address,
            "hostname": host.hostname,
            "state": host.state,
            "services": [],
        }
        for service in host.services:
            filtered_matches = [
                {
                    "cve_id": m.cve_id,
                    "cvss_score": m.cvss_score,
                    "severity": m.severity,
                    "confidence": m.confidence,
                }
                for m in service.cve_matches
                if matches_filter(m.severity)
            ]

            service_data = {
                "port": service.port,
                "protocol": service.protocol,
                "product": service.product,
                "version": service.version,
                "cve_matches": filtered_matches,
            }
            host_data["services"].append(service_data)
        result["hosts"].append(host_data)

    return result

@app.get("/")
def root():
    return {"status": "CVEHawk is running"}
