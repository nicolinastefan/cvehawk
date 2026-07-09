import re


def resolve_cpe(service: dict) -> dict:
    """
    Given a service dict (from parser.py) with keys:
      cpe, product, version
    Returns:
      {
        "cpe": str or None,
        "confidence": "exact" | "generic" | None,
      }
    confidence=None means there isn't enough data to attempt a CVE lookup at all.
    """
    existing_cpe = service.get("cpe")
    if existing_cpe:
        return {"cpe": existing_cpe, "confidence": "exact"}

    product = service.get("product")
    version = service.get("version")

    if product and version:
        guessed_cpe = _build_generic_cpe(product, version)
        return {"cpe": guessed_cpe, "confidence": "generic"}

    # No CPE, and not enough info (missing product or version) to guess one
    return {"cpe": None, "confidence": None}


def _build_generic_cpe(product: str, version: str) -> str:
    """
    Builds a best-effort CPE 2.3 string from a raw product name and version.
    This is NOT a reliable vendor lookup -- it's a rough guess used only
    when Nmap didn't supply a real CPE. Always tagged confidence='generic'
    downstream because vendor/product names guessed this way often don't
    match NVD's actual CPE dictionary entries.
    """
    clean_product = _normalize(product)
    clean_version = _normalize_version(version)

    # Without a real vendor, we reuse the product name as a stand-in guess
    # for both vendor and product fields -- this is the core limitation.
    return f"cpe:2.3:a:{clean_product}:{clean_product}:{clean_version}:*:*:*:*:*:*:*"


def _normalize(text: str) -> str:
    """Lowercase, replace spaces/special chars with underscores, for CPE compatibility."""
    text = text.lower().strip()
    text = re.sub(r"[^a-z0-9]+", "_", text)
    text = text.strip("_")
    return text


def _normalize_version(version: str) -> str:
    """
    Extracts just the leading version number (e.g. "6.6.1p1 Ubuntu 2ubuntu2.13" -> "6.6.1p1"),
    since CPE version fields expect a clean version token, not a full descriptive string.
    """
    match = re.match(r"^[\w\.\-]+", version.strip())
    return match.group(0) if match else _normalize(version)


if __name__ == "__main__":
    import json

    test_services = [
        {"cpe": "cpe:/a:openbsd:openssh:6.6.1p1", "product": "OpenSSH", "version": "6.6.1p1 Ubuntu 2ubuntu2.13"},
        {"cpe": None, "product": "Nping echo", "version": None},
        {"cpe": None, "product": None, "version": None},
        {"cpe": None, "product": "SomeProduct", "version": "1.2.3"},
    ]

    for svc in test_services:
        result = resolve_cpe(svc)
        print(json.dumps({"input": svc, "output": result}, indent=2))
