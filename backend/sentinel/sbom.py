"""CycloneDX 1.5 JSON export with embedded VEX-style vulnerability analysis.

VEX states are assigned conservatively:
  * `in_triage`      - default for every matched advisory (exploitability has NOT been established)
  * `not_affected`   - only when local range evaluation shows the installed version is outside the
                       published affected range (no justification code is claimed; detail text explains)
`exploitable` and `resolved` are never emitted: neither is established by static evidence.
"""
from __future__ import annotations

import base64
import uuid
from datetime import datetime, timezone

from . import __version__

HASH_ALGS = {"sha512": "SHA-512", "sha256": "SHA-256", "sha1": "SHA-1", "sha384": "SHA-384"}


def _hash(integrity: str | None):
    if not integrity:
        return None
    if "-" in integrity and integrity.split("-", 1)[0] in HASH_ALGS:
        alg, b64 = integrity.split("-", 1)
        try:
            return {"alg": HASH_ALGS[alg], "content": base64.b64decode(b64.split()[0]).hex()}
        except (ValueError, base64.binascii.Error):
            return None
    if ":" in integrity and integrity.split(":", 1)[0] in HASH_ALGS:
        alg, hx = integrity.split(":", 1)
        if all(c in "0123456789abcdef" for c in hx.lower()):
            return {"alg": HASH_ALGS[alg], "content": hx.lower()}
    return None


def export_cyclonedx(result: dict) -> dict:
    pk = result["packages"]
    comps = []
    for p in pk.values():
        c = {"type": "library", "bom-ref": p["id"], "name": p["name"], "version": p["version"] or "unknown",
             "scope": "optional" if p["scope"] in ("dev", "test", "optional") else "required"}
        if p.get("purl"):
            c["purl"] = p["purl"]
        h = _hash(p.get("integrity"))
        if h:
            c["hashes"] = [h]
        lic = p.get("license") or ((p.get("registry") or {}).get("license"))
        if lic:
            c["licenses"] = [{"license": {"name": lic[:100]}}]
        c["properties"] = [{"name": "sentinel:direct", "value": str(p["direct"]).lower()},
                           {"name": "sentinel:scope", "value": p["scope"]},
                           {"name": "sentinel:vulnerability-status", "value": p["vuln_status"]}]
        comps.append(c)
    deps = []
    for n in result["graph"]["nodes"]:
        out = [e["to"] for e in result["graph"]["edges"] if e["from"] == n["id"]]
        deps.append({"ref": n["id"], "dependsOn": out})
    roots = [n for n in result["graph"]["nodes"] if n["type"] == "root"]
    vulns = []
    for f in result["findings"]:
        if f["kind"] != "vulnerability":
            continue
        adv = f["advisory"]
        applies = adv.get("applies_to_installed")
        v = {"bom-ref": f["id"], "id": adv["id"],
             "source": {"name": "OSV", "url": adv["source_url"]},
             "references": [{"id": a, "source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{a}"}}
                            for a in adv["aliases"] if a != adv["id"]][:20],
             "ratings": [], "cwes": [int(c.split("-")[1]) for c in adv.get("cwes", []) if c.split("-")[-1].isdigit()],
             "description": adv.get("summary"), "published": adv.get("published"), "updated": adv.get("modified"),
             "affects": [{"ref": f["package_id"]}],
             "analysis": {"state": "not_affected" if applies is False else "in_triage",
                          "detail": f"Reachability: {f['reachability']['label']}. {f['reachability']['explanation']}"[:1000]}}
        if adv.get("cvss_score") is not None:
            v["ratings"].append({"source": {"name": "OSV"}, "score": adv["cvss_score"], "severity": adv["severity"],
                                 "method": "CVSSv31" if "3.1" in (adv.get("cvss_vector") or "") else "CVSSv3",
                                 "vector": adv.get("cvss_vector")})
        elif adv.get("severity") != "unknown":
            v["ratings"].append({"source": {"name": "OSV"}, "severity": adv["severity"], "method": "other"})
        if adv.get("fixed_versions"):
            v["recommendation"] = f"Upgrade to {adv['fixed_versions'][0]} or later"
        vulns.append(v)
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {"timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                     "tools": {"components": [{"type": "application", "name": "SENTINEL-SC", "version": __version__}]},
                     "component": {"type": "application", "bom-ref": roots[0]["id"] if roots else "root",
                                   "name": roots[0]["name"] if roots else result["scan"]["source_name"]},
                     "properties": [{"name": "sentinel:scan-status", "value": result["scan"]["status"]},
                                    {"name": "sentinel:vex-note", "value": "in_triage = matched advisory, exploitability not established"}]},
        "components": comps, "dependencies": deps, "vulnerabilities": vulns,
    }
