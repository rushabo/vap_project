#!/usr/bin/env python3
"""
Threat Intelligence Aggregator
Collects indicators of compromise (IoCs) from AlienVault OTX pulses and,
when the account has access, VirusTotal Intelligence Search. Outputs JSON/CSV.

Set API keys in environment variables:
  OTX_API_KEY       AlienVault OTX API key (free account)
  VT_API_KEY        VirusTotal API key (VT Intelligence Search may require a paid tier)
  VT_SEARCH_QUERY  Optional VT Intelligence query, e.g. "type:ip"
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

OTX_PULSES_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
VT_SEARCH_URL = "https://www.virustotal.com/api/v3/intelligence/search"
DEFAULT_TIMEOUT = 20
USER_AGENT = "ThreatIntelligenceAggregator/1.0 (educational project)"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def request_json(url: str, *, headers: dict[str, str], params: dict[str, Any] | None = None,
                 timeout: int = DEFAULT_TIMEOUT) -> dict[str, Any]:
    """GET JSON with readable handling for common API/network errors."""
    try:
        response = requests.get(url, headers=headers, params=params, timeout=timeout)
        if response.status_code == 401:
            raise RuntimeError("Authentication failed: check the API key.")
        if response.status_code == 403:
            raise RuntimeError("Access denied: this endpoint or query may not be enabled for your API tier.")
        if response.status_code == 429:
            raise RuntimeError("Rate limit reached. Wait before retrying.")
        response.raise_for_status()
        return response.json()
    except requests.Timeout as exc:
        raise RuntimeError(f"Request timed out after {timeout} seconds.") from exc
    except requests.RequestException as exc:
        raise RuntimeError(f"Network/API request failed: {exc}") from exc
    except ValueError as exc:
        raise RuntimeError("The API returned invalid JSON.") from exc


def normalize_indicator(indicator: dict[str, Any], source: str, pulse_name: str = "") -> dict[str, Any] | None:
    """Convert a provider indicator into a consistent, deduplicatable record."""
    value = str(indicator.get("indicator") or indicator.get("value") or "").strip()
    kind = str(indicator.get("type") or indicator.get("type_title") or "unknown").strip()
    if not value:
        return None
    return {
        "indicator": value,
        "type": kind,
        "source": source,
        "pulse": pulse_name,
        "first_seen": str(indicator.get("created") or indicator.get("created_at") or ""),
        "collected_at": utc_now(),
        "description": str(indicator.get("description") or ""),
        "source_id": str(indicator.get("id") or ""),
    }


def collect_otx(api_key: str, limit: int = 10) -> tuple[list[dict[str, Any]], list[str]]:
    """Collect IoCs from the authenticated user's subscribed OTX pulses."""
    headers = {"X-OTX-API-KEY": api_key, "User-Agent": USER_AGENT}
    params = {"limit": limit, "page": 1}
    data = request_json(OTX_PULSES_URL, headers=headers, params=params)
    pulses = data.get("results", [])
    records: list[dict[str, Any]] = []
    for pulse in pulses:
        pulse_name = str(pulse.get("name") or "")
        for indicator in pulse.get("indicators", []) or []:
            item = normalize_indicator(indicator, "AlienVault OTX", pulse_name)
            if item:
                records.append(item)
    return records, []


def collect_virustotal(api_key: str, query: str, limit: int = 10) -> tuple[list[dict[str, Any]], list[str]]:
    """Search VirusTotal Intelligence. This endpoint may require a suitable VT plan."""
    headers = {"x-apikey": api_key, "User-Agent": USER_AGENT}
    data = request_json(VT_SEARCH_URL, headers=headers, params={"query": query, "limit": limit})
    records: list[dict[str, Any]] = []
    for item in data.get("data", []) or []:
        attrs = item.get("attributes", {}) or {}
        item_id = str(item.get("id") or "")
        kind = str(item.get("type") or attrs.get("type_description") or "unknown")
        record = normalize_indicator(
            {"indicator": item_id, "type": kind, "created": attrs.get("first_submission_date", ""),
             "description": attrs.get("meaningful_name", ""), "id": item_id},
            "VirusTotal", ""
        )
        if record:
            records.append(record)
    return records, []


def deduplicate(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deduplicate by (type, indicator), preserving provider attribution."""
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for record in records:
        key = (record["type"].lower(), record["indicator"].lower())
        if key not in merged:
            merged[key] = record.copy()
        else:
            existing = merged[key]
            sources = set(existing["source"].split("; "))
            sources.update(record["source"].split("; "))
            existing["source"] = "; ".join(sorted(sources))
            pulses = set(filter(None, existing["pulse"].split("; ")))
            pulses.update(filter(None, record["pulse"].split("; ")))
            existing["pulse"] = "; ".join(sorted(pulses))
            if not existing.get("description") and record.get("description"):
                existing["description"] = record["description"]
    return sorted(merged.values(), key=lambda row: (row["type"], row["indicator"]))


def write_json(records: list[dict[str, Any]], path: Path) -> None:
    path.write_text(json.dumps({"generated_at": utc_now(), "count": len(records), "indicators": records},
                               indent=2, ensure_ascii=False), encoding="utf-8")


def write_csv(records: list[dict[str, Any]], path: Path) -> None:
    fields = ["indicator", "type", "source", "pulse", "first_seen", "collected_at", "description", "source_id"]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(records)


def main() -> int:
    parser = argparse.ArgumentParser(description="Aggregate IoCs from AlienVault OTX and VirusTotal Intelligence.")
    parser.add_argument("--limit", type=int, default=10, help="Maximum pulses/results requested per provider (default: 10)")
    parser.add_argument("--vt-query", default=os.getenv("VT_SEARCH_QUERY", "type:ip"),
                        help='VirusTotal Intelligence query (default: environment VT_SEARCH_QUERY or "type:ip")')
    parser.add_argument("--out", default="output", help="Output directory (default: output)")
    parser.add_argument("--skip-otx", action="store_true", help="Skip AlienVault OTX collection")
    parser.add_argument("--skip-vt", action="store_true", help="Skip VirusTotal Intelligence collection")
    args = parser.parse_args()

    if args.limit < 1 or args.limit > 100:
        parser.error("--limit must be between 1 and 100")

    output_dir = Path(args.out)
    output_dir.mkdir(parents=True, exist_ok=True)
    records: list[dict[str, Any]] = []
    errors: list[str] = []

    otx_key = os.getenv("OTX_API_KEY", "").strip()
    vt_key = os.getenv("VT_API_KEY", "").strip()

    if not args.skip_otx:
        if not otx_key:
            errors.append("AlienVault OTX skipped: set OTX_API_KEY.")
        else:
            try:
                found, _ = collect_otx(otx_key, args.limit)
                records.extend(found)
                print(f"[OK] AlienVault OTX: collected {len(found)} indicators.")
            except RuntimeError as exc:
                errors.append(f"AlienVault OTX: {exc}")

    if not args.skip_vt:
        if not vt_key:
            errors.append("VirusTotal skipped: set VT_API_KEY.")
        else:
            try:
                found, _ = collect_virustotal(vt_key, args.vt_query, args.limit)
                records.extend(found)
                print(f"[OK] VirusTotal: collected {len(found)} indicators.")
            except RuntimeError as exc:
                errors.append(f"VirusTotal: {exc}")

    unique_records = deduplicate(records)
    json_path = output_dir / "indicators.json"
    csv_path = output_dir / "indicators.csv"
    write_json(unique_records, json_path)
    write_csv(unique_records, csv_path)

    print(f"\nUnique indicators: {len(unique_records)}")
    print(f"JSON output: {json_path}")
    print(f"CSV output:  {csv_path}")
    if errors:
        print("\nWarnings:")
        for error in errors:
            print(f" - {error}")
        if not unique_records:
            print("No indicators were collected. Check credentials, permissions, and network access.", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
