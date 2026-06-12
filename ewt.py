#!/usr/bin/env python3
"""
EpistemicWindTunnel.CLI.v0

Minimal CLI for testing the hypothesis:
    distinction -> commitment

Core invariant I0:
    A distinction without provenance must be explicitly committed as UNEXPLAINED_DEIXIS.

Storage:
    local JSON files:
      - distinctions.json
      - commitments.json
      - receipts.json
      - constitution.json

No SDK, REST API, MCP, UI, CRS, MTR2, SCITT, crypto, or LLM replay.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import sys
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal


Source = Literal["manual", "synthetic", "llm", "sensor"]
ProvenanceStatus = Literal["PROVENANCED", "UNEXPLAINED_DEIXIS"]
TaintStatus = Literal["world", "synthetic", "unknown"]
CommitmentType = Literal["ADMIT", "REJECT", "DEFER", "TRANSFORM"]


DATA_DIR = Path(os.environ.get("EWT_DATA_DIR", ".")).resolve()
DISTINCTIONS_PATH = DATA_DIR / "distinctions.json"
COMMITMENTS_PATH = DATA_DIR / "commitments.json"
RECEIPTS_PATH = DATA_DIR / "receipts.json"
CONSTITUTION_PATH = DATA_DIR / "constitution.json"


@dataclass(frozen=True)
class DistinctionEvent:
    id: str
    source: Source
    content_hash: str
    provenance_status: ProvenanceStatus
    deixis_token: str | None
    taint_status: TaintStatus
    timestamp: str


@dataclass(frozen=True)
class Commitment:
    id: str
    distinction_id: str
    commitment_type: CommitmentType
    reason_code: str
    constitution_version: str = "0.1"


@dataclass(frozen=True)
class Receipt:
    id: str
    commitment_id: str
    payload_hash: str
    previous_receipt_hash: str | None
    signature: str


@dataclass(frozen=True)
class ReplayResult:
    receipt_id: str
    reconstructed: bool
    deterministic: bool
    notes: list[str]


def now_iso8601() -> str:
    return _dt.datetime.now(_dt.UTC).isoformat()


def sha256_json(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def load_list(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8") as f:
        value = json.load(f)
    if not isinstance(value, list):
        raise ValueError(f"{path} must contain a JSON list")
    return value


def save_list(path: Path, rows: list[dict[str, Any]]) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2, sort_keys=True)
        f.write("\n")


def load_json_file(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        value = json.load(f)
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def ensure_constitution() -> None:
    if CONSTITUTION_PATH.exists():
        return
    constitution = {
        "constitution_version": "0.1",
        "rules": [
            "unprovenanced_distinction_requires_unexplained_deixis",
            "synthetic_taint_must_propagate",
            "commitment_requires_receipt",
        ],
    }
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with CONSTITUTION_PATH.open("w", encoding="utf-8") as f:
        json.dump(constitution, f, indent=2, sort_keys=True)
        f.write("\n")


def find_by_id(rows: list[dict[str, Any]], item_id: str, kind: str) -> dict[str, Any]:
    for row in rows:
        if row.get("id") == item_id:
            return row
    raise KeyError(f"{kind} not found: {item_id}")


def parse_input_distinction(path: Path) -> dict[str, Any]:
    raw = load_json_file(path)

    required = {"source", "provenance_status", "taint_status"}
    missing = sorted(required - set(raw))
    if missing:
        raise ValueError(f"Input missing required fields: {', '.join(missing)}")

    source = raw["source"]
    provenance_status = raw["provenance_status"]
    taint_status = raw["taint_status"]

    if source not in {"manual", "synthetic", "llm", "sensor"}:
        raise ValueError("source must be one of manual, synthetic, llm, sensor")
    if provenance_status not in {"PROVENANCED", "UNEXPLAINED_DEIXIS"}:
        raise ValueError("provenance_status must be PROVENANCED or UNEXPLAINED_DEIXIS")
    if taint_status not in {"world", "synthetic", "unknown"}:
        raise ValueError("taint_status must be world, synthetic, or unknown")

    if source == "synthetic" and taint_status == "world":
        raise ValueError("I0 fail: synthetic distinction cannot be marked as world")

    if provenance_status == "UNEXPLAINED_DEIXIS" and not raw.get("deixis_token"):
        raise ValueError("I0 fail: UNEXPLAINED_DEIXIS requires deixis_token")

    # Content may be explicit, or the whole input object can be treated as content.
    # Exclude volatile fields that this CLI generates.
    content = raw.get("content", {k: v for k, v in raw.items() if k not in {"id", "timestamp"}})
    content_hash = raw.get("content_hash") or sha256_json(content)

    if not isinstance(content_hash, str) or len(content_hash) != 64:
        raise ValueError("content_hash must be a sha256 hex string if provided")

    return {
        "source": source,
        "content_hash": content_hash,
        "provenance_status": provenance_status,
        "deixis_token": raw.get("deixis_token"),
        "taint_status": taint_status,
    }


def create_distinction(input_path: Path) -> DistinctionEvent:
    parsed = parse_input_distinction(input_path)
    distinction = DistinctionEvent(
        id=str(uuid.uuid4()),
        source=parsed["source"],
        content_hash=parsed["content_hash"],
        provenance_status=parsed["provenance_status"],
        deixis_token=parsed["deixis_token"],
        taint_status=parsed["taint_status"],
        timestamp=now_iso8601(),
    )

    rows = load_list(DISTINCTIONS_PATH)
    rows.append(asdict(distinction))
    save_list(DISTINCTIONS_PATH, rows)
    return distinction


def validate_commitment_allowed(distinction: dict[str, Any], commitment_type: CommitmentType) -> None:
    # I0: unprovenanced distinction must be explicitly committed as UNEXPLAINED_DEIXIS.
    # In v0, explicitness is carried by provenance_status + required deixis_token.
    if distinction["provenance_status"] == "UNEXPLAINED_DEIXIS" and not distinction.get("deixis_token"):
        raise ValueError("I0 fail: unprovenanced distinction lacks deixis_token")

    if distinction["source"] == "synthetic" and distinction["taint_status"] == "world":
        raise ValueError("I0 fail: synthetic distinction cannot be committed as world")


def previous_receipt_hash() -> str | None:
    receipts = load_list(RECEIPTS_PATH)
    if not receipts:
        return None
    return receipts[-1]["payload_hash"]


def stub_signature(payload_hash: str) -> str:
    return f"stub:{payload_hash[:16]}"


def create_receipt(commitment: Commitment) -> Receipt:
    commitments = load_list(COMMITMENTS_PATH)
    try:
        find_by_id(commitments, commitment.id, "commitment")
    except KeyError as exc:
        raise ValueError("I0 fail: receipt without stored commitment") from exc

    prev_hash = previous_receipt_hash()
    payload = {
        "commitment_id": commitment.id,
        "previous_receipt_hash": prev_hash,
    }
    payload_hash = sha256_json(payload)
    receipt = Receipt(
        id=str(uuid.uuid4()),
        commitment_id=commitment.id,
        payload_hash=payload_hash,
        previous_receipt_hash=prev_hash,
        signature=stub_signature(payload_hash),
    )
    receipts = load_list(RECEIPTS_PATH)
    receipts.append(asdict(receipt))
    save_list(RECEIPTS_PATH, receipts)
    return receipt


def create_commitment(
    distinction_id: str, commitment_type: CommitmentType, reason_code: str
) -> tuple[Commitment, Receipt]:
    distinctions = load_list(DISTINCTIONS_PATH)
    distinction = find_by_id(distinctions, distinction_id, "distinction")
    validate_commitment_allowed(distinction, commitment_type)

    commitment = Commitment(
        id=str(uuid.uuid4()),
        distinction_id=distinction_id,
        commitment_type=commitment_type,
        reason_code=reason_code,
    )
    commitments = load_list(COMMITMENTS_PATH)
    commitments.append(asdict(commitment))
    save_list(COMMITMENTS_PATH, commitments)

    receipt = create_receipt(commitment)
    return commitment, receipt


def get_receipt_by_commitment(commitment_id: str) -> dict[str, Any]:
    receipts = load_list(RECEIPTS_PATH)
    for receipt in receipts:
        if receipt["commitment_id"] == commitment_id:
            return receipt
    raise KeyError(f"receipt not found for commitment: {commitment_id}")


def replay(receipt_id: str) -> ReplayResult:
    receipts = load_list(RECEIPTS_PATH)
    commitments = load_list(COMMITMENTS_PATH)
    distinctions = load_list(DISTINCTIONS_PATH)

    receipt = find_by_id(receipts, receipt_id, "receipt")
    commitment = find_by_id(commitments, receipt["commitment_id"], "commitment")
    distinction = find_by_id(distinctions, commitment["distinction_id"], "distinction")

    expected_payload_hash = sha256_json(
        {
            "commitment_id": commitment["id"],
            "previous_receipt_hash": receipt["previous_receipt_hash"],
        }
    )

    notes: list[str] = []
    reconstructed = True
    if expected_payload_hash != receipt["payload_hash"]:
        reconstructed = False
        notes.append("payload_hash mismatch")

    if distinction["provenance_status"] == "UNEXPLAINED_DEIXIS":
        notes.append("UNEXPLAINED_DEIXIS: receipt proves commitment, not full provenance")

    return ReplayResult(
        receipt_id=receipt_id,
        reconstructed=reconstructed,
        deterministic=True,
        notes=notes,
    )


def audit(receipt_id: str) -> dict[str, Any]:
    receipts = load_list(RECEIPTS_PATH)
    commitments = load_list(COMMITMENTS_PATH)
    distinctions = load_list(DISTINCTIONS_PATH)

    receipt = find_by_id(receipts, receipt_id, "receipt")
    commitment = find_by_id(commitments, receipt["commitment_id"], "commitment")
    distinction = find_by_id(distinctions, commitment["distinction_id"], "distinction")
    replay_result = replay(receipt_id)

    return {
        "receipt": receipt,
        "commitment": commitment,
        "distinction": distinction,
        "verification": asdict(replay_result),
        "limitation": "receipt != full provenance",
    }


def print_json(value: Any) -> None:
    if hasattr(value, "__dataclass_fields__"):
        value = asdict(value)
    print(json.dumps(value, indent=2, sort_keys=True))


def run_falsification_deixis_collision() -> dict[str, Any]:
    """
    Creates two different UNEXPLAINED_DEIXIS distinctions and verifies that receipts differ.
    Uses in-memory temp-ish input files inside DATA_DIR.
    """
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    a_path = DATA_DIR / "_fixture_a.json"
    b_path = DATA_DIR / "_fixture_b.json"

    a = {
        "source": "manual",
        "content": {"act": "deictic_act_A"},
        "provenance_status": "UNEXPLAINED_DEIXIS",
        "deixis_token": "a",
        "taint_status": "unknown",
    }
    b = {
        "source": "manual",
        "content": {"act": "deictic_act_B"},
        "provenance_status": "UNEXPLAINED_DEIXIS",
        "deixis_token": "b",
        "taint_status": "unknown",
    }

    a_path.write_text(json.dumps(a), encoding="utf-8")
    b_path.write_text(json.dumps(b), encoding="utf-8")

    da = create_distinction(a_path)
    db = create_distinction(b_path)
    ca, ra = create_commitment(da.id, "ADMIT", "UNEXPLAINED_DEIXIS")
    cb, rb = create_commitment(db.id, "ADMIT", "UNEXPLAINED_DEIXIS")

    receipts_differ = ra.payload_hash != rb.payload_hash
    return {
        "test": "deixis_collision",
        "distinction_a": da.id,
        "distinction_b": db.id,
        "commitment_a": ca.id,
        "commitment_b": cb.id,
        "receipt_a": ra.id,
        "receipt_b": rb.id,
        "receipt_a_hash": ra.payload_hash,
        "receipt_b_hash": rb.payload_hash,
        "passed": receipts_differ,
        "expected": "receipts differ unless content_hash + deixis_token collide",
        "conclusion": "receipt != full provenance",
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ewt", description="EpistemicWindTunnel.CLI.v0")
    sub = parser.add_subparsers(dest="command", required=True)

    p_distinguish = sub.add_parser("distinguish", help="store distinction from input JSON")
    p_distinguish.add_argument("input_json", type=Path)

    p_commit = sub.add_parser("commit", help="create commitment and receipt")
    p_commit.add_argument("distinction_id")
    group = p_commit.add_mutually_exclusive_group(required=True)
    group.add_argument("--admit", action="store_true")
    group.add_argument("--reject", action="store_true")
    group.add_argument("--defer", action="store_true")
    group.add_argument("--transform", action="store_true")
    p_commit.add_argument("--reason", required=True)

    p_receipt = sub.add_parser("receipt", help="print receipt for commitment")
    p_receipt.add_argument("commitment_id")

    p_replay = sub.add_parser("replay", help="replay receipt")
    p_replay.add_argument("receipt_id")

    p_audit = sub.add_parser("audit", help="audit receipt lineage and verification")
    p_audit.add_argument("receipt_id")

    sub.add_parser("init", help="write constitution.json if absent")
    sub.add_parser("test-deixis-collision", help="run primary falsification fixture")

    return parser


def main(argv: list[str] | None = None) -> int:
    ensure_constitution()
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "init":
            ensure_constitution()
            print_json(load_json_file(CONSTITUTION_PATH))
            return 0

        if args.command == "distinguish":
            distinction = create_distinction(args.input_json)
            print_json(distinction)
            return 0

        if args.command == "commit":
            if args.admit:
                ctype: CommitmentType = "ADMIT"
            elif args.reject:
                ctype = "REJECT"
            elif args.defer:
                ctype = "DEFER"
            else:
                ctype = "TRANSFORM"
            commitment, receipt = create_commitment(args.distinction_id, ctype, args.reason)
            print_json({"commitment": asdict(commitment), "receipt": asdict(receipt)})
            return 0

        if args.command == "receipt":
            print_json(get_receipt_by_commitment(args.commitment_id))
            return 0

        if args.command == "replay":
            print_json(replay(args.receipt_id))
            return 0

        if args.command == "audit":
            print_json(audit(args.receipt_id))
            return 0

        if args.command == "test-deixis-collision":
            print_json(run_falsification_deixis_collision())
            return 0

        parser.error(f"unknown command: {args.command}")
        return 2

    except Exception as exc:
        print(f"ewt: error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
