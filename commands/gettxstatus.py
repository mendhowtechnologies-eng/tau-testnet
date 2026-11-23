"""Transaction status lookup by hash (issue #11).

Resolution order:
  1. mempool  -> "queued"  (both 'pending' and 'reserved'), or "expired" if the
                 row is past its expiration_time but not yet pruned.
  2. tx_index -> "confirmed" for the first location on the canonical chain
                 (with block_hash/number and confirmation depth). Fork-only
                 locations fall through (a reorged-out tx is re-queued into the
                 mempool, so step 1 usually catches it).
  3. mempool_dropped -> "expired" / "evicted" / "rejected". A "rejected" row
                 may carry the apply receipt's `reason` code and a `detail`
                 log trail. Only the node that built the block records these;
                 other nodes see the tx stay queued until it expires.
  4. "unknown".

"unknown" is a valid answer, not an error; the envelope stays ok. Only a
malformed hash / usage yields INVALID_PARAMS.
"""
import json
import logging
import time
from datetime import datetime, timezone

import api_response

logger = logging.getLogger(__name__)


def _iso_from_ms(ms) -> str:
    try:
        return datetime.fromtimestamp(int(ms) / 1000.0, tz=timezone.utc).isoformat()
    except Exception:
        return ""


def _iso_from_seconds(secs) -> str:
    try:
        return datetime.fromtimestamp(int(secs), tz=timezone.utc).isoformat()
    except Exception:
        return ""


def _retractable_fields(db, tx_hash: str, block_hash: str) -> dict:
    """`retractable` for a confirmed park, `retracts` for a confirmed retract."""
    try:
        block = db.get_block_by_hash(block_hash) or {}
        txs = block.get("transactions") or []
        ids = block.get("tx_ids") or []
        if tx_hash not in ids or len(ids) != len(txs):
            return {}
        tx = txs[ids.index(tx_hash)]
        tx_type = tx.get("tx_type") if isinstance(tx, dict) else None
        if tx_type == "retract_transfer":
            return {"retracts": tx.get("retractable_id")}
        if tx_type != "retractable_transfer":
            return {}
        from commands.getretractable import resolution
        from consensus.facade import TipAdmissionView
        from consensus.retractable import parse_retractable_transfer

        rid = parse_retractable_transfer(tx).retractable_id
        if TipAdmissionView().get_retractable(rid) is not None:
            status = "open"
        else:
            resolved = resolution(rid.hex())
            status = resolved[0] if resolved else "not_recorded"
        return {"retractable": {"id": rid.hex(), "status": status}}
    except Exception:
        logger.exception("Failed to resolve retractable detail for %s", tx_hash)
        return {}


def _rule_outcome_fields(db, tx_hash: str, block_hash: str) -> dict:
    """`rule_outcome` for a confirmed op-0 rule transaction (#42).

    Read from the committed journal of the block (`tau_rules_in_force.
    rule_tx_outcomes`): whether the engine took the revision, its outcome and
    the revision counter before and after. Nothing is recorded for this at
    apply, so every node holding the block answers the same, including for
    blocks applied before an upgrade. A rule with no revision of the shared
    specification (an `o5` rule goes to the clause registry) says so.
    """
    try:
        block = db.get_block_by_hash(block_hash) or {}
        txs = block.get("transactions") or []
        ids = block.get("tx_ids") or []
        if tx_hash not in ids or len(ids) != len(txs):
            return {}
        rules, mine = [], None
        for tid, tx in zip(ids, txs):
            ops = tx.get("operations") if isinstance(tx, dict) else None
            text = ops.get("0") if isinstance(ops, dict) else None
            if isinstance(text, str) and text.strip():
                if tid == tx_hash:
                    mine = len(rules)
                rules.append(text)
        if mine is None:
            return {}
        import tau_rules_in_force
        outcomes = tau_rules_in_force.rule_tx_outcomes(block_hash, rules, store=db)
        if outcomes is None:
            return {"rule_outcome": {"recorded": False,
                                     "reason": "no commit record for the block on this node"}}
        found = outcomes[mine]
        if found is None:
            return {"rule_outcome": {"recorded": True, "engine_revision": None,
                                     "note": "no revision of the shared specification "
                                             "(a clause-registry rule claims none)"}}
        return {"rule_outcome": {"recorded": True, "engine_revision": found}}
    except Exception:
        logger.exception("Failed to resolve rule outcome for %s", tx_hash)
        return {}


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) != 2:
        return api_response.error_response(
            "gettxstatus", "Usage: gettxstatus <tx_hash>", "INVALID_PARAMS"
        )
    tx_hash = parts[1].lower()
    if len(tx_hash) != 64 or any(c not in "0123456789abcdef" for c in tx_hash):
        return api_response.error_response(
            "gettxstatus", "tx_hash must be 64 hex characters.", "INVALID_PARAMS"
        )

    db = container.db
    try:
        # 1. In the mempool?
        entry = db.get_mempool_entry(tx_hash)
        if entry is not None:
            payload = {}
            try:
                payload = json.loads(entry.get("payload") or "{}")
            except Exception:
                payload = {}
            exp = payload.get("expiration_time")
            now_s = int(time.time())
            data = {
                "tx_hash": tx_hash,
                "sender": payload.get("sender_pubkey"),
                "sequence_number": payload.get("sequence_number"),
                "received_at": _iso_from_ms(entry.get("received_at", 0)),
                "fee_limit": entry.get("fee_limit", 0),
                "estimated_fee": entry.get("estimated_fee", 0),
            }
            if isinstance(exp, int) and exp < now_s:
                data["status"] = "expired"
                data["expires_at"] = _iso_from_seconds(exp)
            else:
                data["status"] = "queued"
                data["expires_at"] = _iso_from_seconds(exp)
            return api_response.success_response("gettxstatus", data)

        # 2. Confirmed on the canonical chain?
        for loc in db.get_tx_block_locations(tx_hash):
            is_canonical, head_number = db.get_canonical_confirmation(
                loc["block_hash"], loc["block_number"]
            )
            if is_canonical:
                confirmations = head_number - loc["block_number"] + 1
                data = {
                    "tx_hash": tx_hash,
                    "status": "confirmed",
                    "block_hash": loc["block_hash"],
                    "block_number": loc["block_number"],
                    "confirmations": max(1, confirmations),
                }
                data.update(_retractable_fields(db, tx_hash, loc["block_hash"]))
                data.update(_rule_outcome_fields(db, tx_hash, loc["block_hash"]))
                return api_response.success_response("gettxstatus", data)

        # 3. Dropped without being mined?
        dropped = db.get_dropped_tx(tx_hash)
        if dropped is not None:
            data = {
                "tx_hash": tx_hash,
                "status": dropped["reason"],  # expired | evicted | rejected
                "dropped_at": _iso_from_ms(dropped.get("dropped_at", 0)),
            }
            # Apply-time rejection cause, when the node that mined the block
            # recorded one (e.g. rule_not_applied, width_mismatch).
            if dropped.get("reject_code"):
                data["reason"] = dropped["reject_code"]
            if dropped.get("reject_detail"):
                data["detail"] = dropped["reject_detail"]
            return api_response.success_response("gettxstatus", data)

        # 4. Never seen.
        return api_response.success_response("gettxstatus", {
            "tx_hash": tx_hash,
            "status": "unknown",
        })
    except Exception as exc:
        logger.exception("Failed to resolve status for %s", tx_hash)
        return api_response.error_response(
            "gettxstatus", f"Failed to resolve tx status: {exc}", "INTERNAL_ERROR"
        )
