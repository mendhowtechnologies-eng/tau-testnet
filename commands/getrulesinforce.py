"""getrulesinforce [<block_hash> | <height>] [<account>] -- the rules in force (#42).

Shared specification: what the engine runs after a canonical block (default:
the latest commit), rebuilt from the committed journal exactly as a restart
rebuilds the node's engine, every replayed step checked against the
fingerprint recorded when the block was applied (`tau_rules_in_force`). It is
full-width text, so two nodes give the same text and sha256 for one block.
`available: false` with a `reason` when the rebuild failed or did not reproduce
the committed execution: a text is never shown unverified.

With an account: that account's own clauses from the clause registry (its
`o5` policy, its rule-change guard, ...), each with its sha256. The registry is
kept for the head only, so they are given when the view is at the head, read
in the same database read as the head they belong to.
"""
import hashlib

import api_response

USAGE = "Usage: getrulesinforce [<block_hash> | <height>] [<account>]"

_STREAM_NAMES = {5: "policy (o5)", 0xFFFFFFFF: "rule-change guard"}


def _is_hex(text, n):
    return len(text) == n and all(c in "0123456789abcdef" for c in text)


def _parse(args):
    block = account = None
    for raw in args:
        text = raw.strip().lower()
        if _is_hex(text, 96) and account is None:
            account = text
        elif (_is_hex(text, 64) or text.isdigit()) and block is None:
            block = text
        else:
            return None, None, False
    return block, account, True


def _account_section(db, account, view_tip):
    head_tip, clauses = db.account_clauses_at_head(account)
    section = {"address": account}
    if view_tip is not None and head_tip != view_tip:
        section["clauses"] = None
        section["note"] = ("the clause registry is kept for the head only; "
                           "ask without a block for this account's clauses")
        return section
    section["clauses"] = [{
        "stream": stream,
        "kind": _STREAM_NAMES.get(stream, f"o{stream}"),
        "text": body,
        "sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
    } for stream, body in clauses]
    return section


def execute(raw_command: str, container):
    parts = raw_command.split()
    block_arg, account, ok = _parse(parts[1:])
    if not ok or len(parts) > 3:
        return api_response.error_response("getrulesinforce", USAGE, "INVALID_PARAMS")
    import tau_authority
    import tau_rules_in_force

    db = container.db
    block_hash = None
    if block_arg is not None:
        block_hash = (db.get_canonical_block_hash_at(int(block_arg))
                      if block_arg.isdigit() else block_arg)
        block = db.get_block_by_hash(block_hash) if block_hash else None
        number = (block or {}).get("header", {}).get("block_number")
        if block is None or number is None or \
                not db.get_canonical_confirmation(block_hash, int(number))[0]:
            return api_response.error_response(
                "getrulesinforce", "not a canonical block on this node", "NOT_FOUND")
    if not tau_authority.owner().enabled:
        view = {"available": False,
                "reason": "this node runs without the authoritative engine, so it "
                          "keeps no committed journal"}
    else:
        view = tau_rules_in_force.at_block(block_hash, store=db)
        if view is None:
            return api_response.error_response(
                "getrulesinforce", "no commit record for that block on this node",
                "NOT_FOUND")
    data = {"shared_spec": view}
    if account is not None:
        data["account"] = _account_section(db, account, view.get("block_hash"))
    return api_response.success_response("getrulesinforce", data)
