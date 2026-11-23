"""The rules in force as of a block, rebuilt the way the node rebuilds itself (#42).

Source: the committed journal (`tau_journal_v1`) and the commit records that
name its head per block (`block_commits_v1`). A restart rebuilds the
authoritative engine from exactly these rows (`AuthoritativeTauOwner.
reconstruct_from_committed`); this module runs that same reconstruction,
`WorkerSession.reconstruct(..., verify=True)`, on the journal cut at the asked
block, and reads the engine's `current_spec()` from it. Two properties follow:

* **Checked, not assumed.** Every replayed revision and step is compared with
  the semantic fingerprint recorded when the block was applied. A view that
  does not reproduce the committed execution is refused, never shown.
* **The same text on every node.** The replay runs with every stream plain
  (full width), so the text carries no node-local interned id or width.

Nothing is written at apply. A node upgraded in place answers for every block it
holds, and a reorg needs nothing here: it rebuilds the journal from genesis, so
a block that is not canonical has no commit record and gets no answer.

Deliberately not read: `application_rules` (submitted text; it drops a resent
unit, so A, B, A reads as [A, B] while the engine runs A's terms),
`tau_manager.get_canonical_spec()` (outside test mode it holds only the
consensus rules), and the authoritative worker's text (shrunk, node-local).
"""
from __future__ import annotations

import hashlib
import logging
import os
import threading
from collections import OrderedDict

logger = logging.getLogger(__name__)

#: every stream index the engine accepts is kept plain in the replay
_ALL_STREAMS = frozenset(range(0, 128))
_CACHE_SIZE = 64

_lock = threading.Lock()
_cache: "OrderedDict[str, str]" = OrderedDict()


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def full_width_plan():
    import tau_reconstruction
    import tau_shrink
    return tau_reconstruction.RepresentationPlan(
        width=tau_shrink.current_shrink_width(), interned=frozenset(),
        plain=_ALL_STREAMS)


def rebuild_spec(rows, *, baseline, cwd=None, env=None, reconstruct=None) -> str:
    """Replay committed journal rows (verified) and return `current_spec()`."""
    import tau_allocator
    import tau_journal
    import tau_session
    import tau_speculation

    journal = tau_journal.journal_from_rows(rows)
    journal.verify_chain()
    cwd = cwd or os.path.dirname(os.path.abspath(__file__))
    session = (reconstruct or tau_session.WorkerSession.reconstruct)(
        baseline, journal=journal, plan=full_width_plan(),
        snapshot=tau_allocator.DbMappingSnapshot(), cwd=cwd, env=env,
        verify=True)
    try:
        return session._spec.current_spec()
    finally:
        try:
            session.dispose()
        except (Exception, tau_speculation.WorkerLost):
            pass


def at_block(block_hash=None, *, store=None, baseline=None, reconstruct=None):
    """The rules in force after `block_hash` (None: the latest commit), or None
    when no commit record names that block."""
    import tau_speculation

    if store is None:
        import db as store
    cut = store.committed_journal_at(block_hash)
    if cut is None:
        return None
    answer = {
        "block_hash": cut["tip"],
        "journal_head": cut["journal_head"],
        "spec_revision": cut["spec_revision"],
    }
    key = cut["journal_head"] or ""
    with _lock:
        text = _cache.get(key)
        if text is not None:
            _cache.move_to_end(key)
    if text is None:
        try:
            if baseline is None:
                import tau_authority
                baseline = tau_authority.program_baseline()
            if not baseline:
                raise RuntimeError("no program baseline")
            text = rebuild_spec(cut["rows"], baseline=baseline, reconstruct=reconstruct)
        except (Exception, tau_speculation.WorkerLost) as exc:
            # A divergence or a lost worker is reported, never papered over
            # with a text nobody verified.
            logger.warning("rules in force at %s could not be rebuilt: %r",
                           cut["tip"], exc)
            return {**answer, "available": False, "reason": repr(exc)[:300]}
        with _lock:
            _cache[key] = text
            while len(_cache) > _CACHE_SIZE:
                _cache.popitem(last=False)
    return {**answer, "available": True, "text": text, "sha256": _sha256(text)}


def _canonical(rule_text: str) -> str:
    import chain_state
    try:
        return chain_state._preprocess_tau_spec_text(rule_text) or (rule_text or "").strip()
    except Exception:
        return (rule_text or "").strip()


def rule_tx_outcomes(block_hash: str, rule_texts, *, store=None):
    """What each op-0 rule of one block did to the engine, from the journal.

    `rule_texts` are the block's op-0 rule texts in block order. The k-th rule
    with a given canonical text is matched to the k-th revision with that text
    committed in the block. A rule with no revision there was routed to the
    clause registry (an `o5` rule) and claims none. None when no commit record
    names the block.
    """
    if store is None:
        import db as store
    window = store.block_journal_revisions(block_hash)
    if window is None:
        return None
    revision = window["spec_revision_before"]
    pending = []
    for entry in window["entries"]:
        before = revision
        if entry.get("outcome") == "ACCEPTED_CHANGED" and revision is not None:
            revision += 1
        pending.append([_canonical(entry.get("rule_text") or ""), {
            "outcome": entry.get("outcome"),
            "taken": entry.get("outcome") == "ACCEPTED_CHANGED",
            "spec_revision_before": before,
            "spec_revision_after": revision,
            "journal_seq": entry["seq"],
        }])
    out = []
    for text in rule_texts:
        want = _canonical(text or "")
        for item in pending:
            if item[0] == want:
                out.append(item[1])
                item[0] = None          # each revision answers for one rule
                break
        else:
            out.append(None)
    return out


def reset_cache() -> None:
    with _lock:
        _cache.clear()
