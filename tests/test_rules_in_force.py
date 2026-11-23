"""#42: rules in force and rule outcomes, read from the committed journal.

Engine-free: the journal rows and commit records are written through the real
commit path (`db.commit_prepared_block`) and the reconstruction is a stub. The
real engine runs in `scripts/e2e_rules_in_force_journal.py`.
"""
import hashlib
import json
from types import SimpleNamespace

import pytest

import db
import tau_journal
import tau_rules_in_force as rif

A = "always (o26[t]:bv[24] = { 7 }:bv[24] && o27[t]:bv[24] = { 9 }:bv[24])."
B = "always (o26[t]:bv[24] = { 3 }:bv[24])."
P = "always ((i1[t]:bv[24] > { 100 }:bv[24]) ? o5[t]:bv[24] = { 0 }:bv[24] : o5[t]:bv[24] = { 1 }:bv[24])."


class _Chain:
    """Commits blocks the way block apply does: journal delta + commit record."""

    def __init__(self):
        self.journal = tau_journal.Journal(authoritative=True)
        self.parent = None
        self.revision = 6
        self.n = 0

    def commit(self, *revisions, steps=1):
        base = len(self.journal)
        for text, outcome in revisions:
            self.journal.record(tau_journal.REVISION, phase=tau_journal.PHASE_APPLY,
                                rule_text=text, outcome=outcome,
                                result={"o0": "F"})
            if outcome == "ACCEPTED_CHANGED":
                self.revision += 1
            for _ in range(steps):
                self.journal.record(tau_journal.STEP, phase=tau_journal.PHASE_APPLY,
                                    inputs={"i1": "0"}, result={"o1": "1"})
        delta = [e.to_dict() for e in self.journal.entries()[base:]]
        self.n += 1
        tip = hashlib.sha256(f"block-{self.n}".encode()).hexdigest()
        db.commit_prepared_block(
            execution_id=f"exec-{self.n}", tip=tip, parent=self.parent,
            journal_entries=delta, expected_journal_seq=base,
            allocation_delta=None, expected_epoch=None,
            journal_head=self.journal.entries()[-1].link if len(self.journal) else None,
            allocator_digest=None, plan_id=None, spec_revision=self.revision,
            timestamp=1_700_000_000 + self.n,
        )
        self.parent = tip
        return tip


def _replayed(calls):
    """A stand-in for WorkerSession.reconstruct: records what it was given and
    answers with the revisions it saw, in order."""
    def reconstruct(baseline, *, journal, plan, snapshot, cwd, env, verify):
        calls.append({"entries": len(journal), "verify": verify, "plan": plan})
        texts = [e.rule_text for e in journal.entries() if e.kind == tau_journal.REVISION]
        return SimpleNamespace(_spec=SimpleNamespace(current_spec=lambda: " | ".join(texts)),
                               dispose=lambda: None)
    return reconstruct


@pytest.fixture(autouse=True)
def _fresh_cache():
    rif.reset_cache()
    yield
    rif.reset_cache()


def test_view_at_each_block_is_the_journal_cut_at_that_block(temp_database):
    chain = _Chain()
    b1 = chain.commit((A, "ACCEPTED_CHANGED"))
    b2 = chain.commit((B, "ACCEPTED_CHANGED"))
    b3 = chain.commit((A, "ACCEPTED_CHANGED"))          # A resent
    calls = []
    views = [rif.at_block(b, store=db, baseline="base", reconstruct=_replayed(calls))
             for b in (b1, b2, b3)]
    assert [v["spec_revision"] for v in views] == [7, 8, 9]
    assert views[0]["text"] == A
    assert views[1]["text"] == f"{A} | {B}"
    # The resend is replayed: the engine's history is A, B, A, not [A, B].
    assert views[2]["text"] == f"{A} | {B} | {A}"
    assert all(c["verify"] is True for c in calls)
    # Steps are part of the replay (they are what the fingerprints check).
    assert [c["entries"] for c in calls] == [2, 4, 6]
    assert views[2]["sha256"] == hashlib.sha256(views[2]["text"].encode()).hexdigest()


def test_replay_runs_full_width(temp_database):
    chain = _Chain()
    b1 = chain.commit((A, "ACCEPTED_CHANGED"))
    calls = []
    rif.at_block(b1, store=db, baseline="base", reconstruct=_replayed(calls))
    plan = calls[0]["plan"]
    assert not plan.interned and 12 in plan.plain and 5 in plan.plain


def test_latest_commit_by_default_and_cached_per_head(temp_database):
    chain = _Chain()
    chain.commit((A, "ACCEPTED_CHANGED"))
    calls = []
    first = rif.at_block(None, store=db, baseline="base", reconstruct=_replayed(calls))
    again = rif.at_block(None, store=db, baseline="base", reconstruct=_replayed(calls))
    assert first == again and len(calls) == 1
    chain.commit((B, "ACCEPTED_CHANGED"))
    rif.at_block(None, store=db, baseline="base", reconstruct=_replayed(calls))
    assert len(calls) == 2


def test_unknown_block_has_no_answer(temp_database):
    _Chain().commit((A, "ACCEPTED_CHANGED"))
    assert rif.at_block("ab" * 32, store=db, baseline="base",
                        reconstruct=_replayed([])) is None


def test_a_replay_that_diverges_shows_no_text(temp_database):
    b1 = _Chain().commit((A, "ACCEPTED_CHANGED"))

    def diverging(*_a, **_k):
        raise tau_journal.DivergenceError("journal entry 2 diverged")
    view = rif.at_block(b1, store=db, baseline="base", reconstruct=diverging)
    assert view["available"] is False and "text" not in view
    assert "diverged" in view["reason"]


def test_a_tampered_journal_is_refused_before_replay(temp_database):
    b1 = _Chain().commit((A, "ACCEPTED_CHANGED"))
    with db._db_lock:
        db._db_conn.execute("UPDATE tau_journal_v1 SET rule_text = ? WHERE seq = 1", (B,))
        db._db_conn.commit()
    calls = []
    view = rif.at_block(b1, store=db, baseline="base", reconstruct=_replayed(calls))
    assert view["available"] is False and calls == []


def test_rule_outcomes_match_each_rule_to_its_own_revision(temp_database):
    chain = _Chain()
    chain.commit((A, "ACCEPTED_CHANGED"))
    # One block: B, an o5 clause (no revision), B again (implied: no change).
    blk = chain.commit((B, "ACCEPTED_CHANGED"), (B, "ACCEPTED_NOOP"))
    out = rif.rule_tx_outcomes(blk, [B, P, B], store=db)
    assert out[0]["taken"] is True
    assert (out[0]["spec_revision_before"], out[0]["spec_revision_after"]) == (7, 8)
    assert out[1] is None                         # clause registry: claims no revision
    assert out[2]["outcome"] == "ACCEPTED_NOOP" and out[2]["taken"] is False
    assert (out[2]["spec_revision_before"], out[2]["spec_revision_after"]) == (8, 8)


def test_rule_outcomes_need_a_commit_record(temp_database):
    assert rif.rule_tx_outcomes("cd" * 32, [A], store=db) is None


def test_account_clauses_are_read_with_the_head(temp_database):
    chain = _Chain()
    tip = chain.commit((A, "ACCEPTED_CHANGED"))
    acct = "ab" * 48
    with db._db_lock:
        db._db_conn.execute("INSERT INTO rule_clauses_v1 VALUES (?, 5, ?)", (acct, "body"))
        db._db_conn.commit()
    head, clauses = db.account_clauses_at_head(acct.upper())
    assert head == tip and clauses == [(5, "body")]


def test_command_shape(temp_database, monkeypatch):
    import commands.getrulesinforce as cmd
    import tau_authority

    chain = _Chain()
    chain.commit((A, "ACCEPTED_CHANGED"))
    monkeypatch.setattr(tau_authority.owner(), "enabled", True, raising=False)
    monkeypatch.setattr(rif, "at_block",
                        lambda block, store=None: {"block_hash": chain.parent,
                                                   "available": True, "text": A})
    acct = "ab" * 48
    container = SimpleNamespace(db=db)
    res = json.loads(cmd.execute(f"getrulesinforce {acct}", container))
    assert res["status"] == "ok"
    assert res["data"]["shared_spec"]["text"] == A
    assert res["data"]["account"] == {"address": acct, "clauses": []}
    bad = json.loads(cmd.execute("getrulesinforce zz", container))
    assert bad["error"]["code"] == "INVALID_PARAMS"
    missing = json.loads(cmd.execute("getrulesinforce 999", container))
    assert missing["error"]["code"] == "NOT_FOUND"


def test_command_without_the_authority_says_so(temp_database, monkeypatch):
    import commands.getrulesinforce as cmd
    import tau_authority

    monkeypatch.setattr(tau_authority.owner(), "enabled", False, raising=False)
    res = json.loads(cmd.execute("getrulesinforce", SimpleNamespace(db=db)))
    assert res["data"]["shared_spec"]["available"] is False


def test_gettxstatus_reports_the_rule_outcome_of_a_confirmed_rule(temp_database):
    import block as block_module
    import commands.gettxstatus as gts

    sender = "ab" * 48
    txs = [{"tx_type": "user_tx", "sender_pubkey": sender, "sequence_number": i,
            "operations": {"0": text}} for i, text in enumerate((B, P))]
    chain = _Chain()
    chain.commit((A, "ACCEPTED_CHANGED"))
    blk = block_module.Block.create(block_number=2, previous_hash=chain.parent,
                                    transactions=txs, proposer_pubkey="cd" * 48,
                                    timestamp=1_700_000_100)
    # The commit record of this block names it as the tip.
    chain.n += 1
    base = len(chain.journal)
    chain.journal.record(tau_journal.REVISION, phase=tau_journal.PHASE_APPLY,
                         rule_text=B, outcome="ACCEPTED_CHANGED", result={"o0": "F"})
    db.commit_prepared_block(
        execution_id="exec-b", tip=blk.block_hash, parent=chain.parent,
        journal_entries=[e.to_dict() for e in chain.journal.entries()[base:]],
        expected_journal_seq=base, allocation_delta=None, expected_epoch=None,
        journal_head=chain.journal.entries()[-1].link, allocator_digest=None,
        plan_id=None, spec_revision=8, timestamp=1_700_000_100)
    db.add_block(blk)
    with db._db_lock:
        for key, value in (("canonical_head_hash", blk.block_hash), ("canonical_head_number", "2")):
            db._db_conn.execute("INSERT OR REPLACE INTO chain_state (key, value) VALUES (?, ?)",
                                (key, value))
        db._db_conn.commit()
    container = SimpleNamespace(db=db)
    rule = json.loads(gts.execute(f"gettxstatus {blk.tx_ids[0]}", container))["data"]
    assert rule["status"] == "confirmed"
    assert rule["rule_outcome"]["engine_revision"]["taken"] is True
    assert rule["rule_outcome"]["engine_revision"]["spec_revision_after"] == 8
    clause = json.loads(gts.execute(f"gettxstatus {blk.tx_ids[1]}", container))["data"]
    assert clause["rule_outcome"]["engine_revision"] is None
