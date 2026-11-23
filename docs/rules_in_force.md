# Rules in force (#42)

Two answers a wallet needs, both read from what the node already commits:

| question | call | from |
|---|---|---|
| What does the engine run after block B? Which clauses does my account have? | `getrulesinforce [<block_hash> \| <height>] [<account>]` | the committed journal cut at B, replayed |
| Did my confirmed rule transaction change the engine? | `gettxstatus <hash>` → `rule_outcome` | the journal rows committed in that block |

## Where the answer comes from

A node rebuilds its engine at restart from the **committed journal**
(`tau_journal_v1`): every revision and step the engine executed for committed
blocks, each with the fingerprint of what it produced, hash-linked. Every block
commit records the journal head it ends at (`block_commits_v1`). These two tables
are the only source here. Nothing new is written at apply.

`getrulesinforce` runs the node's own reconstruction
(`WorkerSession.reconstruct(..., verify=True)`) on the journal cut at the block,
with every stream plain, and returns the engine's `current_spec()`:

```json
{"shared_spec": {"block_hash": "…", "journal_head": "…", "spec_revision": 9,
                 "available": true, "text": "always (… o26[t]:bv[24] = { 7 } …)",
                 "sha256": "…"},
 "account": {"address": "…", "clauses": [{"stream": 5, "kind": "policy (o5)",
             "text": "…", "sha256": "…"}]}}
```

* **Checked.** Each replayed revision and step is compared with the fingerprint
  recorded when the block was applied. A replay that does not reproduce the
  committed execution, or a journal row that was altered, gives
  `available: false` and a `reason`: a text is never shown unverified.
* **The same on every node.** Full width, so no node-local interned id or width
  is in the text. Two nodes give the same text and sha256 for the same block.
* **Any canonical block.** A payer and a payee can both ask about one block
  hash. A reorg rebuilds the journal from genesis, so a block that is not
  canonical has no commit record and gets `NOT_FOUND`.
* **Upgrade in place.** The journal exists on main already, so an upgraded node
  answers for blocks it applied before the upgrade too.
* **Cost.** One worker replay per journal head the first time (about 0.3 s for
  a short chain), then cached (64 heads). In the expensive RPC tier.

The account section lists the account's own clauses from the clause registry
(its `o5` policy, its rule-change guard), each with the sha256 of the stored
body. The registry is kept for the head only, so it is given only when the view
is at the head, and an older block says so instead of guessing.

## Why not the other texts

* `application_rules` / `gettaustate` is the submitted text, and it drops a
  resent unit. A, then B, then A again leaves `[A, B]` there, while the engine
  runs A's terms (`o26 = 7`). A view built from it answers `o26 = 3`.
* `tau_manager.get_canonical_spec()`: outside test mode the authoritative engine
  is a worker, and the in-process interpreter behind this call holds only the
  consensus rules (no user rule at all).
* The authoritative worker's own text runs address streams shrunk to a
  node-local width, so two nodes cannot compare it.

## `rule_outcome`

For a confirmed transaction with an op-`0` rule:

```json
"rule_outcome": {"recorded": true, "engine_revision": {
    "outcome": "ACCEPTED_CHANGED", "taken": true,
    "spec_revision_before": 8, "spec_revision_after": 9, "journal_seq": 13}}
```

The k-th rule of a block with a given canonical text is matched to the k-th
revision with that text committed in the block, so two rules in one block keep
their own outcomes. `ACCEPTED_NOOP` (a rule the engine already implied) is
`taken: false` with the counter unchanged. An `o5` rule goes to the clause
registry and claims no revision: `engine_revision: null`. Every node holding the
block answers the same, not only the proposer.

## Checking it

* `tests/test_rules_in_force.py`: engine-free; journal rows written through
  `db.commit_prepared_block`.
* `scripts/e2e_rules_in_force_journal.py`: real engine. `run` (A, B, A resent;
  two rules in one block; an o5 clause; account clauses; bad arguments), `after`
  (restart: every view and outcome byte for byte), `follow` (a second node
  syncing from block 0 over p2p: the same), `forge` (a copy of the database
  where one committed step claims other outputs and the hash chain is relinked
  so it still verifies: every view from that step on is refused).
