"""Live check of #42 on the real engine: rules in force and rule outcomes, read
from the committed journal.

    python scripts/e2e_rules_in_force_journal.py provision --dir /tmp/rif
    # start a node from that directory (TAU_ENV=production, mining off), then:
    python scripts/e2e_rules_in_force_journal.py run --dir /tmp/rif
    # restart the node, then:
    python scripts/e2e_rules_in_force_journal.py after --dir /tmp/rif
    # forge one step result in a COPY of the database (hash chain kept valid):
    python scripts/e2e_rules_in_force_journal.py forge --dir /tmp/rif --db /tmp/copy.db
    # a second node syncing from block 0 over p2p:
    python scripts/e2e_rules_in_force_journal.py follow --dir /tmp/rif \
        --miner-identity /tmp/rif/data/identity.key

`run` writes what it saw to <dir>/data/rif_expect.json; `after` and `follow`
compare every view and every rule outcome against it, byte for byte.
"""
import argparse
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import time

ACTORS = ("miner", "alice", "bob")
A = "always (o26[t]:bv[24] = { 7 }:bv[24] && o27[t]:bv[24] = { 9 }:bv[24])."
B = "always (o26[t]:bv[24] = { 3 }:bv[24])."
C = "always (o28[t]:bv[24] = { 5 }:bv[24])."
D = "always (o26[t]:bv[24] = { 4 }:bv[24])."
P = ("always ((i1[t]:bv[24] > { 100 }:bv[24]) ? o5[t]:bv[24] = { 0 }:bv[24] "
     ": o5[t]:bv[24] = { 1 }:bv[24]).")
FAILED = []


def say(msg):
    print(f"[rif] {msg}", flush=True)


def check(label, ok, detail=""):
    say(f"{'PASS' if ok else 'FAIL'}: {label}" + (f" ({detail})" if detail and not ok else ""))
    if not ok:
        FAILED.append(label)


def provision(target):
    from py_ecc.bls import G2Basic as bls

    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.makedirs(os.path.join(target, "data"), exist_ok=True)
    if not os.path.exists(os.path.join(target, "server.py")):
        subprocess.run(f"git -C {repo} archive HEAD | tar -x -C {target}", shell=True, check=True)
    keys = {}
    for name in ACTORS:
        sk = bls.KeyGen(f"rif-e2e-{name}".encode())
        keys[name] = {"sk": format(sk, "064x"), "pk": bls.SkToPk(sk).hex()}
    json.dump(keys, open(os.path.join(target, "keys.json"), "w"), indent=2)
    cmd = [sys.executable, "scripts/gen_genesis.py", "--validator-privkey", keys["miner"]["sk"],
           "--base-fee", "10", "--network-id", "tau-rif-e2e", "--out", "data/genesis.json"]
    for name in ACTORS[1:]:
        cmd += ["--account", f"{keys[name]['pk']}:1000000"]
    subprocess.run(cmd, cwd=target, check=True)
    say(f"provisioned; miner key {keys['miner']['sk']}")
    return 0


class Node:
    def __init__(self, target, port):
        self.port = port
        self.keys = json.load(open(os.path.join(target, "keys.json")))
        sys.path.insert(0, target)
        from consensus.tx_signing import signing_message_bytes
        from py_ecc.bls import G2Basic as bls
        self._sign_bytes, self._bls = signing_message_bytes, bls

    def rpc(self, cmd, timeout=180.0):
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=timeout)
        try:
            sock.sendall((cmd + "\r\n").encode())
            sock.shutdown(socket.SHUT_WR)
            chunks = []
            while True:
                buf = sock.recv(65536)
                if not buf:
                    break
                chunks.append(buf)
            return json.loads(b"".join(chunks).decode(errors="replace").strip())
        finally:
            sock.close()

    def wait(self, tries=90):
        for _ in range(tries):
            try:
                if self.rpc(f"getsequence {self.pk('alice')}", timeout=5).get("status") == "ok":
                    return True
            except Exception:
                pass
            time.sleep(2)
        return False

    def pk(self, name):
        return self.keys[name]["pk"]

    def deploy(self, name, rule):
        payload = {"tx_type": "user_tx", "operations": {"0": rule},
                   "sender_pubkey": self.pk(name)}
        seq = self.rpc(f"getsequence {self.pk(name)}")["data"]
        payload["sequence_number"] = seq["sequence_number"]
        payload["expiration_time"] = int(time.time()) + 3600
        payload["expire_at_height"] = int(seq.get("tip_height") or 0) + 1000
        payload["fee_limit"] = "10000"
        digest = hashlib.sha256(self._sign_bytes(payload)).digest()
        payload["signature"] = self._bls.Sign(int(self.keys[name]["sk"], 16), digest).hex()
        res = self.rpc("sendtx '" + json.dumps(payload, separators=(",", ":")) + "'")
        return (res.get("data") or {}).get("tx_hash"), res

    def mine(self):
        for _ in range(8):
            res = self.rpc("createblock")
            if "BUSY" not in json.dumps(res).upper():
                return res
            time.sleep(3)
        return res

    def view(self, *args):
        return self.rpc(" ".join(("getrulesinforce",) + tuple(str(a) for a in args)))

    def outcome(self, tx_hash):
        return self.rpc(f"gettxstatus {tx_hash}")["data"].get("rule_outcome")


def terms(text):
    return dict(re.findall(r"(o2[6-9])\[t\]:bv\[24\] = \{ ?([#x0-9a-f]+) ?\}", text or ""))


def heights(n):
    blocks = n.rpc("getblocks")["data"].get("blocks") or []
    return max(int(b["header"]["block_number"]) for b in blocks)


def snapshot(n, txs):
    views = {}
    for h in range(heights(n) + 1):
        spec = n.view(h)["data"]["shared_spec"]
        views[str(h)] = {k: spec.get(k) for k in ("available", "spec_revision", "sha256")}
    return {"views": views, "outcomes": {t: n.outcome(t) for t in txs}}


def run(target, port):
    n = Node(target, port)
    check("node answers", n.wait())
    txs = {}
    for label, who, rule in (("A", "alice", A), ("B", "alice", B), ("A again", "alice", A)):
        txs[label], res = n.deploy(who, rule)
        check(f"{label} admitted", bool(txs[label]), json.dumps(res)[:200])
        n.mine()
    txs["C"], _ = n.deploy("alice", C)
    txs["D"], _ = n.deploy("bob", D)
    n.mine()
    txs["policy"], res = n.deploy("bob", P)
    check("o5 policy admitted", bool(txs["policy"]), json.dumps(res)[:200])
    n.mine()

    seen = [terms(n.view(h)["data"]["shared_spec"].get("text")) for h in range(1, 6)]
    check("block 1: o26 = 7, o27 = 9", seen[0] == {"o26": "7", "o27": "9"}, seen[0])
    check("block 2: o26 = 3, o27 = 9 (the probe of Sep 27)", seen[1] == {"o26": "3", "o27": "9"}, seen[1])
    check("block 3: A resent -> o26 = 7 again (application_rules still lists [A, B])",
          seen[2] == {"o26": "7", "o27": "9"}, seen[2])
    check("block 4: two rules in one block both in force",
          seen[3] == {"o26": "4", "o27": "9", "o28": "5"}, seen[3])
    check("block 5: an o5 clause does not change the shared spec", seen[4] == seen[3], seen[4])
    acc = n.rpc("gettaustate")["data"]["rules_state"]
    check("application_rules holds A once (the resend is dropped there)", acc.count(A) == 1)

    h1 = n.view(1)["data"]["shared_spec"]
    h3 = n.view(3)["data"]["shared_spec"]
    check("same terms -> same text and sha256 (block 1 and block 3)",
          h1["sha256"] == h3["sha256"] and h1["text"] == h3["text"])
    check("every view is verified", all(n.view(h)["data"]["shared_spec"]["available"]
                                        for h in range(0, 6)))

    out = {k: n.outcome(v) for k, v in txs.items()}
    revs = [(out[k]["engine_revision"] or {}).get("spec_revision_after")
            for k in ("A", "B", "A again", "C", "D")]
    check("each rule tx says the engine took it, in order",
          all(out[k]["engine_revision"]["taken"] for k in ("A", "B", "A again", "C", "D")))
    check("spec_revision rises by one per rule, also inside one block",
          revs == list(range(revs[0], revs[0] + 5)), revs)
    check("the o5 clause claims no revision", out["policy"]["engine_revision"] is None)

    acct = n.view(n.pk("bob"))["data"]["account"]
    check("bob's own clause is listed with its sha256",
          [c["stream"] for c in acct["clauses"]] == [5]
          and acct["clauses"][0]["sha256"] == hashlib.sha256(acct["clauses"][0]["text"].encode()).hexdigest())
    check("alice has no clause", n.view(n.pk("alice"))["data"]["account"]["clauses"] == [])
    check("an old block does not pretend to know the registry",
          n.view(2, n.pk("bob"))["data"]["account"]["clauses"] is None)
    check("a height past the head is NOT_FOUND",
          n.view(999).get("error", {}).get("code") == "NOT_FOUND")
    check("garbage is INVALID_PARAMS", n.view("zz").get("error", {}).get("code") == "INVALID_PARAMS")

    json.dump({"txs": txs, **snapshot(n, list(txs.values()))},
              open(os.path.join(target, "data", "rif_expect.json"), "w"), indent=1)
    return _finish("ALL CHECKS PASSED")


def _compare(n, target, label):
    expect = json.load(open(os.path.join(target, "data", "rif_expect.json")))
    got = snapshot(n, list(expect["txs"].values()))
    for h, view in expect["views"].items():
        check(f"{label}: block {h} same spec_revision and sha256", got["views"].get(h) == view,
              f"{got['views'].get(h)} != {view}")
    for name, tx in expect["txs"].items():
        check(f"{label}: outcome of {name} unchanged", got["outcomes"][tx] == expect["outcomes"][tx])


def after(target, port):
    n = Node(target, port)
    check("node answers after restart", n.wait())
    _compare(n, target, "after restart")
    return _finish("RESTART AGREES")


def follow(target, port, miner_identity, miner_p2p, follower_port=65521,
           follower_p2p="/ip4/127.0.0.1/tcp/4012"):
    from libp2p.peer.id import ID
    from network.libp2p_compat import keypair_from_seed

    n = Node(target, port)
    peer = str(ID.from_pubkey(keypair_from_seed(open(miner_identity, "rb").read()).public_key))
    data = os.path.join(target, "follower")
    os.makedirs(data, exist_ok=True)
    env = dict(os.environ)
    env.update({
        "TAU_ENV": "production", "TAU_FORCE_TEST": "0", "TAU_MINING_ENABLED": "false",
        "TAU_PORT": str(follower_port), "TAU_HOST": "127.0.0.1", "TAU_DATA_DIR": data,
        "TAU_DB_PATH": os.path.join(data, "node.db"),
        "TAU_IDENTITY_KEY_PATH": os.path.join(data, "identity.key"),
        "TAU_PEERSTORE_PATH": os.path.join(data, "peerstore"),
        "TAU_NETWORK_LISTEN": follower_p2p,
        "TAU_BOOTSTRAP_PEERS": json.dumps([{"peer_id": peer, "addrs": [miner_p2p]}]),
        "TAU_DHT_BOOTSTRAP": "[]",
    })
    env.pop("TAU_MINER_PRIVKEY", None)
    log = open(os.path.join(data, "follower.log"), "w")
    proc = subprocess.Popen([sys.executable, "server.py"], cwd=target, env=env,
                            stdout=log, stderr=log)
    f = Node(target, follower_port)
    try:
        goal = heights(n)
        synced = False
        for _ in range(120):
            time.sleep(5)
            try:
                if heights(f) == goal:
                    synced = True
                    break
            except Exception:
                continue
        check("second node replays every block from block 0", synced)
        _compare(f, target, "second node")
    finally:
        proc.terminate()
    return _finish("BOTH NODES AGREE")


def forge(target, db_path):
    """In a copy of the database, claim one committed step produced other
    outputs, relink the whole chain so it still verifies, and check that every
    view from that step on is refused while the earlier ones still answer."""
    import sqlite3
    os.environ["TAU_DB_PATH"] = db_path
    sys.path.insert(0, target)
    import db
    import tau_journal
    import tau_rules_in_force as rif

    c = sqlite3.connect(db_path)
    cols = [r[1] for r in c.execute("PRAGMA table_info(tau_journal_v1)")]
    rows = [dict(zip(cols, r)) for r in c.execute("SELECT * FROM tau_journal_v1 ORDER BY seq")]
    b_seq = next(r["seq"] for r in rows if r["kind"] == "revision" and (r["rule_text"] or "") == B)
    victim = next(r for r in rows if r["kind"] == "step" and r["seq"] > b_seq)
    victim["result_fp"] = tau_journal.fingerprint(tau_journal.semantic_result(outputs={"o1": "999"}))
    prev = None
    for r in rows:
        entry = tau_journal.JournalEntry(
            seq=r["seq"], kind=r["kind"], phase=r["phase"], rule_text=r["rule_text"],
            inputs=json.loads(r["inputs"] or "{}"), target=r["target"],
            accumulate=bool(r["accumulate"]),
            units=tuple(tuple(u) for u in json.loads(r["units"] or "[]")),
            outcome=r["outcome"], result_fingerprint=r["result_fp"],
            identity=json.loads(r["identity"]) if r["identity"] else None, prev=prev)
        link = entry.compute_link()
        c.execute("UPDATE tau_journal_v1 SET prev=?, link=?, result_fp=? WHERE seq=?",
                  (prev, link, r["result_fp"], r["seq"]))
        c.execute("UPDATE block_commits_v1 SET journal_head=? WHERE journal_head=?",
                  (link, r["link"]))
        prev = link
    c.commit()
    db.init_db()
    tau_journal.journal_from_rows(db.committed_journal_entries()).verify_chain()
    check("the forged journal still passes the hash-chain check", True)
    forged_block = None
    for h in range(0, 6):
        cut = db.committed_journal_at(db.get_canonical_block_hash_at(h))
        if cut["rows"] and cut["rows"][-1]["seq"] >= victim["seq"]:
            forged_block = h
            break
    for h in range(0, 6):
        view = rif.at_block(db.get_canonical_block_hash_at(h), store=db)
        want = h < forged_block
        check(f"block {h}: {'answers' if want else 'refused (replay diverges)'}",
              view["available"] is want, view.get("reason", ""))
    return _finish("FORGERY REFUSED")


def _finish(ok_text):
    if FAILED:
        say(f"{len(FAILED)} check(s) FAILED: {FAILED}")
        return 1
    say(ok_text)
    return 0


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("provision", "run", "after", "follow", "forge"):
        p = sub.add_parser(name)
        p.add_argument("--dir", required=True)
        p.add_argument("--port", type=int, default=65511)
        if name == "follow":
            p.add_argument("--miner-identity", required=True)
            p.add_argument("--miner-p2p", default="/ip4/127.0.0.1/tcp/4001")
        if name == "forge":
            p.add_argument("--db", required=True)
    args = ap.parse_args()
    if args.cmd == "provision":
        return provision(args.dir)
    if args.cmd == "run":
        return run(args.dir, args.port)
    if args.cmd == "after":
        return after(args.dir, args.port)
    if args.cmd == "forge":
        return forge(args.dir, args.db)
    return follow(args.dir, args.port, args.miner_identity, args.miner_p2p)


if __name__ == "__main__":
    sys.exit(main())
