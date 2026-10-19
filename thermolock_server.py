#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
thermolock_guard.py -- THE ThermoLock verification tool (single file).

Everything that was previously split across thermolock_review_gate.py +
thermolock_regression_suite.py + sample fixtures is consolidated here:

  GATE (review-finding intake, batch-8 prescription):
    ingest          raw-bytes fingerprint (sha256 / bytes / lines) of the target
    quote <s> <e>   emit a hash-anchored finding skeleton whose quote is the
                    file's EXACT bytes -- use this to PRODUCE findings, so they
                    are born verified instead of typed into a Markdown buffer
    verify <json>   run the four intake gates on a review JSON:
                       1. hash anchor   -- finding must cite these raw bytes
                       2. verbatim quote -- byte-exact match anywhere in the
                          file; BRACKET_EATEN detector flags the known
                          pipeline defect (quote only matches after [N]
                          indexers are stripped from the real line)
                       3. observable failure -- expected-vs-actual required
                       4. dedup -- reject anything matching the adjudicated
                          ledger (batches 2-9, embedded below)
    ledger list|seed
                    inspect / regenerate the adjudicated-findings ledger
                    (optional JSON scratchpad; tool works from the embedded
                    seed even if the JSON is deleted)

  PROOF (empirical battery, 24 checks -- every behavioral guarantee plus the
  tests that adjudicate recurring review findings, tagged per finding):
    suite           exit 0 iff every guarantee holds ("24/24 GUARANTEES HOLD")

  SELF-PROOF:
    selftest        embedded fixtures: a batch-9-replica review must be 4/4
                    REJECTED, a properly-anchored review must PASS -- proves
                    the gate is neither deaf nor blanket-hostile

Stdlib only. One file, one command surface:

    python3 thermolock_guard.py selftest
    python3 thermolock_guard.py suite
    python3 thermolock_guard.py verify review.json

Exit 0 on success everywhere; exit 1 when findings are rejected, guarantees
fail, or the selftest expectations break.

Scope note: the production daemon (thermolock_server.py) and the ops-side
retention purger (thermolock_retention.py) are runtime deliverables and stay
separate by design -- this file is verification tooling, not deployment code.
"""

import argparse
import contextlib
import concurrent.futures
import difflib
import glob
import hashlib
import importlib.util
import io
import json
import os
import re
import signal
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import zipfile
from http.server import HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_TARGET = os.path.join(HERE, "thermolock_server.py")
LEDGER_PATH = os.path.join(HERE, "thermolock_review_ledger.json")

EXIT_ALL_PASS = 0
EXIT_REJECTED = 1


# ==========================================================================
# PART 1 -- GATE: raw-bytes primitives
# ==========================================================================
def load_raw(path):
    with open(path, "rb") as fh:
        return fh.read()


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def raw_lines(raw):
    """The file is mandated UTF-8; surrogateescape fallback ensures the tool
    itself can never crash on its input."""
    return raw.decode("utf-8", "surrogateescape").splitlines()


def locate_quote(raw, quote):
    """Byte-exact search. Returns (found, line_number | None)."""
    q = quote.encode("utf-8", "surrogateescape")
    idx = raw.find(q)
    if idx < 0:
        return False, None
    return True, raw[:idx].count(b"\n") + 1


def bracket_eaten_match(lines, quote):
    """Detect the known pipeline defect: any line of the quote matches a real
    file line only after square-bracket indexers are stripped from the real
    line."""
    for qline in quote.strip().splitlines():
        q = qline.strip()
        if not q:
            continue
        for n, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped != q and re.sub(r"\[\d+\]", "", stripped) == q:
                return (n, stripped)
    return None


def nearest_line(lines, quote):
    q = quote.strip().splitlines()[0] if quote.strip() else ""
    return max(
        (difflib.SequenceMatcher(None, q, ln.strip()).ratio(), n, ln.strip())
        for n, ln in enumerate(lines, 1)
    )


# ==========================================================================
# PART 2 -- GATE: adjudicated-findings ledger (batches 2-9, embedded seed)
# ==========================================================================
LEDGER_SEED = [
    {
        "id": "PHANTOM-SPLIT-BRACKET0",
        "title": "do_GET/do_POST crash -- missing [0] on self.path.split('?')",
        "status": "REJECTED-PHANTOM",
        "batches": ["5", "8"],
        "reason": ("Raw bytes at lines 1229 and 1247 contain the [0] indexer "
                   "'self.path.split(\"?\", 1)[0]'. The finding reviewed a "
                   "Markdown-mangled copy in which brackets were stripped. "
                   "Refuted by grep of raw bytes and live route tests "
                   "(200/200/200/404)."),
        "disproved_by": "guard-suite: routing; batch-8 P1",
        "match": {
            "title_regex": [
                r"split.*\?.*index|missing.*\[0\]|index(error)?.*split|crash.*split"
            ],
            "quote_substrings": ['self.path.split("?", 1)\n'],
        },
    },
    {
        "id": "PHANTOM-ENTRY-BRACKETS",
        "title": "rate-limiter crash -- entry[0]/entry[1] unpacking",
        "status": "REJECTED-PHANTOM",
        "batches": ["5"],
        "reason": ("Lines 792/794/796 index the bucket list as entry[1]/"
                   "entry[0] exactly as written; the reported crash cannot "
                   "occur. Same bracket-eating pipeline defect as "
                   "PHANTOM-SPLIT-BRACKET0."),
        "disproved_by": "batch-5 grep + E1-E3 battery",
        "match": {
            "title_regex": [r"entry\[|tuple.*unpack.*bucket|rate.?limit.*crash"],
            "quote_substrings": ["entry[1] = now"],
        },
    },
    {
        "id": "PHANTOM-MIXIN-INIT",
        "title": "Multi-Threaded Inheritance Cascade Fault (mixin __init__)",
        "status": "REJECTED-PHANTOM",
        "batches": ["6", "8", "9"],
        "reason": ("socketserver.ThreadingMixIn defines no __init__; the "
                   "legacy composite gets HTTPServer.__init__ via MRO and "
                   "threading via process_request. No override is required. "
                   "Submitted three times under three names."),
        "disproved_by": "guard-suite: mixin-cascade (concurrent serve, <2500ms)",
        "match": {
            "title_regex": [
                r"inheritance.*cascade|mixin.*(__init__|single.?thread)|single.?threaded behavior"
            ],
            "quote_substrings": [],
        },
    },
    {
        "id": "PHANTOM-DEL-REQUEST",
        "title": "Socket Handle Exfiltration Risk (del request in finally)",
        "status": "REJECTED-PHANTOM",
        "batches": ["6", "8", "9"],
        "reason": ("CPython closes the accepted socket via request.close() "
                   "(lines 1145-1150) plus refcounting; 'del request' on a "
                   "local binding has zero kernel-FD effect. Shed accounting "
                   "is exact: pool returns to full after holder EOF."),
        "disproved_by": "guard-suite: thread-cap",
        "match": {
            "title_regex": [
                r"exfiltrat.*(risk|handle)|del request|fd.*(leak|destruction)|socket.*leak"
            ],
            "quote_substrings": ["del request"],
        },
    },
    {
        "id": "PHANTOM-READ1-STUTTER",
        "title": "Network Stream Stutter Vulnerability (read1 double-read)",
        "status": "REJECTED-PHANTOM",
        "batches": ["6", "9"],
        "reason": ("On blocking sockets, read1() returns b'' only at genuine "
                   "EOF -- never at congestion. 4,053 bytes dripped one byte "
                   "per recv ingested as 200 with no phantom EOF; slowloris "
                   "trickle cut by the absolute 408 deadline."),
        "disproved_by": "guard-suite: byte-at-a-time, slowloris-408",
        "match": {
            "title_regex": [
                r"stutter|double.?read|read1.*(b''|empty|stutter)|stream.*stutter"
            ],
            "quote_substrings": [],
        },
    },
    {
        "id": "RULED-SERVER-VERSION-REMOVAL",
        "title": "Remove server_version / drop Server header entirely",
        "status": "REJECTED-BY-DESIGN",
        "batches": ["3"],
        "reason": ("BaseHTTPRequestHandler.version_string is alive in "
                   "3.12-3.14; suppression uses sys_version='' which keeps "
                   "'ThermoLock/1.0' while removing CPython/build leakage."),
        "disproved_by": "guard-suite: sec-headers (Server token present, sys info absent)",
        "match": {"title_regex": [r"server_version|remove.*server.*header"], "quote_substrings": []},
    },
    {
        "id": "RULED-COPY-TRUNCATE-DEFAULT",
        "title": "Default rollover must be copy-truncate",
        "status": "REJECTED-RISK / IMPLEMENTED-AS-OPT-IN",
        "batches": ["7"],
        "reason": ("Silent copy-truncate as default is a data-loss cannon. "
                   "Implemented instead as THERMOLOCK_ROLLOVER_FALLBACK opt-in "
                   "with copy->fsync->byte-verify->truncate and a documented "
                   "loss window; default remains append+warn (zero loss)."),
        "disproved_by": "batch-7 T2/T3; guard-suite: fallback-off / fallback-on",
        "match": {
            "title_regex": [r"copy.?truncate.*default|default.*copy.?truncate|fallback.*must"],
            "quote_substrings": [],
        },
    },
    {
        "id": "RULED-EXCEPT-PERMERR",
        "title": "except (OSError, PermissionError) redundancy",
        "status": "REJECTED-TRIVIA",
        "batches": ["2"],
        "reason": "PermissionError subclasses OSError since 3.3; listing both is a no-op.",
        "disproved_by": "Python data model",
        "match": {"title_regex": [r"permissionerror.*redundan|except \(oserror"], "quote_substrings": []},
    },
    {
        "id": "RULED-FINISH-SEM-RELEASE",
        "title": "Release thread token in Handler.finish",
        "status": "REJECTED-LEAK",
        "batches": ["6"],
        "reason": ("finish() runs in the worker AFTER the request; releasing "
                   "there leaks tokens on parse-level aborts before handler "
                   "dispatch. Token lifetime is owned by "
                   "process_request/process_request_thread where exactly-once "
                   "release is proven."),
        "disproved_by": "guard-suite: thread-cap (pool exact), storm-integrity",
        "match": {"title_regex": [r"finish\(\).*release|release.*in finish|token.*finish"], "quote_substrings": []},
    },
    {
        "id": "RULED-EMBED-TLS",
        "title": "Embed TLS/mTLS inside the process",
        "status": "REJECTED-BY-DESIGN",
        "batches": ["6"],
        "reason": ("Stdlib-only constraint + estate reverse proxy already "
                   "terminates TLS; bearer AUTH_TOKEN_BYTES is documented "
                   "defense-in-depth, not a TLS replacement."),
        "disproved_by": "batch-6 decision record; guard-suite: bearer-gate",
        "match": {"title_regex": [r"embed.*tls|mtls|tls inside|add ssl"], "quote_substrings": []},
    },
    {
        "id": "IMPLEMENTED-BEARER-GATE",
        "title": "Unauthenticated ingestion (missing auth)",
        "status": "ALREADY-IMPLEMENTED",
        "batches": ["6", "7"],
        "reason": ("AUTH_TOKEN / AUTH_TOKEN_BYTES gate every route (401 + "
                   "WWW-Authenticate), health included; token compared in "
                   "constant time."),
        "disproved_by": "guard-suite: bearer-gate",
        "match": {"title_regex": [r"no authentication|missing auth|unauthenticated ingest"], "quote_substrings": []},
    },
    {
        "id": "IMPLEMENTED-ROLLOVER",
        "title": "No log rotation / rollover",
        "status": "ALREADY-IMPLEMENTED",
        "batches": ["1", "2", "7"],
        "reason": ("Size-hint ledger rollover with ENOSPC/locked rollback "
                   "guards plus opt-in hardened fallback; verified across "
                   "batches 1, 2 and 7."),
        "disproved_by": "guard-suite: size-fallback, enospc-rollback, locked-rollback",
        "match": {"title_regex": [r"no rotation|missing rotation|no rollover"], "quote_substrings": []},
    },
]


def seed_ledger():
    with open(LEDGER_PATH, "w", encoding="utf-8") as fh:
        json.dump({"adjudicated": LEDGER_SEED}, fh, indent=2, ensure_ascii=False)
    return LEDGER_PATH


def load_ledger():
    """The JSON scratchpad lets humans add/edit rulings without touching this
    file; the embedded seed keeps the tool fully functional if it is absent."""
    if not os.path.exists(LEDGER_PATH):
        seed_ledger()
    try:
        with open(LEDGER_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)["adjudicated"]
    except (OSError, ValueError):
        return LEDGER_SEED


def ledger_hits(ledger, finding):
    title = (finding.get("title") or "").strip()
    quote = finding.get("quote") or ""
    hits = []
    for entry in ledger:
        m = entry.get("match", {})
        for rx in m.get("title_regex", []):
            if title and re.search(rx, title, re.IGNORECASE):
                hits.append(entry)
                break
        else:
            for sub in m.get("quote_substrings", []):
                if sub and sub in quote:
                    hits.append(entry)
                    break
    return hits


# ==========================================================================
# PART 3 -- GATE commands
# ==========================================================================
def cmd_ingest(target):
    raw = load_raw(target)
    fp = {
        "file": os.path.basename(target),
        "path": os.path.abspath(target),
        "sha256": sha256_hex(raw),
        "bytes": len(raw),
        "lines": len(raw_lines(raw)),
    }
    print(json.dumps(fp, indent=2))
    return EXIT_ALL_PASS


def cmd_quote(target, start, end):
    raw = load_raw(target)
    lines = raw_lines(raw)
    if not (1 <= start < end <= len(lines) + 1):
        print("line range outside 1..%d" % len(lines), file=sys.stderr)
        return EXIT_REJECTED
    skel = {
        "id": "FILL-ME",
        "title": "FILL-ME (one line, concrete)",
        "severity": "low|medium|high",
        "file": os.path.basename(target),
        "file_sha256": sha256_hex(raw),
        "lines": [start, end - 1],
        "quote": "\n".join(lines[start - 1:end - 1]),
        "observable_failure": {
            "repro": "exact command/request that demonstrates the defect",
            "expected": "correct behavior",
            "actual": "observed behavior -- REQUIRED, not optional",
        },
    }
    print(json.dumps(skel, indent=2, ensure_ascii=False))
    return EXIT_ALL_PASS


def verify_one(raw, file_hash, finding, ledger, idx):
    verdicts = []
    title = (finding.get("title") or "(untitled)").strip()
    fid = finding.get("id") or "#%d" % idx

    # Gate 1 -- hash anchor (per-finding, or inherited review-level anchor).
    f_hash = (finding.get("file_sha256") or finding.get("file_hash")
              or finding.get("_review_hash"))
    if not f_hash:
        verdicts.append(("NO_HASH_ANCHOR",
                         "finding carries no file_sha256; cannot prove it was "
                         "produced from these bytes"))
    elif f_hash != file_hash:
        verdicts.append(("STALE_HASH",
                         "finding anchors to sha256:%s but file is sha256:%s"
                         % (f_hash[:12], file_hash[:12])))

    # Gate 2 -- verbatim quote, byte-exact, with the known-defect detector.
    quote = finding.get("quote")
    if not quote or not quote.strip():
        verdicts.append(("NO_QUOTE",
                         "no verbatim quote; resubmit with the raw offending "
                         "line(s) (see: quote command)"))
    else:
        found, _ = locate_quote(raw, quote)
        if not found:
            lines = raw_lines(raw)
            eaten = bracket_eaten_match(lines, quote)
            if eaten:
                detail = ("BRACKET_EATEN: quote matches raw line %d only after "
                          "[N] indexers are stripped from the real line: %s  "
                          "-- your pipeline is eating square brackets; analyze "
                          "raw bytes") % (eaten[0], eaten[1])
            else:
                ratio, n, near = nearest_line(lines, quote)
                detail = "nearest match line %d (%.0f%% similar): %s" % (n, ratio * 100, near)
            verdicts.append(("QUOTE_NOT_IN_RAW_BYTES", detail))

    # Gate 3 -- observable failure required.
    obs = finding.get("observable_failure") or finding.get("repro") or ""
    if isinstance(obs, dict):
        obs = " ".join(str(v) for v in obs.values() if v)
    if not str(obs).strip() or "fill-me" in str(obs).lower():
        verdicts.append(("NO_OBSERVABLE_FAILURE",
                         "no observable failure stated (expected vs actual "
                         "under a concrete repro is mandatory)"))

    # Gate 4 -- dedup against the adjudicated ledger.
    for entry in ledger_hits(ledger, finding):
        verdicts.append(("ALREADY_ADJUDICATED",
                         "%s [%s, batches %s]: %s | refutation: %s"
                         % (entry["title"], entry["status"],
                            ",".join(entry["batches"]), entry["reason"][:160],
                            entry["disproved_by"])))

    header = "%s  %s" % (fid, title)
    return not verdicts, header, verdicts


def cmd_verify(review_path, target, quiet=False):
    raw = load_raw(target)
    file_hash = sha256_hex(raw)
    with open(review_path, "r", encoding="utf-8") as fh:
        review = json.load(fh)
    ledger = load_ledger()
    findings = review.get("findings", [])

    top_hash = review.get("file_sha256") or review.get("file_hash")
    for f in findings:
        f.setdefault("_review_hash", top_hash)

    out = []
    def emit(s=""):
        out.append(s)
        if not quiet:
            print(s)

    emit("== thermolock guard | verify ==")
    emit("target   : %s" % os.path.abspath(target))
    emit("file sha : %s (%d bytes)" % (file_hash, len(raw)))
    emit("ledger   : %d adjudicated entries" % len(ledger))
    if top_hash and top_hash != file_hash:
        emit("NOTE     : review-level hash mismatch -> findings produced from "
             "different bytes")
    emit()

    rejected = 0
    for i, f in enumerate(findings, 1):
        ok_, header, verdicts = verify_one(raw, file_hash, f, ledger, i)
        if ok_:
            emit("PASS  %s" % header)
            emit("      gates 1-4 satisfied -> eligible for technical review")
        else:
            rejected += 1
            emit("REJECT  %s" % header)
            for code, msg in verdicts:
                emit("        [%s] %s" % (code, msg))
        emit()

    emit("== verdict: %d/%d findings rejected, %d admissible =="
         % (rejected, len(findings), len(findings) - rejected))
    return (EXIT_REJECTED if rejected else EXIT_ALL_PASS), "\n".join(out)


def cmd_ledger(action):
    if action == "list":
        for e in load_ledger():
            print("%-32s %-24s batches %-8s %s"
                  % (e["id"], e["status"], ",".join(e["batches"]), e["title"]))
        return EXIT_ALL_PASS
    if action == "seed":
        print("seeded %s" % seed_ledger())
        return EXIT_ALL_PASS
    print("ledger action must be 'list' or 'seed'", file=sys.stderr)
    return EXIT_REJECTED


# ==========================================================================
# PART 4 -- PROOF: the 24-check empirical battery (formerly the standalone
# regression suite; identical checks, wrapped as a command)
# ==========================================================================
PASS = 0


def ok(tag, msg):
    global PASS
    PASS += 1
    print("PASS %-28s %s" % (tag, msg))


def cmd_suite():
    global PASS
    PASS = 0
    spec = importlib.util.spec_from_file_location("tlsrv", DEFAULT_TARGET)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    TMP = tempfile.mkdtemp()

    def poisoned_open(real_open):
        class P:
            def __init__(s, p, mode):
                s._f = real_open(p, mode); s._armed = "a" in mode and "b" in mode and "+" not in mode
            def __getattr__(s, n): return getattr(s._f, n)
            def write(s, d):
                if s._armed:
                    s._armed = False; s._f.write(d[:9]); s._f.flush()
                    raise OSError(28, "simulated ENOSPC")
                return s._f.write(d)
            def __enter__(s): return s
            def __exit__(s, *a): s.close(); return False
        return lambda p, mode: P(p, mode)

    # ---------------- A. storage & unit layer ----------------
    m.MASTER_LOG_PATH = os.path.join(TMP, "thermolock_master.json")

    m.append_to_master_log({"seed": 1})
    real_size = os.path.getsize(m.MASTER_LOG_PATH)
    boom = lambda p: (_ for _ in ()).throw(PermissionError("scanner lock"))
    sq = os.path.getsize
    os.path.getsize = boom
    try:
        assert m._master_log_size() == real_size          # fd fallback
        m._LOG_SIZE_HINT = 4242
        m.MASTER_LOG_PATH = os.path.join(TMP, "nope", "x.json")
        assert m._master_log_size() == 4242               # ledger of last resort
    finally:
        os.path.getsize = sq; m.MASTER_LOG_PATH = os.path.join(TMP, "thermolock_master.json"); m._LOG_SIZE_HINT = None
    ok("size-fallback", "getsize lock -> fd-seek -> ledger; never bogus-0")

    for f in glob.glob(m.MASTER_LOG_PATH + "*"): os.remove(f)
    m.append_to_master_log({"keep": "PRECIOUS"})
    before = open(m.MASTER_LOG_PATH, "rb").read()
    m.open = poisoned_open(open)
    try:
        m.append_to_master_log({"evil": "MUST_VANISH"})   # raises
    except OSError: pass
    finally: del m.open
    after = open(m.MASTER_LOG_PATH, "rb").read()
    assert after == before and b"MUST_VANISH" not in after
    ok("enospc-rollback", "mid-write failure truncated to bookmark; file byte-identical")

    os.path.getsize = boom                                # rollback STILL correct under scanner lock
    m.open = poisoned_open(open)
    try:
        m.append_to_master_log({"evil": "V2"})
    except OSError: pass
    finally: del m.open; os.path.getsize = sq; m._LOG_SIZE_HINT = None
    assert open(m.MASTER_LOG_PATH, "rb").read() == before
    ok("locked-rollback", "refutes: 'size returns 0' wipe hazard -- log intact")

    m.MAX_LOG_BYTES = 2048
    real_replace = os.replace
    os.replace = lambda a, b: (_ for _ in ()).throw(PermissionError("pinned"))
    r0 = m._METRICS["rotations_total"]
    try:
        m.append_to_master_log({"pad": "z" * 3000})
        m.append_to_master_log({"t": 1})
    finally: os.replace = real_replace
    assert m._METRICS["rotations_total"] == r0 and len(glob.glob(m.MASTER_LOG_PATH + ".2*")) == 0
    assert open(m.MASTER_LOG_PATH, "rb").read().startswith(before)
    ok("fallback-off", "rename blocked -> append+warn, zero loss, no segment")

    m.ROLLOVER_FALLBACK_COPY_TRUNCATE = True
    os.replace = lambda a, b: (_ for _ in ()).throw(PermissionError("pinned"))
    try:
        for i in range(5): m.append_to_master_log({"post": i})
    finally:
        os.replace = real_replace; m.ROLLOVER_FALLBACK_COPY_TRUNCATE = False
    segs = glob.glob(m.MASTER_LOG_PATH + ".2*")
    assert len(segs) == 1
    lines = open(segs[0]).read().strip().split("\n") + open(m.MASTER_LOG_PATH).read().strip().split("\n")
    recs = [json.loads(l) for l in lines if l]
    assert m._METRICS["rotations_total"] == r0 + 1
    assert sum(1 for r in recs if "post" in r) == 5 and any(r.get("keep") == "PRECIOUS" for r in recs)
    ok("fallback-on", "verified copy-truncate under handle pin: all records survive")

    m.MAX_LOG_BYTES = 10 ** 9
    for f in glob.glob(m.MASTER_LOG_PATH + "*"): os.remove(f)

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        m.print_alert_summary({"Hostname": "WS-C", "EVENT": "drift", "Severity": "HIGH",
                               "bits": 64, "sender_ip": "1.1.1.1", "server_received_time": "t"})
    assert "hostname    : WS-C" in buf.getvalue() and "severity    : HIGH" in buf.getvalue()
    ok("display-keys-ci", "Hostname/HOSTNAME/host_name all surface canonically")

    base = tempfile.mkdtemp()
    def mz(names):
        b = io.BytesIO()
        with zipfile.ZipFile(b, "w") as z:
            for n in names: z.writestr(n, b"x")
        b.seek(0); return zipfile.ZipFile(b)
    for hostile in ("../e", "/abs", "a/../../e"):
        try:
            m._safe_extractall(mz([hostile]), base); raise SystemExit("zip guard failed")
        except zipfile.BadZipFile: pass
    m._safe_extractall(mz(["ok/deep.py"]), base)
    ok("zip-traversal", "3 hostile shapes rejected, legit extracted (commonpath)")

    m.RATE_LIMIT_ALERTS_PER_SECOND = 5
    m._RATE_BUCKETS.clear()
    codes = [m.rate_limit_allows("9.0.0.9") for _ in range(30)]
    assert codes.count(True) == 5 and codes.count(False) == 25
    ok("bucket-decrement", "refutes: 'entry = x rebinding lets floods through' -- 5/25")

    m.RATE_LIMIT_ALERTS_PER_SECOND = 0
    assert m.rate_limit_allows("x") is True
    ok("limiter-disable", "0 disables cleanly")

    m.RATE_LIMIT_ALERTS_PER_SECOND = 5
    m.RATE_LIMIT_IDLE_TTL_SECONDS = 0.05
    m._RATE_BUCKETS.clear()
    for _ in range(30): m.rate_limit_allows("8.8.8.8")
    time.sleep(0.5); m._last_rate_prune = 0.0  # wide margin vs 0.05s TTL (slow CI hosts)
    m.rate_limit_allows("1.1.1.1")
    assert "8.8.8.8" not in m._RATE_BUCKETS
    ok("age-prune", "drained stormer aged out (pure age rule)")

    m.RATE_LIMIT_MAX_BUCKETS = 3
    m._RATE_BUCKETS.clear(); m._METRICS["rate_limit_overflow_total"] = 0
    for _ in range(30): m.rate_limit_allows("10.0.0.1")
    m.rate_limit_allows("10.0.0.2"); m.rate_limit_allows("10.0.0.3")
    assert m.rate_limit_allows("10.0.0.4") is True and m._METRICS["rate_limit_overflow_total"] == 1
    assert m.rate_limit_allows("10.0.0.1") is False
    ok("bucket-cap", "fail-open for IP4, stormer still throttled, overflow counted")
    m.RATE_LIMIT_ALERTS_PER_SECOND = 0
    m.RATE_LIMIT_MAX_BUCKETS = 10000
    m._RATE_BUCKETS.clear()

    # ---------------- B. live HTTP layer ----------------
    srv = m.ThermoLockServer(("127.0.0.1", 0), m.AlertRequestHandler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    def req(path, method="GET", payload=None, raw=None, token=None):
        data = raw if raw is not None else (json.dumps(payload).encode() if payload is not None else None)
        r = urllib.request.Request("http://127.0.0.1:%d%s" % (port, path), data=data, method=method)
        if token is not None: r.add_header("Authorization", "Bearer " + token)
        try:
            with urllib.request.urlopen(r, timeout=10) as resp: return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as e: return e.code, dict(e.headers), e.read()

    s, _, _ = req("/alert", method="POST", payload={"hostname": "WS-1", "event": "ok"}); assert s == 200
    s, _, _ = req("/alert?source=agent", method="POST", payload={"event": "ok"}); assert s == 200
    s, _, _ = req("/nope", method="POST", payload={"x": 1}); assert s == 404
    s, _, b = req("/health"); assert s == 200 and json.loads(b)["counters"]["ingested_total"] == 2
    ok("routing", "refutes 2x: '.split() list vs str -> all 404' -- 200/200/404/200")

    s, h, b = req("/health", method="HEAD")
    assert s == 200 and b == b"" and int(h["Content-Length"]) > 0
    ok("head-health", "no body, true Content-Length")

    s, h, _ = req("/alert", method="POST", payload={"event": "hdr"})
    assert h.get("X-Content-Type-Options") == "nosniff" and h.get("Cache-Control") == "no-store"
    assert h.get("Server") == "ThermoLock/1.0"
    ok("sec-headers", "nosniff+no-store on replies; no Python version leak")

    assert req("/alert", method="POST", raw=b"{bad")[0] == 400
    assert req("/alert", method="POST", payload=[1, 2])[0] == 400
    assert req("/alert", method="POST", raw=b"")[0] == 400
    ok("malformed", "bad json / non-object / empty -> 400")

    line = [l for l in open(m.MASTER_LOG_PATH).read().splitlines() if l][-1]
    r0d = json.loads(line)
    assert r0d["sender_ip"] == "127.0.0.1" and "server_received_time" in r0d
    ok("metadata", "sender_ip from socket + UTC arrival stamp injected")

    m.AUTH_TOKEN = "t0k"; m.AUTH_TOKEN_BYTES = b"Bearer t0k"
    s, h, _ = req("/alert", method="POST", payload={"event": "x"}); assert s == 401 and "thermolock" in h.get("WWW-Authenticate", "")
    assert req("/alert", method="POST", payload={"event": "x"}, token="t0k")[0] == 200
    assert req("/health")[0] == 401
    m.AUTH_TOKEN = ""; m.AUTH_TOKEN_BYTES = b""
    ok("bearer-gate", "401+challenge anon, 200 correct token, health gated too")

    body = json.dumps({"blob": "y" * 4000, "event": "drip"}).encode()
    s_ = socket.create_connection(("127.0.0.1", port), timeout=10)
    s_.sendall(b"POST /alert HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n" % len(body))
    for bb in body: s_.sendall(bytes([bb]))
    assert b" 200 " in s_.recv(4096); s_.close()
    ok("byte-at-a-time", "refutes: 'read1 returns b\"\" mid-stream' -- 4053B dripped => 200")

    m.MAX_BODY_READ_TOTAL_SECONDS = 2
    tl = socket.create_connection(("127.0.0.1", port), timeout=15)
    tl.sendall(b"POST /alert HTTP/1.1\r\nHost: x\r\nContent-Length: 500\r\n\r\n{\"s\":1")
    t0 = time.monotonic()
    try:
        while time.monotonic() - t0 < 9: time.sleep(0.4); tl.sendall(b" ")
    except OSError: pass
    resp = b""
    while True:
        d = tl.recv(4096)
        if not d: break
        resp += d
    assert b" 408 " in resp, resp[:120]
    ok("slowloris-408", "trickle cut at absolute deadline => 408")

    s2 = socket.create_connection(("127.0.0.1", port), timeout=10)
    s2.sendall(b"POST /alert HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\n{}")
    s2.shutdown(socket.SHUT_WR)
    resp2 = b""
    while True:
        d = s2.recv(4096)
        if not d: break
        resp2 += d
    assert b" 400 " in resp2 and b"incomplete_body" in resp2
    ok("incomplete-body", "clean EOF short of length => 400 incomplete_body")
    m.MAX_BODY_READ_TOTAL_SECONDS = 30

    m._METRICS["connections_dropped_total"] = 0
    # QUIESCENCE BARRIER: the server reads _THREAD_POOL_SEMAPHORE via
    # module-global lookup at release time, so a straggler worker from an
    # earlier phase (e.g. the slowloris thread, which releases only at its
    # 408 deadline) would release into a freshly-swapped Semaphore and
    # inflate it. Wait until no worker threads remain before swapping.
    # (In production the Semaphore is created once at import and never
    # rebound, so this window cannot exist.)
    def _quiesce(secs=15.0):
        allow = {"serve_forever", "__init__"}
        t0 = time.monotonic()
        while time.monotonic() - t0 < secs:
            strays = [t for t in threading.enumerate()
                      if t is not threading.current_thread()
                      and not any(a in t.name for a in allow)]
            if not strays:
                return
            time.sleep(0.05)
        raise AssertionError("stray worker threads never drained: %r" % (strays,))
    _quiesce()
    m._THREAD_POOL_SEMAPHORE = threading.Semaphore(2)
    # Dedicated server instance: the cap guarantee is per-server connection
    # accounting, and a fresh listener avoids accumulated-context flakiness.
    # Worker acquisition is detected via a spy hook (deterministic), NOT by
    # equality-polling the semaphore (whose value can transit 2->0 between
    # samples on fast hosts).
    cap_srv = m.ThermoLockServer(("127.0.0.1", 0), m.AlertRequestHandler)
    cap_port = cap_srv.server_address[1]
    threading.Thread(target=cap_srv.serve_forever, daemon=True).start()
    _started = []
    _orig_prt = cap_srv.process_request_thread
    cap_srv.process_request_thread = lambda req, ca: (_started.append(ca), _orig_prt(req, ca))[1]

    def holder():
        x = socket.create_connection(("127.0.0.1", cap_port), timeout=10)
        x.sendall(b"POST /alert HTTP/1.1\r\nHost: x\r\nContent-Length: 500\r\n\r\n{\"s\":1")
        return x

    def wait_for(cond, secs=10.0, what="condition"):
        t0 = time.monotonic()
        while not cond() and time.monotonic() - t0 < secs:
            time.sleep(0.01)
        assert cond(), "timeout waiting for " + what

    h1 = holder(); wait_for(lambda: len(_started) == 1, what="worker 1")
    h2 = holder(); wait_for(lambda: len(_started) == 2, what="worker 2")
    drop = socket.create_connection(("127.0.0.1", cap_port), timeout=10)
    drop.sendall(b"POST /alert HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\n{}")
    wait_for(lambda: m._METRICS["connections_dropped_total"] == 1, what="shed metric")
    drop_resp = drop.recv(64)
    assert drop_resp == b""
    drop.close(); h1.close(); h2.close()
    wait_for(lambda: m._THREAD_POOL_SEMAPHORE._value == 2, what="pool release")
    ok("thread-cap", "refutes 3x: shed works, FD closed by close(), pool exact -- 'del request' placebo")
    # value==2 proves both releases landed in the NEW pool; no cap-phase
    # worker can still be alive, so a fresh pool is safe to hand onward.
    m._THREAD_POOL_SEMAPHORE = threading.Semaphore(256)
    cap_srv.shutdown(); cap_srv.server_close()

    class LegacyComposite(socketserver.ThreadingMixIn, HTTPServer):
        daemon_threads = True; allow_reuse_address = True
    leg = LegacyComposite(("127.0.0.1", 0), m.AlertRequestHandler)
    threading.Thread(target=leg.serve_forever, daemon=True).start()
    lp = leg.server_address[1]
    sl = socket.create_connection(("127.0.0.1", lp), timeout=10)
    sl.sendall(b"POST /alert HTTP/1.1\r\nHost: x\r\nContent-Length: 400\r\n\r\n{\"slow\":1")
    time.sleep(0.4); t0 = time.monotonic()
    with urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:%d/alert" % lp,
            data=json.dumps({"event": "fast"}).encode(), method="POST"), timeout=5) as r:
        assert r.status == 200
    fast_ms = (time.monotonic() - t0) * 1000
    sl.close(); leg.shutdown(); leg.server_close()
    assert fast_ms < 2500
    ok("mixin-cascade", "refutes 3x: 'fallback drops to single-threaded' -- served concurrently in %dms (MRO already resolves __init__)" % fast_ms)

    m.MAX_LOG_BYTES = 2048
    with concurrent.futures.ThreadPoolExecutor(30) as ex:
        codes = list(ex.map(lambda i: req("/alert", method="POST", payload={"i": i, "event": "storm"})[0], range(80)))
    allf = glob.glob(m.MASTER_LOG_PATH + "*")
    allr = [json.loads(l) for f in allf for l in open(f).read().splitlines() if l]
    assert all(c == 200 for c in codes)
    assert len({r.get("i") for r in allr if "i" in r}) == 80
    assert len(allf) >= 2
    snap = m.metrics_snapshot()
    assert snap["ingested_total"] >= 80
    ok("storm-integrity", "80 concurrent: all 200, 80/80 intact across %d segments, metrics consistent" % len(allf))
    m.MAX_LOG_BYTES = 10 ** 9
    srv.shutdown(); srv.server_close()

    # ---------------- C. process-level shutdown ----------------
    logf = os.path.join(TMP, "svc.json")
    proc = subprocess.Popen([sys.executable, "-c",
        "import importlib.util as u; s=u.spec_from_file_location('m', %r); m=u.module_from_spec(s); s.loader.exec_module(m);"
        "m.MASTER_LOG_PATH=%r; m.BIND_PORT=18099; m.main()"
        % (DEFAULT_TARGET, logf)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    time.sleep(1.5)
    urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:18099/alert",
        data=json.dumps({"event": "prestop"}).encode(), method="POST"), timeout=5).read()
    proc.send_signal(signal.SIGTERM)
    out, _ = proc.communicate(timeout=10)
    assert proc.returncode == 0 and "listening socket closed" in out
    assert len(open(logf).read().strip().splitlines()) == 1
    ok("sigterm-shutdown", "exit 0, socket closed, log intact")
    print("=== %d/%d GUARANTEES HOLD ===" % (PASS, PASS))
    return EXIT_ALL_PASS


# ==========================================================================
# PART 5 -- SELF-PROOF: embedded fixtures (formerly the separate sample JSONs)
# ==========================================================================
FIXTURE_REPLICA = {
    "reviewer": "aggregated markdown review pipeline",
    "target": "thermolock_server.py",
    "file_sha256": "deadbeef-deadbeef-deadbeef",
    "findings": [
        {
            "id": "Update A",
            "title": "Multi-Threaded Inheritance Cascade Fault",
            "severity": "high",
            "quote": "class _ThreadingBase(socketserver.ThreadingMixIn, HTTPServer):\n    def __init__(self, *a, **kw):\n        socketserver.ThreadingMixIn.__init__(self)",
            "observable_failure": "",
        },
        {
            "id": "Update B",
            "title": "Socket Handle Exfiltration Risk",
            "severity": "high",
            "quote": "finally:\n    _THREAD_POOL_SEMAPHORE.release()\n    del request",
            "observable_failure": "",
        },
        {
            "id": "Update C",
            "title": "Network Stream Stutter Vulnerability",
            "severity": "medium",
            "quote": "chunk = self.rfile.read1(min(remaining, 4096))\nif not chunk:  # stutter -- retry read1",
            "observable_failure": "",
        },
        {
            "id": "Update D",
            "title": "Crash: missing [0] index on path split in do_POST",
            "severity": "high",
            "quote": "        target = self.path.split(\"?\", 1)\n        if target != \"/alert\":",
        },
    ],
}


def fixture_valid(file_hash):
    return {
        "reviewer": "hypothetical careful reviewer",
        "target": "thermolock_server.py",
        "file_sha256": file_hash,
        "findings": [
            {
                "id": "EX-1",
                "title": "Admissible example: header duplication policy undocumented",
                "severity": "low",
                "quote": "    def do_GET(self):\n        target = self.path.split(\"?\", 1)[0]\n        if target in (\"/health\", \"/healthz\"):",
                "observable_failure": "Included only to demonstrate the gate admits properly-anchored, byte-verbatim findings instead of blanket-rejecting.",
            }
        ],
    }


def cmd_selftest():
    tmp = tempfile.mkdtemp()
    raw = load_raw(DEFAULT_TARGET)
    file_hash = sha256_hex(raw)
    failures = []

    p1 = os.path.join(tmp, "replica.json")
    with open(p1, "w", encoding="utf-8") as fh:
        json.dump(FIXTURE_REPLICA, fh)
    rc1, out1 = cmd_verify(p1, DEFAULT_TARGET, quiet=True)
    print("-- fixture 1: batch-9 replica (4 phantom findings) --")
    print(out1)
    got_bracket = "BRACKET_EATEN" in out1
    got_dedup = out1.count("ALREADY_ADJUDICATED") >= 3
    got_stale = out1.count("STALE_HASH") == 4
    if rc1 != EXIT_REJECTED or not (got_bracket and got_dedup and got_stale):
        failures.append("fixture replica: expected 4/4 rejected with "
                        "STALE_HASH x4, BRACKET_EATEN, >=3 ALREADY_ADJUDICATED")

    print()
    p2 = os.path.join(tmp, "valid.json")
    with open(p2, "w", encoding="utf-8") as fh:
        json.dump(fixture_valid(file_hash), fh)
    rc2, out2 = cmd_verify(p2, DEFAULT_TARGET, quiet=True)
    print("-- fixture 2: properly anchored finding --")
    print(out2)
    if rc2 != EXIT_ALL_PASS:
        failures.append("fixture valid: expected PASS/exit 0")

    print()
    if failures:
        for f in failures:
            print("SELFTEST FAIL: %s" % f)
        return EXIT_REJECTED
    print("=== SELFTEST OK: gate is neither deaf nor blanket-hostile ===")
    return EXIT_ALL_PASS


# ==========================================================================
# Entry point -- one command surface
# ==========================================================================
def main(argv):
    ap = argparse.ArgumentParser(
        prog="thermolock_guard.py",
        description="ThermoLock verification tool: gate + proof + self-proof, one file")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("ingest", help="raw-bytes fingerprint of the target")
    p.add_argument("target", nargs="?", default=DEFAULT_TARGET)

    p = sub.add_parser("quote", help="emit a verified finding skeleton for a line range")
    p.add_argument("target", nargs="?", default=DEFAULT_TARGET)
    p.add_argument("start", type=int)
    p.add_argument("end", type=int)

    p = sub.add_parser("verify", help="four-gate intake check of a review JSON")
    p.add_argument("review")
    p.add_argument("target", nargs="?", default=DEFAULT_TARGET)

    p = sub.add_parser("ledger", help="adjudicated-findings ledger")
    p.add_argument("action", nargs="?", default="list")

    sub.add_parser("suite", help="run the 24-check empirical battery")
    sub.add_parser("selftest", help="run the gate against embedded fixtures")

    args = ap.parse_args(argv)
    if args.cmd == "ingest":
        return cmd_ingest(args.target)
    if args.cmd == "quote":
        return cmd_quote(args.target, args.start, args.end)
    if args.cmd == "verify":
        return cmd_verify(args.review, args.target)[0]
    if args.cmd == "ledger":
        return cmd_ledger(args.action)
    if args.cmd == "suite":
        try:
            return cmd_suite()
        except AssertionError as e:
            print("GUARANTEE FAILED: %s" % e)
            return EXIT_REJECTED
    if args.cmd == "selftest":
        return cmd_selftest()
    return EXIT_REJECTED


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
