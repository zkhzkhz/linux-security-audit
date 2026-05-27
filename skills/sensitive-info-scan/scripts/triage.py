#!/usr/bin/env python3
"""False-positive triage for gitleaks JSON output.

Reads gitleaks `raw.json` and writes a triaged `result.json` with:
  - severity: critical|high|medium|low|info
  - score: numeric (rule weight + entropy + context boosts/penalties)
  - reasons: list of triage reasons
  - is_likely_fp: bool
  - dedup key
And a top-level `counts` dictionary plus a flat `findings` list ready for the
orchestrator's report.py.

Usage:
    triage.py raw.json [--out result.json] [--module sensitive-info-scan]
"""
from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections import Counter
from pathlib import Path

# --- heuristics --------------------------------------------------------------

PLACEHOLDER_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"akiaiosfodnn7example",
        r"wjalrxutnfemi/k7mdeng/bpxrficyexamplekey",
        r"^x{6,}$",
        r"^0+$",
        r"changeme",
        r"placeholder",
        r"redacted",
        r"<your[-_ ]?(token|secret|key|password)[^>]*>",
        r"^example(\.|_|-)",
        r"\bexample\.com\b",
        r"\byour[-_ ]?(api|access|secret)[-_ ]?(key|token|id)\b",
        r"\bdummy[-_ ]?(secret|token|key)\b",
        r"\b(foo|bar|baz|qux)+\b",
        r"^(.)\1{7,}$",  # same char repeated
        r"\bUSER:PASSWORD\b",
        r"\buser:password\b",
        r"\busername:password\b",
        r"\bmysecretpassword\b",
        r"\bmypassword\b",
        r"\bsecretpassword\b",
        r"://user:pass(word)?@",
        r"://root:root@",
        r"://admin:admin@",
    ]
]

# Rule -> base weight (severity contribution before adjustments).
RULE_WEIGHTS = {
    # private keys are the strongest signal
    "pem-private-key": 8,
    "private_key": 8,
    "putty-private-key": 8,
    "pkcs12-keystore": 6,
    # cloud provider keys
    "aws-access-key-id": 7,
    "aws-secret-access-key": 7,
    "aws_access_key": 6,
    "gcp-service-account-key": 8,
    "azure-storage-key": 7,
    "huawei-cloud-ak": 6,
    "aliyun-ak": 6,
    "tencent-secret-id": 6,
    # vcs / ci tokens
    "github-token": 7,
    "gitlab-token": 7,
    "slack_token": 5,
    "git-url-credentials": 6,
    "git-config-extra-header": 6,
    # generic
    "jwt": 5,
    "kube-bearer-token": 6,
    "kubeconfig-token": 6,
    "shadow-hash": 6,
    "htpasswd-line": 6,
    "mysql-cnf-password": 5,
    "database_url": 6,
    "api_key": 4,
    "token": 3,
    "password": 3,
    "ssh_key_assignment": 5,
    "gitcode-token-rule": 2,
}

# Paths where findings are almost always noise (library source code, caches).
# Findings in these paths are DROPPED unless the rule is in HIGH_CONFIDENCE_RULES.
NOISE_PATHS = [
    re.compile(r"(?:^|/)\.npm/_cacache/"),
    re.compile(r"(?:^|/)\.bun/install/cache/"),
    re.compile(r"(?:^|/)\.yarn/cache/"),
    re.compile(r"(?:^|/)\.pnpm-store/"),
    re.compile(r"(?:^|/)go/pkg/mod/"),
    re.compile(r"(?:^|/)\.cargo/registry/"),
    re.compile(r"(?:^|/)node_modules/"),
    re.compile(r"(?:^|/)site-packages/"),
    # System-bundled libraries (not user code)
    re.compile(r"^/tmp/jiti/"),
    re.compile(r"^/usr/local/hostguard/"),
    re.compile(r"^/usr/local/lib/python[0-9.]+/dist-packages/"),
    re.compile(r"^/usr/lib/python[0-9.]+/"),
    re.compile(r"(?:^|/)\.claude/plugins/"),
    # Tool databases and session logs
    re.compile(r"^/opt/nikto/"),
    re.compile(r"(?:^|/)\.local/share/opencode/storage/"),
    re.compile(r"^/etc/fwupd/"),
    re.compile(r"^/etc/sos/"),
]

# Paths that are ALWAYS dropped regardless of rule (even HIGH_CONFIDENCE_RULES).
# These contain copies/references to secrets found elsewhere, not original secrets.
ALWAYS_DROP_PATHS = [
    re.compile(r"linux-security-audit/reports/"),
    re.compile(r"linux-security-audit/skills/.*/config/"),
    re.compile(r"(?:^|/)\.claude/file-history/"),
    re.compile(r"(?:^|/)\.claude/projects/"),
    re.compile(r"^/tmp/node-compile-cache/"),
    re.compile(r"cloud_init-.*/cloudinit/config/"),
]

HIGH_CONFIDENCE_RULES = {
    "pem-private-key", "private_key", "putty-private-key", "pkcs12-keystore",
    "aws-access-key-id", "aws-secret-access-key", "gcp-service-account-key",
    "azure-storage-key", "github-token", "gitlab-token", "shadow-hash",
    "huawei-cloud-ak", "aliyun-ak", "tencent-secret-id",
}


def is_noise_path(file_path: str, rule: str) -> bool:
    """Return True if this finding should be silently dropped."""
    # Always-drop paths: even high-confidence rules are noise here (copies/references)
    if any(p.search(file_path) for p in ALWAYS_DROP_PATHS):
        return True
    if rule in HIGH_CONFIDENCE_RULES:
        return False
    return any(p.search(file_path) for p in NOISE_PATHS)

# File-type / path adjustments.
PATH_BOOSTS = [
    (re.compile(r"\.env(\.|$)"), 2.0),
    (re.compile(r"(?:^|/)credentials(?:\.|$)"), 2.0),
    (re.compile(r"(?:^|/)id_(rsa|ed25519|ecdsa|dsa)(?:\.|$)"), 2.0),
    (re.compile(r"(?:^|/)\.aws/credentials"), 2.0),
    (re.compile(r"(?:^|/)kubeconfig"), 1.5),
    (re.compile(r"(?:^|/)docker/config\.json$"), 1.5),
    (re.compile(r"\.kube/config$"), 1.5),
    (re.compile(r"(?:^|/)secrets?\."), 1.5),
    (re.compile(r"(?:^|/)wp-config\.php$"), 1.5),
    (re.compile(r"\.pem$|\.key$|\.p12$|\.pfx$|\.jks$"), 1.5),
]

PATH_PENALTIES = [
    (re.compile(r"(?:^|/)tests?/"), 0.5),
    (re.compile(r"(?:^|/)spec(?:s)?/"), 0.5),
    (re.compile(r"(?:^|/)fixtures?/"), 0.4),
    (re.compile(r"(?:^|/)examples?/"), 0.5),
    (re.compile(r"(?:^|/)docs?/"), 0.5),
    (re.compile(r"\.md$|\.rst$|\.txt$"), 0.6),
    (re.compile(r"(?:^|/)CHANGELOG"), 0.4),
    (re.compile(r"\.sample$|\.example$|\.tmpl$|\.template$"), 0.3),
    # Library/cache code — variable names match token rules but are not secrets
    (re.compile(r"(?:^|/)\.npm/_cacache/"), 0.2),
    (re.compile(r"(?:^|/)\.bun/install/cache/"), 0.2),
    (re.compile(r"(?:^|/)go/pkg/mod/"), 0.3),
    (re.compile(r"(?:^|/)\.cargo/registry/"), 0.3),
    (re.compile(r"(?:^|/)\.yarn/cache/"), 0.2),
]

CONTEXT_BOOST_TERMS = re.compile(
    r"\b(prod(?:uction)?|live|production|staging|customer|tenant|admin)\b",
    re.IGNORECASE,
)
CONTEXT_DEMOTE_TERMS = re.compile(
    r"\b(test|fake|mock|sample|demo|fixture|placeholder|dummy)\b",
    re.IGNORECASE,
)

# Entropy floors per rule (below = penalty).
ENTROPY_FLOOR_DEFAULT = 3.0
ENTROPY_FLOOR_RULE = {
    "password": 2.5,
    "mysql-cnf-password": 2.5,
    "git-url-credentials": 2.0,
    "shadow-hash": 0.0,           # hashes pre-pass entropy
    "htpasswd-line": 0.0,
    "pem-private-key": 0.0,
    "private_key": 0.0,
    "putty-private-key": 0.0,
}


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def is_placeholder(secret: str) -> bool:
    if not secret:
        return True
    for p in PLACEHOLDER_PATTERNS:
        if p.search(secret):
            return True
    return False


def severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 6.5:
        return "high"
    if score >= 4.0:
        return "medium"
    if score >= 2.0:
        return "low"
    return "info"


def triage_one(f: dict) -> dict:
    rule = (f.get("RuleID") or f.get("rule") or f.get("Rule") or "").strip()
    secret = (f.get("Secret") or f.get("Match") or "").strip()
    file_path = (f.get("File") or f.get("file") or "").strip()
    line_no = f.get("StartLine") or f.get("Line") or 0
    line = (f.get("Line") if isinstance(f.get("Line"), str) else "") or f.get("Match", "") or ""
    reasons: list[str] = []

    base = RULE_WEIGHTS.get(rule, 3)
    score = float(base)

    # Placeholder / known dummy
    if is_placeholder(secret):
        score -= 5.0
        reasons.append("placeholder/example value")

    # Secret starts with the rule keyword itself — matching code that handles
    # credentials, not actual hardcoded credentials
    secret_lower = secret.lower()[:10]
    if rule in ("token", "password", "mysql-cnf-password") and any(
        secret_lower.startswith(kw)
        for kw in ("token", "password", "passwd")
    ):
        score -= 3.0
        reasons.append("secret is the keyword itself (code handling creds)")

    # gitcode-token-rule: code variable access patterns are not secrets
    if rule == "gitcode-token-rule" and re.match(
        r"^(self\.|this\.|cls\.|ctx\.|ctl\.|config|settings?|params?|opts?\.|"
        r"request\.|response\.|result\.|data\.|map\.|get|set|put|list\.|"
        r"org\.|com\.|net\.|java\.|import|return|def |class |func |var |let |const |"
        r"cur_|item\.|value\.|year\.|person|mainta|commit|contri|subite|descri|"
        r"option|Cookie|insta\.|Author|gramma|lexer\.|pytree|manage|"
        r"waitin|logInf|dispal|parame|resolv|genera|inline|normal|"
        r"RSAUti|tokenC|JWT\.|authin)",
        secret
    ):
        score -= 3.0
        reasons.append("code variable pattern, not a secret")

    # --- Match-content-based FP detection ---
    match_val = (f.get("Match") or "").strip()

    # mysql-cnf-password: if Match is clearly a code statement, not a config line
    if rule == "mysql-cnf-password" and match_val and re.search(
        r"(for\s+\w+\s+in\s|"
        r"org\.apache\.|java\.|javax\.|"
        r"\.\w+\(.*\)|"  # method call like .encodeBase64String(...)
        r"\[.*\bfor\b.*\bin\b|"  # list comprehension
        r"import\s|"
        r"Base64\.|Hex\.|"
        r"password_entry|"
        r"=\s*\w+\.\w+\.\w+)",  # chained method calls
        match_val
    ):
        score -= 4.0
        reasons.append("code statement, not config password")

    # gitcode-token-rule: Match contains code operations, not secrets
    if rule == "gitcode-token-rule" and match_val and re.search(
        r"(\.keySet|\.split\b|\.get\b|\.put\b|\.set\b|"
        r"=\"[a-z]+\.|"  # key="card.title pattern
        r":\s*'[a-z_]+_id'|"  # key: 'gitcode_id' pattern
        r"CommonUtil\.|"
        r"encrypt\w+|decrypt\w+|"
        r"cookie\.|Cookie\.|"
        r"resourceConvert|"
        r"\bMap\b.*\bkey\b)",
        match_val
    ):
        score -= 3.0
        reasons.append("code operation in match, not a secret")

    # database_url: if the URL contains obvious placeholder credentials
    if rule == "database_url" and match_val and re.search(
        r"://(USER|user|username|admin|root|postgres|mysql)"
        r":(PASSWORD|password|pass|secret|mysecretpassword|example|test)@",
        match_val
    ):
        score -= 5.0
        reasons.append("placeholder credentials in database URL")

    # Entropy
    ent = shannon_entropy(secret)
    floor = ENTROPY_FLOOR_RULE.get(rule, ENTROPY_FLOOR_DEFAULT)
    if floor > 0:
        if ent < floor - 0.5:
            score -= 2.0
            reasons.append(f"low entropy {ent:.2f} < {floor}")
        elif ent >= floor + 1.0:
            score += 1.0
            reasons.append(f"high entropy {ent:.2f}")

    # Path boosts / penalties
    for pat, mult in PATH_BOOSTS:
        if pat.search(file_path):
            score += (mult - 1.0) * base
            reasons.append(f"sensitive path: {pat.pattern}")
            break
    for pat, mult in PATH_PENALTIES:
        if pat.search(file_path):
            score *= mult
            reasons.append(f"low-risk path: {pat.pattern}")
            break

    # Context terms in the matched line
    ctx = (line or "")[:400]
    if CONTEXT_BOOST_TERMS.search(ctx):
        score += 1.0
        reasons.append("prod/live keyword nearby")
    if CONTEXT_DEMOTE_TERMS.search(ctx):
        score -= 1.5
        reasons.append("test/fake keyword nearby")

    # Tiny secrets are usually noise
    if len(secret) < 8 and rule not in ("shadow-hash", "htpasswd-line"):
        score -= 1.5
        reasons.append("very short secret")

    severity = severity_from_score(score)
    is_fp = score < 2.0

    secret_prefix = (secret[:6] + "…") if len(secret) > 6 else secret
    dedup_key = f"{rule}|{secret_prefix}|{file_path}"

    return {
        "rule": rule,
        "severity": severity,
        "score": round(score, 2),
        "is_likely_fp": is_fp,
        "reasons": reasons,
        "where": f"{file_path}:{line_no}",
        "file": file_path,
        "line": line_no,
        "secret_prefix": secret_prefix,
        "entropy": round(ent, 2),
        "dedup_key": dedup_key,
        "raw": {
            "RuleID": rule,
            "Description": f.get("Description") or f.get("description") or "",
            "StartLine": line_no,
            "EndLine": f.get("EndLine"),
            "Match": (f.get("Match") or "")[:200],
        },
    }


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("raw")
    p.add_argument("--out")
    p.add_argument("--module", default="sensitive-info-scan")
    args = p.parse_args(argv)

    raw_path = Path(args.raw)
    if not raw_path.exists():
        print(f"missing: {raw_path}", file=sys.stderr)
        return 2
    try:
        data = json.loads(raw_path.read_text(encoding="utf-8", errors="replace") or "[]")
    except Exception as e:
        print(f"parse {raw_path}: {e}", file=sys.stderr)
        return 2
    if not isinstance(data, list):
        data = []

    triaged = [triage_one(f) for f in data if not is_noise_path(
        (f.get("File") or f.get("file") or ""),
        (f.get("RuleID") or f.get("rule") or f.get("Rule") or "").strip()
    )]

    # de-dup
    seen: set[str] = set()
    unique: list[dict] = []
    for t in triaged:
        if t["dedup_key"] in seen:
            continue
        seen.add(t["dedup_key"])
        unique.append(t)

    # sort: severity rank desc, score desc
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    unique.sort(key=lambda x: (sev_rank.get(x["severity"], 0), x["score"]), reverse=True)

    counts = Counter(t["severity"] for t in unique if not t["is_likely_fp"])
    fp = sum(1 for t in unique if t["is_likely_fp"])

    summary = (
        f"{len(unique)} unique findings ({sum(counts.values())} actionable, {fp} likely-FP). "
        f"critical={counts.get('critical',0)} high={counts.get('high',0)} "
        f"medium={counts.get('medium',0)} low={counts.get('low',0)} info={counts.get('info',0)}"
    )

    result = {
        "module": args.module,
        "status": "warn" if counts.get("critical", 0) + counts.get("high", 0) > 0 else "ok",
        "summary": summary,
        "counts": dict(counts) | {"likely_fp": fp, "total_unique": len(unique)},
        "findings": [
            {
                "severity": t["severity"],
                "title": t["rule"],
                "where": t["where"],
                "note": (
                    f"score={t['score']} entropy={t['entropy']} "
                    + (";".join(t["reasons"][:3]) if t["reasons"] else "")
                    + (" [likely FP]" if t["is_likely_fp"] else "")
                ).strip(),
                "secret_prefix": t["secret_prefix"],
                "is_likely_fp": t["is_likely_fp"],
            }
            for t in unique
        ],
        "notes": [
            "Severity is heuristic; review high/critical first.",
            "`is_likely_fp` items are kept for audit but should be skimmed, not actioned blindly.",
        ],
    }

    out_path = Path(args.out) if args.out else raw_path.parent / "result.json"
    out_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"triage: {out_path} ({summary})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
