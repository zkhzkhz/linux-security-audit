# False-positive patterns reference

This is the list of patterns `triage.py` uses (or would benefit from being aware of)
when scoring gitleaks findings. Update both this doc and `triage.py`/`allowlist.toml`
together if you add an entry.

## High-confidence dummies (always FP)

| Pattern | Source | Notes |
|---|---|---|
| `AKIAIOSFODNN7EXAMPLE` | AWS docs | The official AWS example access key. |
| `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` | AWS docs | Matching example secret. |
| `<your-token>`, `<your-secret>`, `<api-key-here>` | Generic | Placeholder syntax in docs/READMEs. |
| `xxxx...`, `0000...`, repeated single char | Generic | Padding fillers. |
| `changeme`, `placeholder`, `redacted`, `dummy*` | Generic | Common pre-deploy reminders. |
| `example.com`, `example.org`, `example.net` | RFC 2606 | Reserved demo domains — usually not real creds. |

## Path penalties

Half (or less) the rule weight when matched in:
- `tests/`, `test/`, `spec/`, `specs/`
- `fixtures/`, `examples/`, `docs/`, `doc/`
- `*.md`, `*.rst`, `*.txt`, `CHANGELOG*`
- `*.sample`, `*.example`, `*.tmpl`, `*.template`

## Path boosts

Multiply the rule weight when:
- `.env`, `.env.production`, `.env.live`
- `*credentials*` files (any case)
- `id_rsa`, `id_ed25519`, `id_ecdsa`, `id_dsa`
- `~/.aws/credentials`, `~/.kube/config`, `~/.docker/config.json`
- `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.jks`
- `wp-config.php`, `*.kubeconfig`

## Context terms (in the matched line / nearby content)

Boost: `prod`, `production`, `live`, `staging`, `customer`, `tenant`, `admin`
Demote: `test`, `fake`, `mock`, `sample`, `demo`, `fixture`, `placeholder`, `dummy`

## Entropy floors

Default: 3.0. Lower for hashy rules (`shadow-hash`, `htpasswd-line` set to 0). Higher
for rules that should already capture random-looking values. Below floor -> -2 score.

## Notes on rules that produce a lot of noise

- `password` and `mysql-cnf-password`: anything with `password = X` triggers; reduce
  via `allowlist.toml` for known config-file false positives.
- `gitcode-token-rule` is intentionally broad (matches `key:`, `secret:`, etc.) —
  expect noise from configuration files; rely on entropy + path penalties.
- `jwt` will fire on JS source bundles that embed example JWTs; demote `*.min.js`.

## When to allowlist vs. lower entropy

Prefer **path allowlist** for known-safe directories (`tests/fixtures/`, vendored
SDK samples). Use **regex allowlist** only for genuinely public placeholder strings.
Lowering entropy site-wide trades recall for less noise — usually wrong.
