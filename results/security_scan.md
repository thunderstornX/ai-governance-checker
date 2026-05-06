# DevSecOps gate report

Run on 2026-05-06 against the release tree (commit at HEAD of `main`).

## Bandit (medium and above severity)

```
$ bandit -r checker cli config.py eval -ll
Total issues (by severity):
    Undefined: 0
    Low:       0
    Medium:    0
    High:      0
```

No findings, no suppressions.

## pip-audit (transitive vulnerability scan)

```
$ pip-audit --skip-editable --strict
No known vulnerabilities found
```

## Semgrep (`p/python`, `p/security-audit`)

```
$ semgrep --config p/python --config p/security-audit --error --quiet \
    checker cli config.py eval
exit=0
```

## Summary

| Gate       | Findings | Suppressions |
|-----------:|:--------:|:------------:|
| Bandit     | 0        | 0            |
| pip-audit  | 0        | 0            |
| Semgrep    | 0        | 0            |

All gates blocking on `--error`; `exit=0` across the board.
