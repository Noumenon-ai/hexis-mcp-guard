# Contributing

## How To Add Checks

1. Add the new check implementation to the scanner code and give it a stable rule ID, severity, and category.
2. Add or update tests that cover both a positive detection case and a safe case that should not trigger.
3. Update the README rules table if the new check introduces a new documented rule.
4. Run the local test suite before opening a change.

```bash
pytest -v
```

Keep new checks deterministic, avoid placeholder logic, and make sure every behavior change is covered by tests.
