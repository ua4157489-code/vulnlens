# Contributing

1. Fork the repo and create a branch: `git checkout -b feature/my-change`
2. Install dev dependencies: `pip install -e ".[dev]"`
3. Make your change and add tests under `tests/`
4. Run `ruff check .` and `pytest`
5. Open a pull request describing *what* and *why*

## Adding a new scanner parser

1. Create `vulnlens/collectors/<tool>.py` with a class extending `Collector`
2. Implement `matches(root_tag)` and `parse(path)` returning a `ScanResult`
3. Register it in `_registry()` in `vulnlens/collectors/base.py`
4. Add a small sample file to `tests/data/` and tests in `tests/test_collectors.py`

Never commit real scan results from systems you don't own. Use sanitized or lab data only.
