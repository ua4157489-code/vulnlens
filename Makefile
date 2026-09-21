.PHONY: install test lint demo clean

install:
	pip install -e ".[dev]"

test:
	pytest

lint:
	ruff check .

demo:
	vulnlens parse tests/data/sample_openvas.xml

clean:
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	rm -rf .pytest_cache .ruff_cache
