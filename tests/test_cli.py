import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from vulnlens.cli import main

DATA = Path(__file__).parent / "data"


class CliTests(unittest.TestCase):
    def test_summary_output(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = main(["parse", str(DATA / "sample_openvas.xml")])
        self.assertEqual(code, 0)
        self.assertIn("Critical", out.getvalue())

    def test_json_export_with_min_severity(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "out.json"
            with contextlib.redirect_stdout(io.StringIO()):
                code = main(["parse", str(DATA / "sample_openvas.xml"), "-m", "high", "-o", str(dest)])
            self.assertEqual(code, 0)
            data = json.loads(dest.read_text())
            self.assertEqual(data["summary"]["findings"], 1)
            self.assertEqual(data["findings"][0]["severity"], "Critical")

    def test_bad_file_returns_error_code(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["parse", str(DATA / "malicious_entity.xml")]), 2)


if __name__ == "__main__":
    unittest.main()
