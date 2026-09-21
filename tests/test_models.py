import unittest

from vulnlens.core.models import Finding, ScanResult, Severity


class SeverityTests(unittest.TestCase):
    def test_cvss_boundaries(self):
        self.assertEqual(Severity.from_cvss(None), Severity.INFO)
        self.assertEqual(Severity.from_cvss(0.0), Severity.INFO)
        self.assertEqual(Severity.from_cvss(3.9), Severity.LOW)
        self.assertEqual(Severity.from_cvss(4.0), Severity.MEDIUM)
        self.assertEqual(Severity.from_cvss(7.0), Severity.HIGH)
        self.assertEqual(Severity.from_cvss(9.0), Severity.CRITICAL)

    def test_from_name_aliases(self):
        self.assertEqual(Severity.from_name("Log"), Severity.INFO)
        self.assertEqual(Severity.from_name("HIGH"), Severity.HIGH)
        self.assertEqual(Severity.from_name("nonsense"), Severity.INFO)


class FindingTests(unittest.TestCase):
    def _finding(self, **kw):
        base = dict(title="t", severity=Severity.LOW, source="nmap", host="10.0.0.1", port=80)
        base.update(kw)
        return Finding(**base)

    def test_id_is_stable_and_distinct(self):
        self.assertEqual(self._finding().id, self._finding().id)
        self.assertNotEqual(self._finding().id, self._finding(port=443).id)

    def test_scan_result_filtering_and_counts(self):
        result = ScanResult(
            source="x",
            findings=[self._finding(severity=Severity.INFO), self._finding(severity=Severity.HIGH)],
        )
        filtered = result.filter_min_severity(Severity.MEDIUM)
        self.assertEqual(len(filtered.findings), 1)
        self.assertEqual(result.counts_by_severity()["High"], 1)


if __name__ == "__main__":
    unittest.main()
