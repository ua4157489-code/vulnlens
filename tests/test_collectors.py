import unittest
from pathlib import Path

from vulnlens.collectors import NmapCollector, OpenVASCollector, ParseError, detect_collector
from vulnlens.core.models import Severity

DATA = Path(__file__).parent / "data"


class NmapTests(unittest.TestCase):
    def setUp(self):
        self.result = NmapCollector().parse(DATA / "sample_nmap.xml")

    def test_only_up_hosts_and_open_ports(self):
        self.assertEqual([a.address for a in self.result.assets], ["192.168.56.101"])
        ports = {f.port for f in self.result.findings if f.severity == Severity.INFO}
        self.assertEqual(ports, {22, 3000})  # closed 8080 excluded

    def test_vulnerable_nse_script_becomes_high(self):
        high = [f for f in self.result.findings if f.severity == Severity.HIGH]
        self.assertEqual(len(high), 1)
        self.assertEqual(high[0].port, 3000)

    def test_hostname_captured(self):
        self.assertEqual(self.result.assets[0].hostnames, ["juice-shop.lab"])


class OpenVASTests(unittest.TestCase):
    def setUp(self):
        self.result = OpenVASCollector().parse(DATA / "sample_openvas.xml")

    def test_counts_and_assets(self):
        self.assertEqual(len(self.result.findings), 3)
        self.assertEqual(len(self.result.assets), 2)  # .101 and .103; .101 appears twice

    def test_severity_mapping(self):
        by_title = {f.title: f for f in self.result.findings}
        self.assertEqual(by_title["Remote Code Execution in Example Service"].severity, Severity.CRITICAL)
        self.assertEqual(by_title["Weak SSL/TLS Protocol Versions Supported"].severity, Severity.MEDIUM)
        self.assertEqual(by_title["TCP Timestamps"].severity, Severity.INFO)

    def test_cve_and_port_parsing(self):
        weak_tls = next(f for f in self.result.findings if f.title.startswith("Weak SSL"))
        self.assertEqual(weak_tls.cves, ["CVE-2011-3389"])
        self.assertEqual((weak_tls.port, weak_tls.protocol), (443, "tcp"))
        general = next(f for f in self.result.findings if f.title == "TCP Timestamps")
        self.assertIsNone(general.port)


class DetectionTests(unittest.TestCase):
    def test_autodetect(self):
        self.assertEqual(detect_collector(DATA / "sample_nmap.xml").name, "nmap")
        self.assertEqual(detect_collector(DATA / "sample_openvas.xml").name, "openvas")

    def test_rejects_xxe(self):
        with self.assertRaises(ParseError):
            detect_collector(DATA / "malicious_entity.xml")

    def test_missing_file(self):
        with self.assertRaises(ParseError):
            detect_collector(DATA / "does_not_exist.xml")


if __name__ == "__main__":
    unittest.main()
