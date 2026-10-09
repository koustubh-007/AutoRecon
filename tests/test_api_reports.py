import csv
import json
import os
import tempfile
import unittest

from api_recon.runner import _target_output_dir, _write_csv, _write_report, _write_text


class ReportGenerationTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.output = self.temp_dir.name

    def test_target_output_dir_uses_working_base_and_reuses_existing_folder(self):
        base = os.path.join(self.output, "work")
        existing_target = os.path.join(base, "api.example.com")
        os.makedirs(existing_target)
        marker = os.path.join(existing_target, "all_urls.txt")
        with open(marker, "w", encoding="utf-8") as handle:
            handle.write("https://api.example.com/users\\n")

        output = _target_output_dir(base, "api.example.com")

        self.assertEqual(output, os.path.join(existing_target, "api_recon"))
        self.assertTrue(os.path.isfile(marker))

    def test_text_report(self):
        path = os.path.join(self.output, "api_endpoints.txt")
        _write_text(path, ["GET api.example.com/users", "POST api.example.com/login"])

        with open(path, encoding="utf-8") as handle:
            self.assertEqual(len(handle.readlines()), 2)

    def test_csv_report(self):
        path = os.path.join(self.output, "api_endpoints.csv")
        endpoints = [{
            "method": "GET",
            "host": "api.example.com",
            "path": "/users",
            "url": "https://api.example.com/users",
            "summary": "List users",
            "operation_id": "listUsers",
            "source_type": "openapi",
            "source_url": "local-test",
            "deprecated": False,
            "evidence": "Mock test",
        }]

        _write_csv(path, endpoints)

        with open(path, newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["method"], "GET")
        self.assertEqual(rows[0]["path"], "/users")

    def test_json_report_round_trip(self):
        path = os.path.join(self.output, "api_endpoints.json")
        endpoints = [{"method": "GET", "path": "/users"}]

        with open(path, "w", encoding="utf-8") as handle:
            json.dump(endpoints, handle)

        with open(path, encoding="utf-8") as handle:
            loaded = json.load(handle)

        self.assertEqual(loaded, endpoints)

    def test_markdown_report(self):
        path = os.path.join(self.output, "report.md")
        endpoints = [{
            "method": "GET",
            "host": "api.example.com",
            "path": "/users",
            "source_type": "openapi",
        }]

        _write_report(path, ["api.example.com"], [], endpoints, [])

        with open(path, encoding="utf-8") as handle:
            report = handle.read()

        self.assertIn("# AutoRecon API Recon Report", report)
        self.assertIn("api.example.com", report)
        self.assertIn("Deduplicated endpoint candidates: 1", report)


if __name__ == "__main__":
    unittest.main()
