import unittest

from api_recon.parser import parse_spec, extract_url_candidates
from api_recon.scope import host_in_scope, normalize_host, url_in_scope
from api_recon.scope_filter import filter_subdomains, is_out_of_scope


class ScopeTests(unittest.TestCase):
    def test_normalize_host(self):
        self.assertEqual(normalize_host(" HTTPS://API.Example.com/path "), "api.example.com")
        self.assertIsNone(normalize_host("not a host/path"))
        self.assertIsNone(normalize_host(""))

    def test_scope_matches_exact_and_subdomains(self):
        self.assertTrue(host_in_scope("api.example.com", ["example.com"]))
        self.assertTrue(host_in_scope("example.com", ["example.com"]))
        self.assertFalse(host_in_scope("example.org", ["example.com"]))
        self.assertFalse(url_in_scope("https://outside.test/api/v1", ["example.com"]))

    def test_out_of_scope_exact_and_subdomain_boundary(self):
        excluded = {"staging.example.com"}
        self.assertTrue(is_out_of_scope("staging.example.com", excluded))
        self.assertTrue(is_out_of_scope("api.staging.example.com", excluded))
        self.assertFalse(is_out_of_scope("notstaging.example.com", excluded))
        self.assertFalse(is_out_of_scope("example.com", excluded))

    def test_filter_subdomains(self):
        excluded = {"staging.example.com", "old.example.org"}
        result = filter_subdomains([
            "www.example.com",
            "staging.example.com",
            "api.staging.example.com",
            "old.example.org",
            "notstaging.example.com",
            "www.example.com",
        ], excluded)
        self.assertEqual(result, ["notstaging.example.com", "www.example.com"])


class ParserTests(unittest.TestCase):
    def test_openapi_endpoint_metadata(self):
        document = {
            "openapi": "3.0.0",
            "servers": [{"url": "https://api.example.com/v1"}],
            "paths": {
                "/users/{userId}": {
                    "get": {
                        "summary": "Get user",
                        "parameters": [{"name": "userId", "in": "path", "required": True}],
                        "responses": {"200": {"description": "OK"}},
                    }
                }
            },
        }
        records = parse_spec(document, "https://docs.example.com/openapi.json", "specs/spec.json", ["example.com"])
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["method"], "GET")
        self.assertEqual(records[0]["host"], "api.example.com")
        self.assertEqual(records[0]["url"], "https://api.example.com/v1/users/{userId}")
        self.assertEqual(records[0]["parameters"][0]["name"], "userId")

    def test_url_candidate_only_in_scope(self):
        records = extract_url_candidates([
            ("https://api.example.com/api/v1/users", "recon"),
            ("https://outside.test/api/v1/users", "recon"),
        ], ["example.com"])
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["host"], "api.example.com")


if __name__ == "__main__":
    unittest.main()
