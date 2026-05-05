from __future__ import annotations

import unittest

from app.ui_helpers import normalize_http_url, safe_cache_name, safe_favicon_host


class UIHelperTests(unittest.TestCase):
    def test_normalize_http_url_allows_only_http_schemes(self) -> None:
        self.assertEqual(normalize_http_url('example.com'), 'https://example.com')
        self.assertEqual(normalize_http_url('http://example.com/path'), 'http://example.com/path')
        with self.assertRaises(ValueError):
            normalize_http_url('file:///etc/passwd')
        with self.assertRaises(ValueError):
            normalize_http_url('javascript:alert(1)')

    def test_favicon_host_and_cache_name_are_safe(self) -> None:
        self.assertEqual(safe_favicon_host('https://www.example.com:443/path'), 'example.com')
        self.assertEqual(safe_favicon_host('javascript:alert(1)'), '')
        self.assertEqual(safe_favicon_host('localhost'), '')
        self.assertEqual(safe_favicon_host('https://127.0.0.1:8080'), '')
        self.assertEqual(safe_favicon_host('https://192.168.1.10/admin'), '')
        self.assertEqual(safe_favicon_host('https://intranet.local'), '')
        self.assertEqual(safe_favicon_host('router'), '')
        self.assertEqual(safe_cache_name('example.com:443/a b'), 'example.com_443_a_b')


if __name__ == '__main__':
    unittest.main()
