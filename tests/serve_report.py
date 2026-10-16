#!/usr/bin/env python3
"""Tiny static file server for previewing out/report.html over HTTP."""

import http.server
import os
import socketserver

PORT = 8622
ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "out")


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=ROOT, **kwargs)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()


if __name__ == "__main__":
    os.makedirs(ROOT, exist_ok=True)
    with socketserver.TCPServer(("127.0.0.1", PORT), Handler) as httpd:
        print(f"report preview at http://127.0.0.1:{PORT}/report.html", flush=True)
        httpd.serve_forever()
