# SPDX-License-Identifier: BUSL-1.1
"""Test npm's public tarballs from an empty consumer project."""
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer


def install(project, package):
    (project / "package.json").write_text('{"name":"release-smoke","private":true}')
    deadline = time.monotonic() + 480
    for attempt in range(1, 25):
        result = subprocess.run(
            ["npm", "install", "--registry=https://registry.npmjs.org",
             "--cache", str(project / "cache"), "--prefer-online", "--fetch-retries=0",
             "--no-audit", "--no-fund", "--save-exact", package],
            cwd=project, capture_output=True, text=True,
            timeout=max(1, min(120, deadline - time.monotonic())),
        )
        if result.returncode == 0:
            return
        tarball_404 = re.search(r"404[^\n]*https://registry\.npmjs\.org/[^\s]+\.tgz\b", result.stderr)
        if not tarball_404 or attempt == 24 or time.monotonic() + 15 >= deadline:
            raise RuntimeError(result.stderr)
        print(f"Registry tarball returned 404 on attempt {attempt}; retrying in 15s", flush=True)
        time.sleep(15)


def check_entry_points(project, version):
    binaries = project / "node_modules/.bin"
    methods = []

    # The real CLI speaks HTTP. Forward its sequential requests verbatim to the
    # real stdio process so this check requires neither a deployed API nor a key.
    class Bridge(BaseHTTPRequestHandler):
        def do_POST(self):
            try:
                request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                server.stdin.write(json.dumps(request) + "\n")
                server.stdin.flush()
                methods.append(request["method"])
                if "id" not in request:
                    self.send_response(202)
                    self.end_headers()
                else:
                    response = json.loads(server.stdout.readline())
                    assert response["id"] == request["id"]
                    if request["method"] == "initialize":
                        assert response["result"]["serverInfo"]["version"] == version
                    if request["method"] == "tools/list":
                        assert any(t["name"] == "check_spf" for t in response["result"]["tools"])
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(response).encode())
            except Exception as exc:
                self.send_error(502, str(exc))

    with HTTPServer(("localhost", 0), Bridge) as bridge:
        server = subprocess.Popen(
            [binaries / "blackveil-dns-mcp"], cwd=project, text=True,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        )
        threading.Thread(target=bridge.serve_forever, daemon=True).start()
        try:
            cli = subprocess.run(
                [binaries / "blackveil", "check", "spf", "example.com", "--format", "json"],
                cwd=project, env={**os.environ, "BLACKVEIL_API_KEY": "",
                                  "BLACKVEIL_MCP_URL": f"http://127.0.0.1:{bridge.server_port}/mcp"},
                check=True, stdout=subprocess.PIPE, text=True, timeout=60,
            )
            result = json.loads(cli.stdout)
            assert result["category"] == "spf" and result["passed"] is True, result
            assert result["metadata"]["spfAll"] == "-all", result
            assert methods == ["initialize", "notifications/initialized", "tools/list", "tools/call"], methods
        finally:
            server.kill()
            server.wait(timeout=5)
            bridge.shutdown()


if __name__ == "__main__":
    root = os.environ["ROOT_VERSION"]
    checks = os.environ["DNS_CHECKS_VERSION"]
    checks_only = os.environ["PACKAGES"] == "dns-checks"
    with tempfile.TemporaryDirectory(prefix="npm-consumer-") as temp:
        project = Path(temp)
        install(project, f"@blackveil/dns-checks@{checks}" if checks_only else f"blackveil-dns@{root}")
        tree = json.loads(subprocess.check_output(["npm", "ls", "--all", "--json"], cwd=project))
        dependencies = tree["dependencies"]
        if not checks_only:
            assert dependencies["blackveil-dns"]["version"] == root
            dependencies = dependencies["blackveil-dns"]["dependencies"]
        assert dependencies["@blackveil/dns-checks"]["version"] == checks
        subprocess.run(["node", "--input-type=module", "-e", "await import('@blackveil/dns-checks')"],
                       cwd=project, check=True)
        if not checks_only:
            check_entry_points(project, root)
        print("Published npm consumer smoke passed")
