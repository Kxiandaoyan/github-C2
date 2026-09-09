"""
Lab launcher — run the web controller against the local mock SaaS.

Patches GitHubClient.BASE to the mock server BEFORE app.py is imported, so
every GitHub API call from the controller hits the in-memory mock instead of
api.github.com. Test-only harness; production entry point stays app.py.

Usage (inside the repo's web-controller/, ideally on native Linux FS):
    python3 tests/run_controller_lab.py            # 127.0.0.1:8081
    C2_LAB=http://127.0.0.1:8480 C2_BIND=127.0.0.1 C2_PORT=8081 \
        WEB_USERNAME=admin WEB_PASSWORD=... python3 tests/run_controller_lab.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Patch BEFORE importing app (app.py builds clients at request time, but keep
# the ordering guarantee explicit).
import github_api  # noqa: E402

github_api.GitHubClient.BASE = os.environ.get("C2_LAB", "http://127.0.0.1:8480")

import app  # noqa: E402,F401  (module-level side effects start the poller etc.)

if __name__ == "__main__":
    host = os.environ.get("C2_BIND", "127.0.0.1")
    port = int(os.environ.get("C2_PORT", "8081"))
    print(f"[lab] controller on http://{host}:{port} "
          f"(github base -> {github_api.GitHubClient.BASE})", flush=True)
    app.app.run(host=host, port=port, debug=False, threaded=True)
