"""
Lab agent launcher — starts the built agent against the mock SaaS server.
Factoried into Python so the test harness owns the full env contract in one
place (see run_integration_linux.sh).

Usage: python lab_run_agent.py <agent_bin> <c2_lab_base> <password>
Prints the agent PID on stdout.
"""
import os
import subprocess
import sys


def main():
    agent_bin, c2_lab, password = sys.argv[1], sys.argv[2], sys.argv[3]

    home = "/tmp/c2lab-home"
    os.makedirs(home, exist_ok=True)

    env = dict(os.environ)
    env.update({
        # Channel + credentials (test vectors from test_crypto.py)
        "GITHUB_TOKEN": "mock-token",
        "GITHUB_REPO": "test/lab",
        "ENCRYPTION_PASSWORD": password,
        "POLL_INTERVAL": "5",
        # Point every API call at the local mock server (see main.rs api_base)
        "C2_LAB": c2_lab,
        # Research safety switches: skip persistence/hiding/relocation and the
        # uptime sandbox check — this is a lab container, not a real target.
        "SKIP_PERSIST": "1",
        "SKIP_ROOTKIT": "1",
        "RELOCATED": "1",
        "HOME": home,
    })

    proc = subprocess.Popen(
        [agent_bin],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    print(proc.pid)


if __name__ == "__main__":
    main()
