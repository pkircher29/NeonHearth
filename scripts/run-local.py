#!/usr/bin/env python3
"""Launch an isolated local build without replacing the installed service."""
import argparse
import getpass
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import time
import urllib.request
import webbrowser

ROOT = Path(__file__).resolve().parents[1]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def protected(path):
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    if os.name == "nt":
        subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r",
                        f"{getpass.getuser()}:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F"],
                       check=True, capture_output=True)
    else:
        path.chmod(0o700)


def authenticated(url, token):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    request = urllib.request.Request(url + "/api/v1/automation", headers={"Authorization": "Bearer " + token})
    try:
        with opener.open(request, timeout=2) as response:
            return response.status == 200 and "devices" in json.load(response)
    except Exception:
        return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=58121)
    parser.add_argument("--state", type=Path, default=ROOT / ".local" / "runtime")
    parser.add_argument("--service", type=Path, default=ROOT / "artifacts" / "NeonHearth-home-hub-release" / "lattice-service.exe")
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--mqtt-directory", type=Path, default=ROOT / ".local" / "mqtt")
    parser.add_argument("--mqtt-port", type=int, default=58183)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        raise ValueError("Port must be 1024..65535")
    state = args.state.resolve()
    protected(state)
    broker = ROOT / "artifacts" / "mosquitto" / "bin" / ("mosquitto.exe" if os.name == "nt" else "mosquitto")
    if broker.is_file():
        subprocess.run([sys.executable, str(ROOT / "scripts" / "mqtt-hub.py"),
                        "ensure", "--binary", str(broker),
                        "--directory", str(args.mqtt_directory.resolve()),
                        "--port", str(args.mqtt_port)], check=True,
                       creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
    connection = state / "connection.json"
    url = f"http://127.0.0.1:{args.port}"
    if connection.exists():
        previous = json.loads(connection.read_text(encoding="utf-8"))
        if previous.get("url") == url and authenticated(url, previous["token"]):
            if not args.no_browser:
                webbrowser.open(url + "/#token=" + previous["token"])
            print(f"NeonHearth is running at {url}")
            return
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", args.port))
    binary = args.service.resolve(strict=True)
    ui = ROOT / "apps" / "desktop" / "dist"
    if not (ui / "index.html").is_file():
        raise ValueError("Build the desktop UI first")
    token = secrets.token_urlsafe(48)
    env = os.environ.copy()
    env.setdefault("RUST_LOG", "lattice_service=warn,lattice_sensor=warn")
    env.update(LATTICE_BIND=f"127.0.0.1:{args.port}", LATTICE_SERVICE_TOKEN=token,
               LATTICE_STATE_BASE=str(state / "data"), LATTICE_UI_DIR=str(ui))
    mqtt_config = args.mqtt_directory.resolve() / "client.json"
    if mqtt_config.is_file():
        env["LATTICE_MQTT_CREDENTIAL_FILE"] = str(mqtt_config)
    log = (state / "service.log").open("ab")
    process = subprocess.Popen([str(binary)], cwd=binary.parent, env=env,
                               stdout=log, stderr=subprocess.STDOUT,
                               creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                               start_new_session=os.name != "nt")
    for _ in range(80):
        if process.poll() is not None:
            raise RuntimeError(f"Service exited. See {state / 'service.log'}")
        if authenticated(url, token):
            connection.write_text(json.dumps({"url": url, "token": token, "pid": process.pid,
                                              "binary": str(binary)}), encoding="utf-8")
            if os.name != "nt":
                connection.chmod(0o600)
            if not args.no_browser:
                webbrowser.open(url + "/#token=" + token)
            print(f"NeonHearth started at {url}. Private state: {state}")
            return
        time.sleep(0.25)
    raise RuntimeError(f"Service did not become ready. See {state / 'service.log'}")


if __name__ == "__main__":
    main()
