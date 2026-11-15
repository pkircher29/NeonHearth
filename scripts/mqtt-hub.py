#!/usr/bin/env python3
"""Provision and run a private Mosquitto hub. No credentials on command lines."""
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


def private_directory(path):
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name == "nt":
        subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r",
                        f"{getpass.getuser()}:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F"],
                       check=True, capture_output=True)
    else:
        path.chmod(0o700)


def write_private(path, content):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(content)
    if os.name != "nt":
        path.chmod(0o600)


def provision(binary, directory, port):
    if not 1024 <= port <= 65535:
        raise ValueError("Use an unprivileged port from 1024 to 65535")
    if directory.exists() and any(directory.iterdir()):
        raise ValueError("The hub directory already contains data. Existing credentials are never overwritten.")
    private_directory(directory)
    passwd = binary.with_name("mosquitto_passwd.exe" if os.name == "nt" else "mosquitto_passwd")
    if not binary.is_file() or not passwd.is_file():
        raise ValueError("Select an installed Mosquitto binary with mosquitto_passwd beside it")
    accounts = {name: secrets.token_urlsafe(32) for name in ("neonhearth", "homeassistant", "test-device")}
    password_file = directory / "passwords"
    write_private(password_file, "".join(f"{user}:{password}\n" for user, password in accounts.items()))
    # Hash the private staging file in place. -b would expose a password in argv.
    subprocess.run([str(passwd), "-U", str(password_file)], check=True, capture_output=True)
    write_private(directory / "acl", """user neonhearth
topic write neonhearth/automation/#
topic write neonhearth/network/#
topic write neonhearth/status
user homeassistant
topic read neonhearth/#
topic readwrite homeassistant/#
pattern write neonhearth/devices/%u/state
pattern write neonhearth/devices/%u/availability
pattern read neonhearth/devices/%u/set
""")
    # Only the local bridge is enabled initially. A LAN listener needs the TLS
    # configuration described in docs/owner/home-automation.md.
    config = f"""listener {port} 127.0.0.1
allow_anonymous false
password_file {password_file.as_posix()}
acl_file {(directory / 'acl').as_posix()}
persistence false
max_connections 64
max_packet_size 4194304
max_queued_messages 100
max_queued_bytes 4194304
memory_limit 67108864
log_dest stdout
log_type error
log_type warning
connection_messages false
"""
    write_private(directory / "mosquitto.conf", config)
    write_private(directory / "client.json", json.dumps({"port": port, "username": "neonhearth", "password": accounts["neonhearth"]}))
    write_private(directory / "accounts.json", json.dumps(accounts, indent=2))
    print(f"Hub configured at {directory}. Credentials are in the private accounts.json file.")


def authenticated(config):
    """Bounded MQTT 3.1.1 CONNECT probe against the configured loopback port."""
    def field(value):
        encoded = value.encode("utf-8")
        if len(encoded) > 256:
            raise ValueError("Invalid MQTT credential length")
        return len(encoded).to_bytes(2, "big") + encoded

    payload = field("neonhearth-probe-" + secrets.token_hex(4))
    payload += field(config["username"]) + field(config["password"])
    body = b"\x00\x04MQTT\x04\xc2\x00\x0a" + payload
    remaining, encoded_length = len(body), bytearray()
    while True:
        digit, remaining = remaining % 128, remaining // 128
        encoded_length.append(digit | (128 if remaining else 0))
        if not remaining:
            break
    try:
        with socket.create_connection(("127.0.0.1", config["port"]), timeout=1) as client:
            client.sendall(b"\x10" + encoded_length + body)
            reply = b""
            while len(reply) < 4:
                chunk = client.recv(4 - len(reply))
                if not chunk:
                    return False
                reply += chunk
            if reply != b"\x20\x02\x00\x00":
                return False
            client.sendall(b"\xe0\x00")
            return True
    except OSError:
        return False


def ensure_running(binary, directory, port):
    if not (directory / "client.json").is_file():
        provision(binary, directory, port)
    path = directory / "client.json"
    if path.stat().st_size > 4096:
        raise ValueError("Invalid MQTT configuration")
    config = json.loads(path.read_text(encoding="utf-8"))
    if (config.get("username") != "neonhearth" or
            not isinstance(config.get("port"), int) or not 1024 <= config["port"] <= 65535 or
            not isinstance(config.get("password"), str) or not 32 <= len(config["password"]) <= 256):
        raise ValueError("Invalid MQTT configuration")
    if authenticated(config):
        print("Authenticated local MQTT hub is ready.")
        return
    # Never replace an existing listener that does not accept these credentials.
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", config["port"]))
    broker_config = directory / "mosquitto.conf"
    if not broker_config.is_file():
        raise ValueError("Missing MQTT broker configuration")
    with (directory / "broker.log").open("ab") as log:
        process = subprocess.Popen([str(binary), "-c", str(broker_config)],
                                   cwd=binary.parent, stdout=log, stderr=subprocess.STDOUT,
                                   creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                                   start_new_session=os.name != "nt")
    (directory / "process.json").write_text(json.dumps({"pid": process.pid, "binary": str(binary)}), encoding="utf-8")
    for _ in range(40):
        if process.poll() is not None:
            raise ValueError("MQTT hub exited; inspect its private broker.log")
        if authenticated(config):
            print("Authenticated local MQTT hub started.")
            return
        time.sleep(0.25)
    raise ValueError("MQTT hub did not become ready")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("setup", "run", "ensure"))
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--directory", type=Path, default=Path(__file__).resolve().parents[1] / ".local" / "mqtt")
    parser.add_argument("--port", type=int, default=58183)
    args = parser.parse_args()
    binary, directory = args.binary.resolve(strict=True), args.directory.resolve()
    if args.action == "setup":
        provision(binary, directory, args.port)
    elif args.action == "ensure":
        ensure_running(binary, directory, args.port)
    else:
        config = directory / "mosquitto.conf"
        if not config.is_file():
            raise ValueError("Run setup before starting the hub")
        print(f"Starting the configured MQTT hub ({config}).")
        subprocess.run([str(binary), "-c", str(config)], check=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"MQTT hub failed: {type(error).__name__}. Check the binary and private configuration directory.", file=sys.stderr)
        sys.exit(1)
