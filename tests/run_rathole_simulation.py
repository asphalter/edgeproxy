#!/usr/bin/env python3
import subprocess
import time
import json
import sys
import os

SERVER_CONTAINER = "sim-rathole-server"
CLIENT_CONTAINER = "sim-rathole-client"
BACKEND_CONTAINER = "sim-mock-backend"

WORKSPACE = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SIM_DATA_DIR = os.path.join(WORKSPACE, "tests/sim_data")


def run_cmd(cmd, check=True):
    res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if check and res.returncode != 0:
        raise RuntimeError(f"Command failed ({res.returncode}): {cmd}\nStderr: {res.stderr}\nStdout: {res.stdout}")
    return res


def cleanup():
    print("[Simulation] Cleaning up containers...", flush=True)
    subprocess.run(f"podman rm -f {SERVER_CONTAINER} {CLIENT_CONTAINER} {BACKEND_CONTAINER}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    print("=" * 70, flush=True)
    print("Simulazione Reale Data Plane: Tunnel Rathole + Mock Backend HTTP", flush=True)
    print("=" * 70, flush=True)

    cleanup()

    try:
        # 1. Avvia Mock Backend HTTP su 127.0.0.1:9000
        print("[1/4] Avvio Mock Backend HTTP (porta 9000 su localhost)...", flush=True)
        run_cmd(
            f'podman run -d --name {BACKEND_CONTAINER} --network host '
            f'-v "{SIM_DATA_DIR}:/workspace:z" -w /workspace '
            f'docker.io/python:3.12-slim python3 backend.py'
        )

        # 2. Avvia Rathole Server
        print("[2/4] Avvio Rathole Server (porta controllo 2333, porta servizio 8003)...", flush=True)
        run_cmd(
            f'podman run -d --name {SERVER_CONTAINER} --network host '
            f'-v "{SIM_DATA_DIR}:/workspace:z" '
            f'docker.io/rapiz1/rathole:latest /workspace/server.toml'
        )

        # 3. Avvia Rathole Client
        print("[3/4] Avvio Rathole Client (connessione a 127.0.0.1:2333)...", flush=True)
        run_cmd(
            f'podman run -d --name {CLIENT_CONTAINER} --network host '
            f'-v "{SIM_DATA_DIR}:/workspace:z" '
            f'docker.io/rapiz1/rathole:latest /workspace/client.toml'
        )

        # Attendi che il tunnel Rathole negozi la connessione e stabilisca la sessione
        print("In attesa che il tunnel Rathole negozi la sessione multiplexata...", flush=True)
        time.sleep(3)

        # 4. Invia richiesta HTTP alla porta esposta dal Server Rathole (8003)
        print("[4/4] Inoltro richiesta HTTP verso Rathole Server (127.0.0.1:8003)...", flush=True)
        test_cmd = (
            f'podman run --rm --network host docker.io/python:3.12-slim '
            f'python3 -c "'
            f'import urllib.request, json; '
            f'res = urllib.request.urlopen(\'http://127.0.0.1:8003\', timeout=5); '
            f'body = res.read().decode(); '
            f'print(body)"'
        )
        res = run_cmd(test_cmd)
        raw_output = res.stdout.strip()
        print(f"\n[Risposta Ricevuta dal Mock Backend attraverso il Tunnel]:\n{raw_output}\n", flush=True)

        data = json.loads(raw_output)
        assert data.get("status") == "ok", f"Stato non valido: {data}"
        assert data.get("service") == "backend-payload", f"Servizio non valido: {data}"

        print(">>> SUCCESS: La richiesta ha attraversato con successo il tunnel Rathole!", flush=True)
        print(">>> Flusso verificato: Client HTTP -> Rathole Server (8003) -> Control Tunnel (2333) -> Rathole Client -> Mock Backend (9000).", flush=True)
        print(">>> Data Plane verificato al 100% (Reverse Tunnel Multiplexing Operativo).", flush=True)
        return 0

    except Exception as e:
        print(f"\n[ERROR in Simulazione]: {e}", file=sys.stderr, flush=True)
        for c in (SERVER_CONTAINER, CLIENT_CONTAINER, BACKEND_CONTAINER):
            log_res = subprocess.run(f"podman logs {c}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            print(f"--- Logs {c} ---\n{log_res.stdout}\n", file=sys.stderr, flush=True)
        return 1
    finally:
        cleanup()


if __name__ == "__main__":
    sys.exit(main())
