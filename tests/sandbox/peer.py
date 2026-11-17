"""Provide test addresses, an echo service, and traffic probes within the sandbox."""
import json
import socket
import subprocess
import threading

for address in ('172.29.241.10/24', '172.29.241.11/24', '172.29.241.12/24', 'fd42:6e66:7467::10/64', 'fd42:6e66:7467::11/64', 'fd42:6e66:7467::12/64'):
    subprocess.run(['ip', 'address', 'add', address, 'dev', 'eth0', 'nodad'], check=True)


def listener(family, port, handler):
    with socket.socket(family, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        server.bind(('::' if family == socket.AF_INET6 else '0.0.0.0', port))
        server.listen()
        while True:
            conn, _ = server.accept()
            threading.Thread(target=handler, args=(conn,), daemon=True).start()


def echo(conn):
    with conn:
        conn.sendall(conn.recv(16))


def control(conn):
    with conn:
        with conn.makefile('rwb') as stream:
            for line in stream:
                request = json.loads(line)
                family = socket.AF_INET6 if ':' in request['source'] else socket.AF_INET
                try:
                    with socket.socket(family, socket.SOCK_STREAM) as probe:
                        probe.settimeout(1)
                        probe.bind((request['source'], 0))
                        probe.connect((request['destination'], 8000))
                        probe.sendall(b'ok')
                        result = probe.recv(2) == b'ok'
                except OSError:
                    result = False
                stream.write(json.dumps(result).encode() + b'\n')
                stream.flush()


for family in (socket.AF_INET, socket.AF_INET6):
    threading.Thread(target=listener, args=(family, 8000, echo), daemon=True).start()
listener(socket.AF_INET, 9000, control)
