#!/usr/bin/env python3
import socket, ssl, struct, json

CA_CERT = "cert.pem"
HOST, PORT = "127.0.0.1", 8443

def recv_all(sock, n):
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data

def recv_json(sock):
    raw = recv_all(sock, 4)
    if not raw:
        return None
    (L,) = struct.unpack("!I", raw)
    payload = recv_all(sock, L)
    if payload is None:
        return None
    return json.loads(payload.decode())

def send_json(sock, obj):
    data = json.dumps(obj).encode()
    sock.sendall(struct.pack("!I", len(data)))
    sock.sendall(data)

def main():
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_CERT)
    ctx.check_hostname = True
    token = None

    with socket.create_connection((HOST, PORT)) as sock:
        with ctx.wrap_socket(sock, server_hostname="localhost") as ssock:
            # 1) login
            user = input("Username: ").strip()
            pwd = input("Password: ").strip()

            send_json(ssock, {"action": "login", "user": user, "pass": pwd})
            resp = recv_json(ssock)
            print("login:", resp)
            if resp.get("status") != "ok":
                print("Login failed:", resp.get("reason"))
                return
            token = resp["token"]
            print("Logged in; token expires in", resp.get("expires_in"))
            # 2) interact using token
            while True:
                msg = input("Enter message (or 'quit'/'logout'): ").strip()
                if not msg:
                    continue
                if msg == "quit":
                    break
                if msg == "logout":
                    send_json(ssock, {"action": "logout", "token": token})
                    print(recv_json(ssock))
                    break
                send_json(ssock, {"action": "msg", "token": token, "body": msg})
                print("reply:", recv_json(ssock))

if __name__ == "__main__":
    main()

