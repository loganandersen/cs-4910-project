#!/usr/bin/env python3
#https://docs.python.org/3/library/socketserver.html + chatgpt
import socketserver, ssl, socket, struct, json, time, secrets, threading
import bcrypt

CERTFILE = "cert.pem"
KEYFILE = "key.pem"
HOST, PORT = "0.0.0.0", 8443
SESSION_TTL = 300  # seconds

# Example user DB: username -> bcrypt-hashed password
USERS = {
    "alice": bcrypt.hashpw(b"secret123", bcrypt.gensalt())
}

# In-memory session store: token -> (username, expiry)
sessions = {}
sessions_lock = threading.Lock()

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

def make_token():
    return secrets.token_urlsafe(32)

def validate_token(token):
    with sessions_lock:
        entry = sessions.get(token)
        if not entry:
            return None
        username, expiry = entry
        if time.time() > expiry:
            del sessions[token]
            return None
        return username

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        ssock = self.request
        try:
            ssock.do_handshake()
        except ssl.SSLError as e:
            print("Handshake failed:", e)
            ssock.close()
            return

        try:
            while True:
                msg = recv_json(ssock)
                if msg is None:
                    break  # client closed
                action = msg.get("action")
                if action == "login":
                    user = msg.get("user", "")
                    pwd = msg.get("pass", "").encode()
                    stored = USERS.get(user)
                    if stored and bcrypt.checkpw(pwd, stored):
                        token = make_token()
                        expiry = time.time() + SESSION_TTL
                        with sessions_lock:
                            sessions[token] = (user, expiry)
                        send_json(ssock, {"status": "ok", "token": token, "expires_in": SESSION_TTL})
                    else:
                        send_json(ssock, {"status": "fail", "reason": "invalid credentials"})
                elif action == "msg":
                    token = msg.get("token")
                    user = validate_token(token)
                    if not user:
                        send_json(ssock, {"status": "fail", "reason": "invalid token"})
                        continue
                    body = msg.get("body", "")
                    print(f"[{user}] {body}")
                    send_json(ssock, {"status": "ok", "echo": body})
                elif action == "logout":
                    token = msg.get("token")
                    with sessions_lock:
                        sessions.pop(token, None)
                    send_json(ssock, {"status": "ok"})
                # TODO
                elif action == "create_policy":
                    pass
                # TODO
                elif action == "request_download" :
                    pass
                # TODO 
                elif action == "approve_download" :
                    pass
                # TODO
                elif action == "reset_password" :
                    pass
                else:
                    send_json(ssock, {"status": "fail", "reason": "unknown action"})
        except (ssl.SSLError, OSError) as e:
            print("I/O error:", e)
        finally:
            try:
                ssock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            ssock.close()

class TLSServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True
    def __init__(self, addr, HandlerClass, ctx):
        super().__init__(addr, HandlerClass)
        self.ctx = ctx
    def get_request(self):
        newsock, addr = self.socket.accept()
        ssock = self.ctx.wrap_socket(newsock, server_side=True, do_handshake_on_connect=False)
        return ssock, addr

if __name__ == "__main__":
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=CERTFILE, keyfile=KEYFILE)
    ctx.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    with TLSServer((HOST, PORT), Handler, ctx) as srv:
        print(f"Listening TLS on {HOST}:{PORT}")
        srv.serve_forever()
