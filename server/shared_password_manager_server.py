#!/usr/bin/env python3
#https://docs.python.org/3/library/socketserver.html + chatgpt
import socketserver, ssl, socket, struct, json, time, secrets, threading
import bcrypt
import sqlite3
import pyopt

DATABASE_NAME = "database.db"

APP_NAME = "cs-4910-shared-password-manager"

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

# Initialize the SQLite database
def init_db():
    connection = sqlite3.connect(DATABASE_NAME)
    cursor = connection.cursor()

    # Create users table if it doesn't exist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
    )
    ''')

    # Create policies table if it doesn't exist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS policies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        user TEXT NOT NULL,
        authorizer TEXT NOT NULL,
        secret TEXT NOT NULL,
        salt TEXT NOT NULL,
        url TEXT NOT NULL    
    )
    ''')

    connection.commit()
    connection.close()

def get_user_password(username):
    """Function to retrieve the hashed password for a given username from the SQLite database."""
    connection = sqlite3.connect(DATABASE_NAME)
    cursor = connection.cursor()
    
    cursor.execute('SELECT password FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()
    
    connection.close()
    
    return result[0] if result else None

    
def add_policy(name, user, authorizer, secret, salt):
    connection = sqlite3.connect(DATABASE_NAME)
    cursor = connection.cursor()
    url = generate_totp_uri(user)
    
    try:
        # Insert the new policy into the database
        cursor.execute('''
            INSERT INTO policies (name, user, authorizer, secret, salt, 2FA_uri)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (name, user, authorizer, secret, salt, url))

        connection.commit()
        print(f"Policy '{name}' created successfully.")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        connection.close()
    
# https://pypi.org/project/pyotp/
def generate_totp_uri(user) :
    secret = pyotp.random_base32()
    totp = pyopt.TOTP(secret)
    return totp.provisioning_uri(name=user,isuer_name=APP_NAME)

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
                    stored = get_user_password(user)
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
                    token = msg.get("token")
                    user = validate_token(token)  # Validate the provided token
                    if not user:
                        send_json(ssock, {"status": "fail", "reason": "invalid token"})
                        continue

                    # Retrieve the policy data sent from the client
                    policy = msg.get("policy")
    
                    # Optional: Validate the policy structure if needed
                    if (not policy or
                        "name" not in policy or
                        "user" not in policy or
                        "authorizer" not in policy
                        or "secret" not in policy
                        or "salt" not in policy) :
                        send_json(ssock, {"status": "fail", "reason": "invalid policy structure"})
                        continue

                    # Here you would typically save the policy to a database or process it
                    # For now, we will just print the policy as an example
                    try:
                        add_policy(policy["name"], policy["user"], policy["authorizer"], policy["secret"], policy["salt"])
                        send_json(ssock, {"status": "ok", "reason": "policy created"})
                    except Exception as e:
                        send_json(ssock, {"status": "fail", "reason": f"failed to create policy: {str(e)}"})
                        # Respond back to the client that the policy was successfully created
                        send_json(ssock, {"status": "ok", "reason": "policy created"})

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
    init_db()  # Initialize the database at startup
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=CERTFILE, keyfile=KEYFILE)
    ctx.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    with TLSServer((HOST, PORT), Handler, ctx) as srv:
        print(f"Listening TLS on {HOST}:{PORT}")
        srv.serve_forever()
