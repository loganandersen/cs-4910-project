#!/usr/bin/env python3
import socket, ssl, struct, json
import cryptography
import base64
import os
from getpass import getpass

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import pyotp

APP_NAME = "cs-4910-shared-password-manager"

CA_CERT = "cert.pem"
HOST, PORT = "127.0.0.1", 8443

PASSWORD_ITERATIONS = 1_200_000
MAX_SECRET_SIZE = 256

# https://stackoverflow.com/questions/71667730/encrypting-message-with-user-input-as-key-python-fernet
# https://stackoverflow.com/questions/71667730/encrypting-message-with-user-input-as-key-python-fernet
# Get a fernet key from a password 
def derive_key_from_password(password,salt) :
    password = bytes(password, "UTF-8")
    
    # get a key derivation function
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                     length=32,
                     salt=salt,
                     iterations=PASSWORD_ITERATIONS)
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

def create_encrypted_message(message=None,pass_prompt="enter password to encrypt message: ") :
    """ Asks user for a message and returns a string representation so I can send it on json

    This is for the user only, and isn't decrypted by the server"""
    salt = os.urandom(16)
    
    # get password for encryption
    password = getpass(prompt=pass_prompt)
    # key for fernet
    # https://cryptography.io/en/latest/fernet/#using-passwords-with-fernet
    key = derive_key_from_password(password, salt)
    f = Fernet(key)
    # get message to encrypt

    if message == None :
        getsecret = lambda  : bytes(getpass(prompt="Enter a secret message to encrypt: "), "UTF-8")
        secret = getsecret()
        while len(secret) > MAX_SECRET_SIZE :
            print("Secret too big, must be lower than", MAX_SECRET_SIZE, "bytes")
            secret = getsecret()
    else :
        secret = bytes(message, "utf-8")

    # encrypt the secret
    encrypted_message = f.encrypt(secret).decode("utf-8")
    return encrypted_message, salt

def decrypt_message(secret,salt) :
    """Takes a secret and salt, returns the plaintext of secret,
    secret should be a string, assumes UTF-8 encoding"""

    tries = 0
    value = None
    while (tries < 3) :
        password = getpass(prompt="enter password to decrypt message: ")
        key = derive_key_from_password(password, salt)
        f = Fernet(key)
        try :
            value = f.decrypt(secret).decode("utf-8")
        except cryptography.fernet.InvalidToken :
            print("Failed to decrypt (likely due to wrong password), please try again")
            tries += 1
        else :
            return value.decode("utf-8")
        

    print("decryption failed")
    return False
    
    
# POLICY should have the following things...
# NAME : name of the policy
# USER : person who can download the file
# AUTHORIZER : person who user needs to request permission from to dl
# SECRET : secret the user wants back
# SALT : the salt for decrypting the secret.
def create_policy() :
    name = input("Enter the name of the policy: ")
    user = input("Enter the name of the user who can download the secret: ")
    authorizer = input("Enter the name of the authorizer, the person who needs to approve the download: ")
    encrypted_secret, salt = create_encrypted_message()

    # Construct the policy dictionary
    policy = {
        "name": name,
        "user": user,
        "authorizer": authorizer,
        "secret": encrypted_secret,  # Encrypted secret
        "salt": base64.urlsafe_b64encode(salt).decode()
    }

    return policy

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
    """send a json to the server, obj is a dictionary"""
    data = json.dumps(obj).encode()
    sock.sendall(struct.pack("!I", len(data)))
    sock.sendall(data)

def download(sock, token, policy_name):
    """Request to download a policy and wait for approval."""
    action = "download"
    msg = {
        "action": action,
        "token": token,
        "policy": policy_name
    }
    send_json(sock, msg)
    
    # Poll for approval
    while True:
        approval_response = recv_json(sock)
        print("Approval Response from server:", approval_response)
        
        if approval_response.get("status") == "ok":
            # Download the secret upon approval
            secret = approval_response.get("secret")
            salt = base64.urlsafe_b64decode(approval_response.get("salt"))
            message = decrypt_message(secret,salt)
            if message  :
                print("Secret message below")
                print(message)
            else :
                print("No message found")
                break
        elif approval_response.get("status") == "fail":
            print("Approval failed:", approval_response.get("reason"))
            break
        time.sleep(1)  # Wait a little before polling again


def approve_or_deny_download(sock, token, policy_name,deny):
    """Send a request to approve a download for a policy."""
    action = "approve_download"
    msg = {
        "action": action,
        "token": token,
        "policy_name": policy_name,
        "deny" : "yes" if deny else "no"
    }
    send_json(sock, msg)

    response = recv_json(sock)
    print("Response from server:", response)

def approve_download(sock, token,policy_name) :
    approve_or_deny_download(sock, token, policy_name,deny=False)

def deny_download(sock, token,policy_name) :
    approve_or_deny_download(sock, token, policy_name,deny=True)

def list_policies(sock, token):
    """Request the list of policies."""
    action = "list_policies"
    msg = {
        "action": action,
        "token": token
    }
    send_json(sock, msg)

    response = recv_json(sock)
    if response.get("status") == "ok":
        print("Policies received:")
        print(response.get("policies"))
    else:
        print("Error:", response.get("reason"))

    
def main():
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_CERT)
    ctx.check_hostname = True
    token = None

    with socket.create_connection((HOST, PORT)) as sock:
        with ctx.wrap_socket(sock, server_hostname="localhost") as ssock:
            # 1) login
            user = input("Username: ").strip()
            pwd = getpass().strip()

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
                command = input("Enter command (use help for available commands): ").strip()
                if not command:
                    continue
                
                if command == "quit":
                    break
                
                elif command == "logout":
                    send_json(ssock, {"action": "logout", "token": token})
                    print(recv_json(ssock))
                    break
                
                elif command == "create_policy":
                    policy = create_policy()  
                    send_json(ssock, {"action": "create_policy", "token": token, "policy": policy})
                    print("Policy created and sent to server.")
                
                elif command == "help":
                    # Display help information but don't send anything to the server
                    print("Available commands:")
                    print("- quit: Exit the application.")
                    print("- logout: Log out from the server.")
                    print("- create_policy: Create a new policy.")
                    print("- help: Show this help message.")
                    print("- download: request to download a file")
                    print("- authenticate: authenticate a download request")
                    print("- deny: deny a download request")
                    print("- list: list policies you are privy to")
                    
                elif command == "download":
                    policyname = input("Enter name of policy you want to download: ")
                    download(ssock, token, policyname)

                elif command == "list" :
                    list_policies(ssock,token)
                    
                elif command == "authenticate":
                    policyname = input("Enter name of policy you want to authenticate: ")
                    approve_download(ssock,token,policyname)

                elif command == "deny" :
                    policyname = input("Enter name of policy you want to authenticate: ")
                    approve_download(ssock,token,policyname)
                    
                    
                else:
                    print("Unknown command. Use 'help' for available commands.")

if __name__ == "__main__":
    main()

