import subprocess
import pyotp
import os

# Hardcoded password for testing
gpg_password = "MyTestPassword123"

def load_and_verify_user(username):
    print(f"\nVerifying {username}")

    user_dir = os.path.join("users", username)
    secret_gpg_path = os.path.join(user_dir, "secret.txt.gpg")

    if not os.path.exists(secret_gpg_path):
        print("Secret not found")
        return False

    # Decrypt secret
    result = subprocess.run(
        [
            "gpg",
            "--batch",
            "--yes",
            "--passphrase", gpg_password,
            "-d",
            secret_gpg_path
        ],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print("Decryption failed")
        return False

    secret = result.stdout.strip()
    totp = pyotp.TOTP(secret)

    code = input(f"Enter {username}'s 2FA code: ")

    if totp.verify(code):
        print(f"{username}: Correct")
        return True
    else:
        print(f"{username}: Incorrect")
        return False


# --------------------
# FIRST USER (from active_user.txt)
# --------------------
with open("active_user.txt", "r") as f:
    user1 = f.read().strip()

if load_and_verify_user(user1):

    # --------------------
    # SECOND USER (prompted)
    # --------------------
    user2 = input("\nEnter second username: ").strip()
    load_and_verify_user(user2)
