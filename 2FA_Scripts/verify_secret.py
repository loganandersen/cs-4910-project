import subprocess
import pyotp
import os

# Hardcoded password for testing (same as encryption)
gpg_password = "MyTestPassword123"

# --------------------
# Read active user
# --------------------
with open("active_user.txt", "r") as f:
    user = f.read().strip()

# Build path to user's folder (layer 3)
user_dir = os.path.join("users", user)

# Encrypted secret path (layer 3)
secret_gpg_path = os.path.join(user_dir, "secret.txt.gpg")

# --------------------
# Decrypt the secret in memory
# --------------------
result = subprocess.run(
    [
        "gpg",
        "--batch",
        "--yes",
        "--passphrase", gpg_password,
        "-d",
        secret_gpg_path              # ✅ layer 3
    ],
    capture_output=True,
    text=True
)

# Check for decryption errors
if result.returncode != 0:
    raise Exception(f"Decryption failed: {result.stderr}")

# Extract the secret key
secret = result.stdout.strip()

# Generate TOTP object
totp = pyotp.TOTP(secret)

# Ask the user for their 2FA code
user_code = input("Enter your 2FA code: ")

# Verify the TOTP
if totp.verify(user_code):
    print("Correct")
else:
    print("Incorrect")

# Clear sensitive data
del secret
del result


