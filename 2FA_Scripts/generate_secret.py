import pyotp
import qrcode
import subprocess
import os

# Read active user
with open("active_user.txt", "r") as f:
    user = f.read().strip()

# Build path to user's folder (layer 3)
user_dir = os.path.join("users", user)
os.makedirs(user_dir, exist_ok=True)

# --------------------
# 1. Generate secret
# --------------------
secret = pyotp.random_base32()

secret_path = os.path.join(user_dir, "secret.txt")
with open(secret_path, "w") as f:
    f.write(secret + "\n")

# --------------------
# 2. Encrypt secret (layer 3)
# --------------------
gpg_password = "MyTestPassword123"

subprocess.run([
    "gpg",
    "--batch",
    "--yes",
    "--passphrase", gpg_password,
    "--symmetric",
    "--cipher-algo", "AES256",
    secret_path                      # ✅ FULL PATH
], check=True)

# Delete plaintext secret (layer 3)
os.remove(secret_path)

# --------------------
# 3. Generate QR
# --------------------
totp = pyotp.TOTP(secret)
uri = totp.provisioning_uri(
    name="CS3900 2FA"+ user,
    issuer_name="CS3900 2FA"
)

img = qrcode.make(uri)

png_path = os.path.join(user_dir, "2fa_qr.png")
img.save(png_path)

# --------------------
# 4. Encrypt QR (layer 3)
# --------------------
subprocess.run([
    "gpg",
    "--batch",
    "--yes",
    "--passphrase", gpg_password,
    "--symmetric",
    "--cipher-algo", "AES256",
    png_path                         # ✅ FULL PATH
], check=True)

# Delete plaintext PNG (layer 3)
os.remove(png_path)


