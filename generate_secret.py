import pyotp
import qrcode
import subprocess
import os

# 1. Generate secret for new user
secret = pyotp.random_base32()
with open("secret.txt", "w") as f:
    f.write(secret + "\n")

# 2. Hardcoded password for GPG encryption (for testing only)
gpg_password = "MyTestPassword123"

# 3. Encrypt the secret file with GPG non-interactively
subprocess.run([
    "gpg",
    "--batch",              # non-interactive mode
    "--yes",                # overwrite existing files
    "--passphrase", gpg_password,
    "--symmetric",
    "--cipher-algo", "AES256",
    "secret.txt"
], check=True)

# 3. Delete the plaintext secret file
os.remove("secret.txt")

# 4. Create provisioning URL (for Google Authenticator)
totp = pyotp.TOTP(secret)
uri = totp.provisioning_uri(name="CS3900 2FA", issuer_name="generate_secret_test")

# 5. Create QR code and save PNG
img = qrcode.make(uri)
png_filename = "2fa_qr.png"
img.save(png_filename)

# 6. Encrypt the PNG file immediately after creation
gpg_password = "MyTestPassword123"  # hardcoded for testing

subprocess.run([
    "gpg",
    "--batch",              # non-interactive
    "--yes",                # overwrite if needed
    "--passphrase", gpg_password,
    "--symmetric",
    "--cipher-algo", "AES256",
    png_filename
], check=True)


# 7. Optional: delete plaintext PNG
os.remove(png_filename)
