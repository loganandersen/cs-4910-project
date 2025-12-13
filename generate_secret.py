import pyotp
import qrcode
import subprocess
import os

# 1. Generate secret for new user
secret = pyotp.random_base32()
with open("secret.txt", "w") as f:
    f.write(secret + "\n")

# 2. Encrypt the secret file with GPG (AES-256 symmetric encryption)
# It will prompt for a password
subprocess.run(
    ["gpg", "--symmetric", "--cipher-algo", "AES256", "secret.txt"],
    check=True
)

print("Secret file encrypted: secret.txt.gpg")

# 3. Delete the plaintext secret file
os.remove("secret.txt")
print("Plaintext secret deleted: secret.txt")

# 4. Create provisioning URL (for Google Authenticator)
totp = pyotp.TOTP(secret)
uri = totp.provisioning_uri(name="CS3900 2FA", issuer_name="generate_secret_test")

# 5. Create QR code
img = qrcode.make(uri)
img.save("2fa_qr.png")
print("QR generated: 2fa_qr.png")
