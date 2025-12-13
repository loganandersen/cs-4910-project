import pyotp
import qrcode

# 1. Generate secret for new user
secret = pyotp.random_base32()
with open("secret.txt", "w") as f:
    f.write(secret + "\n")

# 2. Create provisioning URL (for Google Authenticator)
totp = pyotp.TOTP(secret)
uri = totp.provisioning_uri(name="CS3900 2FA", issuer_name="generate_secret_test")

# 3. Create QR code
img = qrcode.make(uri)
img.save("2fa_qr.png")
print("QR generated: 2fa_qr.png")
