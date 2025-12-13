import pyotp
import qrcode

# 1. Generate secret for new user
secret = pyotp.random_base32()
print("Secret:", secret)

# 2. Create provisioning URL (for Google Authenticator)
totp = pyotp.TOTP(secret)
uri = totp.provisioning_uri(name="user@example.com", issuer_name="MyApp")

# 3. Create QR code
img = qrcode.make(uri)
img.save("2fa_qr.png")
print("QR generated: 2fa_qr.png")
