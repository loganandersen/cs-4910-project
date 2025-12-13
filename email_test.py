import smtplib
from email.message import EmailMessage
import mimetypes
import subprocess

EMAIL_ADDRESS = "CS3900TESTforme@gmail.com"
APP_PASSWORD = "jkag vlkm vbhk psgn"  # Google App Password

# Encrypted PNG file
encrypted_image_path = "2fa_qr.png.gpg"
gpg_password = "MyTestPassword123"  # same as used for encryption

# Decrypt PNG in memory
result = subprocess.run(
    ["gpg", "--batch", "--yes", "--passphrase", gpg_password, "-d", encrypted_image_path],
    capture_output=True
)

if result.returncode != 0:
    raise Exception(f"Failed to decrypt PNG: {result.stderr}")

png_data = result.stdout  # binary PNG data

# Create email
msg = EmailMessage()
msg["Subject"] = "Test Email with Image"
msg["From"] = EMAIL_ADDRESS
msg["To"] = EMAIL_ADDRESS
msg.set_content("Hello! This email contains your code.\nScan the QR code to save it in your app.")

# Detect MIME type
mime_type, _ = mimetypes.guess_type("2fa_qr.png")
if mime_type is None:
    mime_type = "application/octet-stream"
maintype, subtype = mime_type.split("/", 1)

# Attach the decrypted PNG
msg.add_attachment(png_data, maintype=maintype, subtype=subtype, filename="2fa_qr.png")

# Send email via Gmail
with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
    smtp.login(EMAIL_ADDRESS, APP_PASSWORD)
    smtp.send_message(msg)

print("Email with encrypted PNG sent successfully!")
