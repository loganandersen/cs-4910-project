import subprocess
import pyotp
import time

# Decrypt the secret from GPG in memory
result = subprocess.run(
    ["gpg", "--batch", "--yes", "-d", "secret.txt.gpg"],
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
    print("Correct ✔️")
    time.sleep(5)  # 5-second delay after "Correct"
else:
    print("Incorrect ❌")
    time.sleep(5)  # 5-second delay after "Incorrect"

# Optional: clear sensitive data from memory
del secret
del result

