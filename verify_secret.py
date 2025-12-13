import pyotp
import time

with open("secret.txt", "r") as f: #reads the generated key 
    secret = f.readline().strip()
    
totp = pyotp.TOTP(secret)

user_code = input("Enter your 2FA code: ")

if totp.verify(user_code):
    print("Correct ✔️")
    time.sleep(5)   # 5-second delay after "Correct"
else:
    print("Incorrect ❌")
    time.sleep(5)   # 5-second delay after "Incorrect"
