import pyotp
import time

def generate_uri() :

    # 1. Generate secret for new user
    secret = pyotp.random_base32()
    print("Secret:", secret)

    # 2. Create provisioning URL (for Google Authenticator)
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name="user@example.com", issuer_name="MyApp")



def verify_uri() :
    secret = "REEL7JCUOHJ7TRSAHCZIODBKH2JLAXRK"    # Replace with your real secret
    totp = pyotp.TOTP(secret)

    user_code = input("Enter your 2FA code: ")

    if totp.verify(user_code):
        print("Correct")
        time.sleep(5)   # 5-second delay after "Correct"
    else:
        print("Incorrect")
        time.sleep(5)   # 5-second delay after "Incorrect"
