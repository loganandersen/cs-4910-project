**1-**Need the following installed:

**pip install pyotp qrcode\[pil]** #This is for the QR code

**gpg4win-4.4.1** #This is used for encryption and decryption

**FreeOTP** #This is a free phone app for storing your key



**2-**In the terminal run the following:

**python generate\_secret.py**

This makes the following:

A key saved for use by other scripts
Encrypts the key

Makes a QR code for the user to store



**3-**Now run the following in the terminal:
**python verify\_secret.py**

This will decrypt the saved key
It will ask you for your 6 digit key saved on your phone
If correct or not, displays the result





**3.5 Using the app-** Using the app "FreeOTP" (icon is a spin style lock) scan the generated QR code



This will save the key. When you tap it, it shows a 6 digit code that will be the correct 2FA code



It changes every few seconds, it will still work as intended.





