import qrcode

def makeqrcode(uri):
    img = qrcode.make(uri)
    img.save("2fa_qr.png")
    print("QR generated: 2fa_qr.png")

