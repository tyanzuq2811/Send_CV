from Crypto.PublicKey import RSA

key = RSA.generate(1024)  
private_key = key
public_key = key.publickey()

with open("public_key.pem", "wb") as f:
    f.write(public_key.export_key())

with open("private_key.pem", "wb") as f:
    f.write(private_key.export_key())

