from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

class PublicKeyAuthority:
    def __init__(self):
        self.key = RSA.generate(2048)
        self.public_key = self.key.publickey().export_key()  
        self.private_key = self.key.export_key()  

    def get_public_key(self):
        return self.public_key

    def get_private_key(self):
        return self.private_key

    def decrypt_message(self, encrypted_message):
        cipher = PKCS1_OAEP.new(self.key)
        return cipher.decrypt(encrypted_message)

if __name__ == "__main__":
    pka = PublicKeyAuthority()

    with open("pka_public.pem", "wb") as pub_file:
        pub_file.write(pka.get_public_key())
    print("Public key PKA telah disimpan dalam pka_public.pem")

    with open("pka_private.pem", "wb") as priv_file:
        priv_file.write(pka.get_private_key())
    print("Private key PKA telah disimpan dalam pka_private.pem")

    print("Public Key Authority Initialized!")
