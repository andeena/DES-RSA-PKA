import asyncio
import websockets
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, DES
from Crypto.Util.Padding import pad, unpad
import os

async def communicate():
    uri = "ws://localhost:8765"
    try:
        async with websockets.connect(uri) as websocket:
            server_public_key = await websocket.recv()
            server_public_key = RSA.import_key(server_public_key.encode())
            print("Kunci publik server diterima.")
            
            des_key = os.urandom(8)  # 8-byte DES key
            des_cipher = DES.new(des_key, DES.MODE_ECB)
            
            rsa_cipher = PKCS1_OAEP.new(server_public_key)
            encrypted_des_key = rsa_cipher.encrypt(des_key)
            await websocket.send(encrypted_des_key.hex())  # Kirim sebagai hex string
            print(f"DES Key terenkripsi berhasil dikirim ke server: {encrypted_des_key.hex()}")
            
            message = input("Enter a message to send to Server: ").encode()
            encrypted_message = des_cipher.encrypt(pad(message, DES.block_size))
            await websocket.send(encrypted_message.hex())  # Kirim sebagai hex string
            print(f"Pesan terenkripsi berhasil dikirim ke server: {encrypted_message.hex()}")
            
            encrypted_reply = await websocket.recv()
            encrypted_reply = bytes.fromhex(encrypted_reply)  # Convert dari hex string
            
            decrypted_reply = unpad(des_cipher.decrypt(encrypted_reply), DES.block_size)
            print(f"Balasan dari Server: {decrypted_reply.decode()}")
    
    except websockets.exceptions.ConnectionClosedError as e:
        print(f"Connection closed with error: {e}")

asyncio.run(communicate())
