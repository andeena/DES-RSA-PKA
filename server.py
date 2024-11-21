import asyncio
import websockets
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, DES
from Crypto.Util.Padding import pad, unpad
import hashlib

server_key = RSA.generate(2048)
server_public_key = server_key.publickey().export_key()
print("RSA Key Pair untuk server berhasil dibuat.")

with open("server_public.pem", "wb") as f:
    f.write(server_public_key)

async def handle_client(websocket):
    print("Client terhubung.")
    
    await websocket.send(server_public_key.decode())
    print("Kunci publik server dikirim ke client.")
    
    encrypted_des_key = await websocket.recv()
    encrypted_des_key = bytes.fromhex(encrypted_des_key)  # Convert dari hex string
    
    rsa_cipher = PKCS1_OAEP.new(server_key)
    try:
        des_key = rsa_cipher.decrypt(encrypted_des_key)
        print(f"DES Key berhasil didekripsi: {des_key.hex()}")
    except ValueError:
        print("Error: Dekripsi DES Key gagal.")
        await websocket.close()
        return
    
    encrypted_message = await websocket.recv()
    encrypted_message = bytes.fromhex(encrypted_message)  # Convert dari hex string
    
    des_cipher = DES.new(des_key, DES.MODE_ECB)
    try:
        decrypted_message = unpad(des_cipher.decrypt(encrypted_message), DES.block_size)
        print(f"Pesan dari Client: {decrypted_message.decode()}")
    except ValueError:
        print("Error: Dekripsi pesan gagal.")
        await websocket.close()
        return
    
    reply = input("Masukkan balasan untuk Client: ").encode()
    encrypted_reply = des_cipher.encrypt(pad(reply, DES.block_size))
    await websocket.send(encrypted_reply.hex())  # Kirim sebagai hex string
    print("Balasan terenkripsi berhasil dikirim ke client.")

async def main():
    async with websockets.serve(handle_client, "localhost", 8765):
        print("Server berjalan di ws://localhost:8765")
        await asyncio.Future()  # Keep running forever

asyncio.run(main())
