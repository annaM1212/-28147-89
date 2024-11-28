import tkinter as tk
from tkinter import messagebox
import secrets

S_BOXES = [
    [0x9, 0x6, 0x3, 0x2, 0x8, 0xB, 0x1, 0x7, 0xA, 0x4, 0xE, 0xF, 0xC, 0x0, 0xD, 0x5],
    [0x3, 0x7, 0xE, 0x9, 0x8, 0xA, 0xF, 0x0, 0x5, 0x2, 0x6, 0xC, 0xB, 0x4, 0xD, 0x1],
    [0xE, 0x4, 0x6, 0x2, 0xB, 0x3, 0xD, 0x8, 0xC, 0xF, 0x5, 0xA, 0x0, 0x7, 0x1, 0x9],
    [0xE, 0x7, 0xA, 0xC, 0xD, 0x1, 0x3, 0x9, 0x0, 0x2, 0xB, 0x4, 0xF, 0x8, 0x5, 0x6],
    [0xB, 0x5, 0x1, 0x9, 0x8, 0xD, 0xF, 0x0, 0xE, 0x4, 0x2, 0x3, 0xC, 0x7, 0xA, 0x6],
    [0x3, 0xA, 0xD, 0xC, 0x1, 0x2, 0x0, 0xB, 0x7, 0x5, 0x9, 0x4, 0x8, 0xF, 0xE, 0x6],
    [0x1, 0xD, 0x2, 0x9, 0x7, 0xA, 0x6, 0x0, 0x8, 0xC, 0x4, 0x5, 0xF, 0x3, 0xB, 0xE],
    [0xB, 0xA, 0xF, 0x5, 0x0, 0xC, 0xE, 0x8, 0x6, 0x2, 0x3, 0x9, 0x1, 0x7, 0xD, 0x4]
]

def substitute(value):
    result = 0
    for i in range(8):
        nibble = (value >> (4 * i)) & 0xF
        result |= S_BOXES[i][nibble] << (4 * i)
    return result

def rotate_left(value, shift, size=32):
    return ((value << shift) | (value >> (size - shift))) & ((1 << size) - 1)

def f(block, key):
    temp = (block + key) % (2**32)
    substituted = substitute(temp)
    return rotate_left(substituted, 11)

def generate_keys(master_key):
    key_parts = [(master_key >> (32 * i)) & 0xFFFFFFFF for i in range(8)]
    return key_parts

def encrypt_block(left, right, keys):
    for i in range(16):
        round_key = keys[i % 8]
        temp = f(right, round_key)
        left, right = right, left ^ temp
    return right, left

def encrypt_message(message, key):
    master_key = int.from_bytes(key, 'big')
    keys = generate_keys(master_key)

    message = message.encode('utf-8')
    if len(message) % 8 != 0:
        message += b'\x00' * (8 - len(message) % 8)

    encrypted = []
    for i in range(0, len(message), 8):
        block = message[i:i + 8]
        left = int.from_bytes(block[:4], 'big')
        right = int.from_bytes(block[4:], 'big')
        left, right = encrypt_block(left, right, keys)
        encrypted.append(left.to_bytes(4, 'big') + right.to_bytes(4, 'big'))
    return b''.join(encrypted).hex()

def generate_key():
    return secrets.token_bytes(32)

def on_generate_key():
    global generated_key
    generated_key = generate_key()
    key_label.config(text=f"Сгенерированный ключ: {generated_key.hex()}")

def on_encrypt():
    message = entry.get()
    if not generated_key:
        result_label.config(text="Сначала сгенерируйте ключ!")
        return
    encrypted_message = encrypt_message(message, generated_key)
    result_label.config(text=f"Зашифрованное сообщение: {encrypted_message}")

def on_closing():
    root.destroy()

root = tk.Tk()
root.title("Шифрование ГОСТ 28147-89")
root.protocol("WM_DELETE_WINDOW", on_closing)
root.geometry("600x400")

generated_key = None

label = tk.Label(root, text="Введите сообщение:")
label.pack(pady=10)

entry = tk.Entry(root, width=50)
entry.pack(pady=5)

generate_key_button = tk.Button(root, text="Сгенерировать ключ", command=on_generate_key)
generate_key_button.pack(pady=10)

key_label = tk.Label(root, text="Сгенерированный ключ: ")
key_label.pack(pady=10)

encrypt_button = tk.Button(root, text="Зашифровать", command=on_encrypt)
encrypt_button.pack(pady=10)

result_label = tk.Label(root, text="", wraplength=500)
result_label.pack(pady=20)

root.mainloop()