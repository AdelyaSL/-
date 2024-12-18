import tkinter as tk
from tkinter import messagebox
import random

def generate_key(message):
    message_length = len(message)
    key = ''.join(random.choice('01') for _ in range(message_length * 8))
    return key

def text_to_binary(text):
    return ''.join(format(ord(c), '08b') for c in text)

def binary_to_text(binary_data):
    n = 8
    return ''.join(chr(int(binary_data[i:i + n], 2)) for i in range(0, len(binary_data), n))

def encrypt(message, key):
    message_binary = text_to_binary(message)

    # случайные числа для вероятностного шифрования
    random_numbers = ''.join(random.choice('01') for _ in range(len(message_binary)))

    # применение XOR
    encrypted_binary = ''.join(
        str(int(message_binary[i]) ^ int(key[i]) ^ int(random_numbers[i])) for i in range(len(message_binary)))

    encrypted_message = binary_to_text(encrypted_binary)
    return encrypted_message, random_numbers


def decrypt(encrypted_message, key, random_numbers):
    encrypted_binary = text_to_binary(encrypted_message)

    decrypted_binary = ''.join(
        str(int(encrypted_binary[i]) ^ int(key[i]) ^ int(random_numbers[i])) for i in range(len(encrypted_binary)))

    decrypted_message = binary_to_text(decrypted_binary)
    return decrypted_message


def on_encrypt():
    message = entry_message.get().strip()
    if message == "":
        messagebox.showerror("Ошибка", "Введите сообщение для шифрования")
        return

    key = entry_key.get().strip()
    if key == "":
        messagebox.showerror("Ошибка", "Сначала сгенерируйте ключ")
        return

    encrypted_message, random_numbers = encrypt(message, key)

    entry_result.delete("1.0", tk.END)
    entry_result.insert(tk.END, encrypted_message)

    global stored_random_numbers
    stored_random_numbers = random_numbers


def on_decrypt():
    encrypted_message = entry_message.get().strip()
    key = entry_key.get().strip()

    if encrypted_message == "" or key == "" or not stored_random_numbers:
        messagebox.showerror("Ошибка", "Введите зашифрованное сообщение и ключ")
        return

    try:
        decrypted_message = decrypt(encrypted_message, key, stored_random_numbers)
    except ValueError:
        messagebox.showerror("Ошибка", "Некорректный ключ для расшифровки")
        return

    entry_result.delete("1.0", tk.END)
    entry_result.insert(tk.END, decrypted_message)


def on_generate_key():
    message = entry_message.get().strip()
    if message == "":
        messagebox.showerror("Ошибка", "Введите сообщение для генерации ключа")
        return

    key = generate_key(message)
    entry_key.delete(0, tk.END)
    entry_key.insert(0, key)


root = tk.Tk()
root.title("Вероятностный шифр")
root.geometry("600x400")

label_message = tk.Label(root, text="Сообщение:")
label_message.pack()

entry_message = tk.Entry(root, width=70)
entry_message.pack()

button_generate_key = tk.Button(root, text="Сгенерировать ключ", command=on_generate_key)
button_generate_key.pack()

label_key = tk.Label(root, text="Ключ:")
label_key.pack()
entry_key = tk.Entry(root, width=70)
entry_key.pack()

button_encrypt = tk.Button(root, text="Зашифровать", command=on_encrypt)
button_encrypt.pack()

button_decrypt = tk.Button(root, text="Расшифровать", command=on_decrypt)
button_decrypt.pack()

label_result = tk.Label(root, text="Результат (зашифрованное/расшифрованное сообщение):")
label_result.pack()

entry_result = tk.Text(root, height=5, width=70)
entry_result.pack()

root.mainloop()
