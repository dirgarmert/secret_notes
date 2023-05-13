import tkinter
from tkinter import *
from PIL import ImageTk, Image
from tkinter import messagebox
import base64


def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()


def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)


def save_and_encrypt():
    x = enter_your_title.get()
    text = input_text.get("1.0", END)
    master_secret_key = enter_master_key.get()

    if len(x) == 0 or len(text) == 0 or len(master_secret_key) == 0:
        messagebox.showwarning(title="EROR!", message="Hepsine yazı girmelisin")
    else:
        message_encrypted = encode(master_secret_key, text)
        try:
            with open("mysecret.txt", "a") as data_file:
                data_file.write(f"\n{x}\n{message_encrypted}")
        except FileNotFoundError:
            with open("mysecret.txt", "w") as data_file:
                data_file.write(f"\n{x}\n{message_encrypted}")
        finally:
            enter_your_title.delete(0, END)
            input_text.delete("1.0", END)
            enter_master_key.delete(0, END)


def decrypted_notes():
    message_encrypted = input_text.get("1.0", END)
    master_secret_key = enter_master_key.get()
    if len(message_encrypted) == 0 or len(master_secret_key) == 0:
        messagebox.showwarning(title="EROR!", message="Hepsine yazı girmelisin")
    else:
        try:
            decrypted_messages = decode(master_secret_key, message_encrypted)
            input_text.delete("1.0", END)
            input_text.insert("1.0", decrypted_messages)
        except:
            messagebox.showwarning(title="EROR!", message="KODUN YOK MUYDU SENİN")


window = tkinter.Tk()
p1 = PhotoImage(file="png.png")
window.iconphoto(False, p1)
window.config(padx=40, pady=40)
window.title("Secret Notes")
window.config(height=4000, width=4000)
window.config(padx=10, pady=10)
photo = PhotoImage(file="png.png")
img = ImageTk.PhotoImage(Image.open("png.png"))
photo_1 = Label(window, image=img, )
photo_1.config(padx=15, pady=15, height=50, width=60)
photo_1.pack()
title_label = tkinter.Label(text="Enter your Title", font=("Verdana", 12, "bold"))
title_label.config(padx=5, pady=5)
title_label.pack()
enter_your_title = tkinter.Entry()
enter_your_title.pack()
label_3 = tkinter.Label(text="Enter your secret", font=("Verdana", 12, "bold"))
label_3.config(padx=5, pady=5)
label_3.pack()
input_text = Text()
input_text.config(width=30, height=15)
input_text.pack()
master_label = tkinter.Label(text="Enter your Master Key", font=("Verdana", 12, "bold"))
master_label.config(padx=5, pady=5)
master_label.pack()
enter_master_key = tkinter.Entry()
enter_master_key.pack()
save_and_enc_button = tkinter.Button(width=12, height=1, text="Save and Encrypt", font=("Comic Sans MS", 10, "normal"),
                                     command=save_and_encrypt)
save_and_enc_button.config(padx=5, pady=5)
save_and_enc_button.pack()
decrypt_button = tkinter.Button(width=12, height=1, text="Decrypt", font=("Comic Sans MS", 10, "normal"),
                                command=decrypted_notes)
decrypt_button.pack()
window.mainloop()
