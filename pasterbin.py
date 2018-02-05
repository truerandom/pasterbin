import base64

from Tkinter import *
from Crypto import Random
from Crypto.Cipher import AES

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-ord(s[-1])]

class App:
  def __init__(self, master):
    frame = Frame(master)
    frame.pack()

    def retrieve_input(campo):
        return campo.get("1.0",END)

    def cryptdecrypt(self,clave,texto,opcion):
        cipher = AESCipher(pad(retrieve_input(clave)))
        msg = ''
        texxt = retrieve_input(texto)
        if(opcion == 0):
            msg = cipher.encrypt(texxt)
        else:
            msg = cipher.decrypt(texxt)
        texto.delete("1.0",END)
        texto.insert(END,msg)
    lambda: cryptdecrypt()

    texto = Text(frame, height=20, width=100)
    scroll = Scrollbar(frame, command=texto.yview)
    texto.configure(yscrollcommand=scroll.set)

    clave = Text(frame, height=1, width=60)

    self.encrypt = Button(frame,
                         text="encrypt",
                         command= lambda: cryptdecrypt('',clave,texto,0)
                         )
    self.encrypt.pack(side=LEFT)

    self.decrypt = Button(frame,
                         text="decrypt",
                         command= lambda: cryptdecrypt('',clave,texto,1)
                         )
    self.decrypt.pack(side=LEFT)

    clave.pack()
    texto.pack(side=LEFT)
    scroll.pack(side=RIGHT, fill=Y)

class AESCipher:

    def __init__( self, key ):
        self.key = key

    def encrypt( self, raw ):
        raw = pad(raw)
        iv = Random.new().read( AES.block_size )
        cipher = AES.new( self.key, AES.MODE_CBC, iv )
        return base64.b64encode( iv + cipher.encrypt( raw ) )

    def decrypt( self, enc ):
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv )
        return unpad(cipher.decrypt( enc[16:] ))

root = Tk()
root.wm_title("PASTERBIN")
app = App(root)
root.mainloop()
