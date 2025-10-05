import customtkinter as ctk
from .controller import Controller

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Apkghost - Analysis Toolkit")
        self.geometry("1200x800")
        self.minsize(900, 700)
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")
        self.controller = Controller(self)

def launch():
    app = App()
    app.mainloop()