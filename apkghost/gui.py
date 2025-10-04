import customtkinter as ctk
from .controller import Controller

def launch_gui():
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
    app = ctk.CTk()
    app.title("APK Ghost")
    app.geometry("1000x700")
    ctrl = Controller(app)
    app.mainloop()
