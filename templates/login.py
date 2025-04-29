import tkinter as tk
from tkinter import messagebox
import json
import os
from templates.main_screen import MainScreen

class LoginScreen:
    def __init__(self, root):
        self.root = root
        self.root.title("ZeroTalk 로그인")
        self.root.geometry("400x300")

        tk.Label(root, text="아이디").pack()
        self.id_entry = tk.Entry(root)
        self.id_entry.pack()

        tk.Label(root, text="비밀번호").pack()
        self.pw_entry = tk.Entry(root, show="*")
        self.pw_entry.pack()

        tk.Button(root, text="로그인", command=self.login).pack(pady=10)

        self.load_users()

    def load_users(self):
        if not os.path.exists("user_data.json"):
            with open("user_data.json", "w") as f:
                json.dump({}, f)

        with open("user_data.json", "r") as f:
            self.users = json.load(f)

    def login(self):
        id_ = self.id_entry.get()
        pw = self.pw_entry.get()

        if id_ in self.users and self.users[id_] == pw:
            self.root.destroy()
            main = tk.Tk()
            MainScreen(main, id_)
            main.mainloop()
        else:
            messagebox.showerror("로그인 실패", "아이디 또는 비밀번호가 틀렸습니다.")
            self.save_log("로그인 실패", id_)

    def save_log(self, status, id_):
        import time
        log_file = "zerotalk_logs.json"
        log = {
            "status": status,
            "id": id_,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }

        logs = []
        if os.path.exists(log_file):
            with open(log_file, "r") as f:
                try:
                    logs = json.load(f)
                except json.JSONDecodeError:
                    logs = []

        logs.append(log)

        with open(log_file, "w") as f:
            json.dump(logs, f, ensure_ascii=False, indent=4)

# 웰컴 스크린
def open_welcome_screen(username):
    login_window.destroy()
    welcome_window = tk.Tk()
    welcome_window.title("ZeroTalk - 메인")
    welcome_window.geometry("400x600")
    welcome_window.configure(bg="black")

    label_welcome = tk.Label(welcome_window, text=f"Welcome, {username}!", font=("Helvetica", 20), fg="white", bg="black")
    label_welcome.pack(pady=50)

    button_exit = tk.Button(welcome_window, text="종료", font=("Helvetica", 14), bg="gray20", fg="white", command=welcome_window.destroy)
    button_exit.pack(pady=20)

    welcome_window.mainloop()

# 로그인 창 세팅
login_window = tk.Tk()
login_window.title("ZeroTalk - 로그인")
login_window.geometry("400x600")
login_window.configure(bg="black")

label_title = tk.Label(login_window, text="ZeroTalk", font=("Helvetica", 28, "bold"), fg="white", bg="black")
label_title.pack(pady=50)

frame_inputs = tk.Frame(login_window, bg="black")
frame_inputs.pack(pady=20)

label_username = tk.Label(frame_inputs, text="아이디", font=("Helvetica", 14), fg="white", bg="black")
label_username.grid(row=0, column=0, pady=10, sticky="w")
entry_username = tk.Entry(frame_inputs, font=("Helvetica", 14), width=20, bg="gray20", fg="white", insertbackground="white")
entry_username.grid(row=0, column=1, pady=10)

label_password = tk.Label(frame_inputs, text="비밀번호", font=("Helvetica", 14), fg="white", bg="black")
label_password.grid(row=1, column=0, pady=10, sticky="w")
entry_password = tk.Entry(frame_inputs, font=("Helvetica", 14), width=20, show="*", bg="gray20", fg="white", insertbackground="white")
entry_password.grid(row=1, column=1, pady=10)

frame_buttons = tk.Frame(login_window, bg="black")
frame_buttons.pack(pady=30)

button_login = tk.Button(frame_buttons, text="로그인", font=("Helvetica", 16), width=15, bg="deepskyblue", fg="white", command=login)
button_login.grid(row=0, column=0, pady=10)

button_register = tk.Button(frame_buttons, text="회원가입", font=("Helvetica", 16), width=15, bg="gray30", fg="white")
button_register.grid(row=1, column=0, pady=10)

login_window.mainloop()

import tkinter as tk
from tkinter import messagebox

# 로그인 데이터 (임시)
user_accounts = {
    "admin": "1234",
    "testuser": "abcd"
}

# 로그인 함수
def login():
    username = entry_username.get()
    password = entry_password.get()

    if username in user_accounts and user_accounts[username] == password:
        messagebox.showinfo("로그인 성공", f"{username}님 환영합니다!")
        open_welcome_screen(username)
    else:
        messagebox.showerror("로그인 실패", "아이디 또는 비밀번호가 올바르지 않습니다.")

# 웰컴 스크린
def open_welcome_screen(username):
    login_window.destroy()
    welcome_window = tk.Tk()
    welcome_window.title("ZeroTalk - 메인")
    welcome_window.geometry("400x600")
    welcome_window.configure(bg="black")

    label_welcome = tk.Label(welcome_window, text=f"Welcome, {username}!", font=("Helvetica", 20), fg="white", bg="black")
    label_welcome.pack(pady=50)

    button_exit = tk.Button(welcome_window, text="종료", font=("Helvetica", 14), bg="gray20", fg="white", command=welcome_window.destroy)
    button_exit.pack(pady=20)

    welcome_window.mainloop()

# 로그인 창 세팅
login_window = tk.Tk()
login_window.title("ZeroTalk - 로그인")
login_window.geometry("400x600")
login_window.configure(bg="black")

label_title = tk.Label(login_window, text="ZeroTalk", font=("Helvetica", 28, "bold"), fg="white", bg="black")
label_title.pack(pady=50)

frame_inputs = tk.Frame(login_window, bg="black")
frame_inputs.pack(pady=20)

label_username = tk.Label(frame_inputs, text="아이디", font=("Helvetica", 14), fg="white", bg="black")
label_username.grid(row=0, column=0, pady=10, sticky="w")
entry_username = tk.Entry(frame_inputs, font=("Helvetica", 14), width=20, bg="gray20", fg="white", insertbackground="white")
entry_username.grid(row=0, column=1, pady=10)

label_password = tk.Label(frame_inputs, text="비밀번호", font=("Helvetica", 14), fg="white", bg="black")
label_password.grid(row=1, column=0, pady=10, sticky="w")
entry_password = tk.Entry(frame_inputs, font=("Helvetica", 14), width=20, show="*", bg="gray20", fg="white", insertbackground="white")
entry_password.grid(row=1, column=1, pady=10)

frame_buttons = tk.Frame(login_window, bg="black")
frame_buttons.pack(pady=30)

button_login = tk.Button(frame_buttons, text="로그인", font=("Helvetica", 16), width=15, bg="deepskyblue", fg="white", command=login)
button_login.grid(row=0, column=0, pady=10)

button_register = tk.Button(frame_buttons, text="회원가입", font=("Helvetica", 16), width=15, bg="gray30", fg="white")
button_register.grid(row=1, column=0, pady=10)

def register_user(self):
    id_ = self.id_entry.get()
    pw = self.pw_entry.get()
    
    if not id_ or not pw:
        messagebox.showwarning("입력 오류", "아이디와 비밀번호를 모두 입력하세요.")
        return

    if id_ in self.users:
        messagebox.showerror("중복", "이미 존재하는 아이디입니다.")
        return

    self.users[id_] = pw
    with open("user_data.json", "w") as f:
        json.dump(self.users, f, indent=4)

    messagebox.showinfo("회원가입 성공", f"{id_}님 가입되었습니다.")
    
login_window.mainloop()

