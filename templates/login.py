import tkinter as tk
from tkinter import messagebox
import json
import os
import random
import string

from security import (
    is_ip_blocked, register_failed_attempt, reset_ip_attempt,
    detect_device_change, validate_token
    )
import socket

from templates.main_screen import MainScreen


class LoginScreen:
    def __init__(self, root):
        self.root = root
        self.root.title("ZeroTalk 로그인")
        self.root.geometry("400x450")
        self.root.configure(bg="black")

        self.users = self.load_users()

        # ID 입력
        tk.Label(root, text="아이디", font=("Helvetica", 14), bg="black", fg="white").pack(pady=5)
        self.id_entry = tk.Entry(root, font=("Helvetica", 14), bg="gray20", fg="white", insertbackground="white")
        self.id_entry.pack(pady=5)

        # PW 입력
        tk.Label(root, text="비밀번호", font=("Helvetica", 14), bg="black", fg="white").pack(pady=5)
        self.pw_entry = tk.Entry(root, show="*", font=("Helvetica", 14), bg="gray20", fg="white", insertbackground="white")
        self.pw_entry.pack(pady=5)

        # 토큰 선택 여부
        self.use_token_var = tk.BooleanVar()
        self.token_checkbox = tk.Checkbutton(root, text="토큰 키 사용", variable=self.use_token_var, bg="black", fg="white", selectcolor="black", activebackground="black", command=self.toggle_token_entry)
        self.token_checkbox.pack(pady=5)

        # 토큰 키 입력 (처음엔 숨김)
        self.token_label = tk.Label(root, text="토큰 키", font=("Helvetica", 14), bg="black", fg="white")
        self.token_entry = tk.Entry(root, show="*", font=("Helvetica", 14), bg="gray20", fg="white", insertbackground="white")

        # 버튼 영역
        tk.Button(root, text="로그인", font=("Helvetica", 14), bg="deepskyblue", fg="white", command=self.login).pack(pady=10)
        tk.Button(root, text="회원가입", font=("Helvetica", 14), bg="gray30", fg="white", command=self.register_user).pack(pady=5)

        self.root.bind('<Return>', lambda e: self.login())

    def toggle_token_entry(self):
        if self.use_token_var.get():
            self.token_label.pack()
            self.token_entry.pack()
        else:
            self.token_label.pack_forget()
            self.token_entry.pack_forget()

    def load_users(self):
        if not os.path.exists("user_data.json"):
            with open("user_data.json", "w") as f:
                json.dump({}, f)
        with open("user_data.json", "r") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}

    def login(self):
        id_ = self.id_entry.get()
        pw = self.pw_entry.get()
        token = self.token_entry.get() if self.use_token_var.get() else ""

        if id_ in self.users:
            user_info = self.users[id_]
            if user_info["password"] == pw:
                if "token_key" in user_info and self.use_token_var.get():
                    if user_info["token_key"] != token:
                        messagebox.showerror("로그인 실패", "토큰 키가 틀렸습니다.")
                        self.save_log("토큰 인증 실패", id_)
                        return
                messagebox.showinfo("로그인 성공", f"{id_}님 환영합니다!")
                self.save_log("로그인 성공", id_)
                self.open_welcome_screen(id_)
                return
            else:
                self.save_log("비밀번호 오류", id_)
        else:
            self.save_log("아이디 없음", id_)

        messagebox.showerror("로그인 실패", "아이디 또는 비밀번호가 틀렸습니다.")

    def register_user(self):
        id_ = self.id_entry.get()
        pw = self.pw_entry.get()

        if not id_ or not pw:
            messagebox.showwarning("입력 오류", "아이디와 비밀번호를 입력하세요.")
            return

        if id_ in self.users:
            messagebox.showerror("중복", "이미 존재하는 아이디입니다.")
            return

        if self.use_token_var.get():
            token = self.generate_token_key()
            self.users[id_] = {
                "password": pw,
                "token_key": token
            }
            messagebox.showinfo("회원가입 완료", f"{id_}님 가입되었습니다.\n발급된 토큰: {token}")
        else:
            self.users[id_] = {
                "password": pw
            }
            messagebox.showinfo("회원가입 완료", f"{id_}님 가입되었습니다.")
            sio.emit("register", {"username": id_})
            
        with open("user_data.json", "w") as f:
            json.dump(self.users, f, indent=4)

    def save_log(self, status, id_):
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

    def generate_token_key(self, length=10):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def open_welcome_screen(self, username):
        welcome_window = tk.Tk()
        welcome_window.title("ZeroTalk - 메인")
        welcome_window.geometry("400x600")
        welcome_window.configure(bg="black")

        tk.Label(
            welcome_window,
            text=f"Welcome, {username}!",
            font=("Helvetica", 20),
            fg="white",
            bg="black"
        ).pack(pady=50)

        tk.Button(
            welcome_window,
            text="종료",
            font=("Helvetica", 14),
            bg="gray20",
            fg="white",
            command=welcome_window.destroy
        ).pack(pady=20)

        welcome_window.mainloop()

# 실행부
if __name__ == "__main__":
    root = tk.Tk()
    app = LoginScreen(root)
    root.mainloop()