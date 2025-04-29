import tkinter as tk
from tkinter import simpledialog, messagebox
import os
import json
import socketio
import time

sio = socketio.Client()
try:
    sio.connect('http://localhost:5000')
except Exception as e:
    print("서버 연결 실패:", e)

class MainScreen:
    active_instance = None

    def __init__(self, root, username):
        MainScreen.active_instance = self
        self.root = root
        self.username = username
        self.active_friend = None
        self.friends = []

        self.chat_logs = {}
        self.init_ui()
        self.load_friends()

    def init_ui(self):
        self.root.title(f"{self.username} - ZeroTalk")
        self.root.geometry("1000x600")

        self.left_frame = tk.Frame(self.root, bg="#2c2f33", width=200)
        self.left_frame.pack(side="left", fill="y")

        self.right_frame = tk.Frame(self.root, bg="#23272a")
        self.right_frame.pack(side="right", expand=True, fill="both")

        tk.Label(self.left_frame, text="친구 목록", bg="#2c2f33", fg="white", font=("Arial", 12)).pack(pady=10)

        self.friends_listbox = tk.Listbox(
            self.left_frame, bg="#2c2f33", fg="white",
            selectbackground="#7289da", font=("Arial", 11)
        )
        self.friends_listbox.pack(fill="both", expand=True, padx=10)
        self.friends_listbox.bind("<<ListboxSelect>>", self.select_friend)

        tk.Button(self.left_frame, text="친구 추가", command=self.add_friend).pack(pady=5)
        tk.Button(self.left_frame, text="친구 삭제", command=self.delete_friend).pack()

        self.chat_display = tk.Text(self.right_frame, bg="#1e1e1e", fg="white", font=("Arial", 12), state=tk.DISABLED)
        self.chat_display.pack(fill="both", expand=True, padx=10, pady=(10, 5))

        self.input_frame = tk.Frame(self.right_frame, bg="#2c2f33")
        self.input_frame.pack(fill="x", padx=10, pady=(0, 10))

        self.chat_entry = tk.Entry(self.input_frame, font=("Arial", 12))
        self.chat_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))

        send_btn = tk.Button(self.input_frame, text="전송", command=self.send_message)
        send_btn.pack(side="right")

    def add_friend(self):
        friend = simpledialog.askstring("친구 추가", "친구 이름을 입력하세요:")
        if friend and friend not in self.friends:
            self.friends.append(friend)
            self.save_friends()
            self.refresh_friend_list()

    def delete_friend(self):
        selected = self.friends_listbox.curselection()
        if selected:
            friend = self.friends_listbox.get(selected)
            self.friends.remove(friend)
            self.save_friends()
            self.refresh_friend_list()

    def load_friends(self):
        if os.path.exists("friends.json"):
            with open("friends.json", "r", encoding="utf-8") as f:
                try:
                    all_data = json.load(f)
                    self.friends = all_data.get(self.username, [])
                except:
                    self.friends = []
        self.refresh_friend_list()

    def save_friends(self):
        all_data = {}
        if os.path.exists("friends.json"):
            with open("friends.json", "r", encoding="utf-8") as f:
                try:
                    all_data = json.load(f)
                except:
                    all_data = {}
        all_data[self.username] = self.friends
        with open("friends.json", "w", encoding="utf-8") as f:
            json.dump(all_data, f, ensure_ascii=False, indent=4)

    def refresh_friend_list(self):
        self.friends_listbox.delete(0, tk.END)
        for friend in self.friends:
            self.friends_listbox.insert(tk.END, friend)

    def select_friend(self, event):
        selected = self.friends_listbox.curselection()
        if selected:
            self.active_friend = self.friends_listbox.get(selected)
            self.chat_display.config(state=tk.NORMAL)
            self.chat_display.delete(1.0, tk.END)
            if self.active_friend in self.chat_logs:
                for msg in self.chat_logs[self.active_friend]:
                    self.chat_display.insert(tk.END, msg + "\n")
            self.chat_display.config(state=tk.DISABLED)

    def send_message(self):
        msg = self.chat_entry.get().strip()
        if msg and self.active_friend:
            timestamp = time.strftime("%H:%M:%S")
            line = f"[{timestamp}] {self.username}: {msg}"

            if self.active_friend not in self.chat_logs:
                self.chat_logs[self.active_friend] = []
            self.chat_logs[self.active_friend].append(line)

            self.chat_display.config(state=tk.NORMAL)
            self.chat_display.insert(tk.END, line + "\n")
            self.chat_display.config(state=tk.DISABLED)
            self.chat_display.see(tk.END)
            self.chat_entry.delete(0, tk.END)

            try:
                sio.emit("send_message", {
                    "sender": self.username,
                    "receiver": self.active_friend,
                    "message": msg
                })
            except:
                print("서버 전송 오류")

@sio.on("receive_message")
def on_receive(data):
    app = MainScreen.active_instance
    sender = data["sender"]
    msg = data["message"]
    timestamp = time.strftime("%H:%M:%S")
    line = f"[{timestamp}] {sender}: {msg}"

    if sender not in app.chat_logs:
        app.chat_logs[sender] = []
    app.chat_logs[sender].append(line)

    if app.active_friend == sender:
        app.chat_display.config(state=tk.NORMAL)
        app.chat_display.insert(tk.END, line + "\n")
        app.chat_display.config(state=tk.DISABLED)
        app.chat_display.see(tk.END)
