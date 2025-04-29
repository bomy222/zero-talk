import tkinter as tk
from tkinter import simpledialog
import json
import os
import time
import socketio

sio = socketio.Client()

try:
    sio.connect('http://localhost:5000')
except Exception as e:
    print("서버 연결 실패:", e)

class MainScreen:
    active_instance = None

    def __init__(self, root, username):
      
        self.root = root
        self.username = username
        self.active_friend = None
        self.friends = []

        self.root.title(f"{username} - ZeroTalk")
        self.root.geometry("1000x600")

        self.setup_frames()
        self.setup_friend_list()
        self.setup_chat_display()
        self.load_friends()

    def setup_frames(self):
        self.left_frame = tk.Frame(self.root, bg="#202020", width=250)
        self.left_frame.pack(side="left", fill="y")

        self.right_frame = tk.Frame(self.root, bg="#1e1e1e")
        self.right_frame.pack(side="right", expand=True, fill="both")

    def setup_friend_list(self):
        tk.Label(self.left_frame, text="친구 목록", bg="#202020", fg="white", font=("Arial", 14)).pack(pady=10)

        self.friends_listbox = tk.Listbox(self.left_frame, bg="#2c2f33", fg="white",
                                          selectbackground="skyblue", font=("Arial", 12))
        self.friends_listbox.pack(padx=10, pady=5, fill="both", expand=True)
        self.friends_listbox.bind("<<ListboxSelect>>", self.select_friend)

        tk.Button(self.left_frame, text="친구 추가", command=self.add_friend).pack(pady=3)
        tk.Button(self.left_frame, text="친구 삭제", command=self.delete_friend).pack(pady=3)

    def setup_chat_display(self):
        self.chat_display = tk.Text(self.right_frame, bg="#1e1e1e", fg="white",
                                    font=("Arial", 12), wrap="word", state=tk.DISABLED)
        self.chat_display.pack(padx=10, pady=(10, 0), fill="both", expand=True)

        self.input_frame = tk.Frame(self.right_frame, bg="#1e1e1e")
        self.input_frame.pack(fill="x", padx=10, pady=10)

        self.chat_entry = tk.Entry(self.input_frame, font=("Arial", 12))
        self.chat_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))

        tk.Button(self.input_frame, text="전송", command=self.send_message).pack(side="right")

    def load_friends(self):
        if os.path.exists("friends.json"):
            try:
                with open("friends.json", "r", encoding="utf-8") as f:
                    all_data = json.load(f)
                    self.friends = all_data.get(self.username, [])
            except:
                self.friends = []
        else:
            self.friends = []
        self.refresh_friend_list()

    def save_friends(self):
        all_data = {}
        if os.path.exists("friends.json"):
            try:
                with open("friends.json", "r", encoding="utf-8") as f:
                    all_data = json.load(f)
            except:
                pass
        all_data[self.username] = self.friends
        with open("friends.json", "w", encoding="utf-8") as f:
            json.dump(all_data, f, ensure_ascii=False, indent=4)

    def refresh_friend_list(self):
        self.friends_listbox.delete(0, tk.END)
        for f in self.friends:
            self.friends_listbox.insert(tk.END, f)

    def add_friend(self):
        new_friend = simpledialog.askstring("친구 추가", "추가할 친구 ID:")
        if new_friend and new_friend not in self.friends:
            self.friends.append(new_friend)
            self.save_friends()
            self.refresh_friend_list()

    def delete_friend(self):
        sel = self.friends_listbox.curselection()
        if sel:
            target = self.friends_listbox.get(sel[0])
            if target in self.friends:
                self.friends.remove(target)
                self.save_friends()
                self.refresh_friend_list()
                if self.active_friend == target:
                    self.active_friend = None
                    self.chat_display.config(state=tk.NORMAL)
                    self.chat_display.delete(1.0, tk.END)
                    self.chat_display.config(state=tk.DISABLED)

    def select_friend(self, event):
        sel = self.friends_listbox.curselection()
        if sel:
            self.active_friend = self.friends_listbox.get(sel[0])
            self.display_chat_history()

    def send_message(self):
        msg = self.chat_entry.get().strip()
        if not msg or not self.active_friend:
            return

        now = time.strftime('%H:%M:%S')
        self.append_chat(self.username, msg, now)
        self.save_chat(self.username, self.active_friend, msg, now)

        try:
            sio.emit("send_message", {
                "sender": self.username,
                "receiver": self.active_friend,
                "message": msg,
                "timestamp": now
            })
        except:
            print("서버 전송 실패")

        self.chat_entry.delete(0, tk.END)

    def append_chat(self, sender, message, timestamp):
        self.chat_display.config(state=tk.NORMAL)
        label = "나" if sender == self.username else sender
        self.chat_display.insert(tk.END, f"{timestamp} | {label}: {message}\n")
        self.chat_display.config(state=tk.DISABLED)
        self.chat_display.see(tk.END)

    def save_chat(self, user, friend, msg, time_):
        path = f"chat_{user}_{friend}.json"
        chat = []
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    chat = json.load(f)
            except:
                pass
        chat.append({"sender": user, "message": msg, "time": time_})
        with open(path, "w", encoding="utf-8") as f:
            json.dump(chat, f, ensure_ascii=False, indent=4)

    def display_chat_history(self):
        self.chat_display.config(state=tk.NORMAL)
        self.chat_display.delete(1.0, tk.END)
        path = f"chat_{self.username}_{self.active_friend}.json"
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    history = json.load(f)
                    for entry in history:
                        self.chat_display.insert(tk.END, f"{entry['time']} | {entry['sender']}: {entry['message']}\n")
            except:
                pass
        self.chat_display.config(state=tk.DISABLED)
        self.chat_display.see(tk.END)

@sio.on("receive_message")
def on_receive(data):
    app = MainScreen.active_instance
    if not app:
        return
    if data["sender"] not in app.friends:
        app.friends.append(data["sender"])
        app.save_friends()
        app.refresh_friend_list()
    if app.active_friend == data["sender"]:
        app.append_chat(data["sender"], data["message"], data["timestamp"])
    app.save_chat(data["sender"], app.username, data["message"], data["timestamp"])
