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
        MainScreen.active_instance = self
        self.root = root
        self.username = username
        self.active_friend = None
        self.friends = []
        self.chat_rooms = {}  # 친구별 채팅기록
        self.theme_mode = "dark"
        self.rooms = {}  # 단톡방 이름: 메시지 목록
        self.active_room = None

        self.root.title(f"{username} - ZeroTalk")
        self.root.geometry("1000x600")

        self.setup_menu()
        self.setup_frames()
        self.setup_friend_list()
        self.setup_chat_display()
        self.load_friends()

    def on_close(self):
        self.save_room_chats()
        self.root.destroy()

    def setup_menu(self):
        menubar = tk.Menu(self.root)
        mode_menu = tk.Menu(menubar, tearoff=0)
        mode_menu.add_command(label="다크 모드", command=lambda: self.set_theme("dark"))
        mode_menu.add_command(label="라이트 모드", command=lambda: self.set_theme("light"))
        menubar.add_cascade(label="모드 선택", menu=mode_menu)
        self.root.config(menu=menubar)

    def set_theme(self, mode):
        self.theme_mode = mode
        bg = "#1e1e1e" if mode == "dark" else "white"
        fg = "white" if mode == "dark" else "black"

        self.left_frame.config(bg=bg)
        self.right_frame.config(bg=bg)
        self.chat_display.config(bg=bg, fg=fg)
        self.input_frame.config(bg=bg)
        self.chat_entry.config(bg="white" if mode == "light" else "#2c2f33", fg=fg)

    def setup_frames(self):
    # 왼쪽 프레임 (친구 목록 + 단톡방 목록)
        self.left_frame = tk.Frame(self.root, bg="#202020", width=250)
        self.left_frame.pack(side="left", fill="y")

    # 오른쪽 프레임 (채팅창)
        self.right_frame = tk.Frame(self.root, bg="#1e1e1e")
        self.right_frame.pack(side="right", expand=True, fill="both")

    # 친구 목록 UI
        tk.Label(self.left_frame, text="친구 목록", bg="#202020", fg="white", font=("Arial", 14)).pack(pady=(10, 0))
        self.friends_listbox = tk.Listbox(
        self.left_frame,
        bg="#2c2f33",
        fg="white",
        selectbackground="skyblue",
        font=("Arial", 12)
        )
        self.friends_listbox.pack(padx=10, pady=5, fill="both", expand=True)
        self.friends_listbox.bind("<<ListboxSelect>>", self.select_friend)

        tk.Button(self.left_frame, text="친구 추가", command=self.add_friend).pack(pady=3)
        tk.Button(self.left_frame, text="친구 삭제", command=self.delete_friend).pack(pady=3)

    # 단톡방 목록 UI (신규)
        tk.Label(self.left_frame, text="단톡방 목록", bg="#202020", fg="white", font=("Arial", 14)).pack(pady=(15, 0))
        self.room_listbox = tk.Listbox(
        self.left_frame,
        bg="#2c2f33",
        fg="white",
        height=6,
        selectbackground="orange",
        font=("Arial", 12)
        )
        self.room_listbox.pack(padx=10, pady=5, fill="both")
        self.room_listbox.bind("<<ListboxSelect>>", self.select_room)

        tk.Button(self.left_frame, text="단톡방 생성", command=self.create_room).pack(pady=3)
        tk.Button(self.left_frame, text="단톡방 삭제", command=self.delete_room).pack(pady=3)

    def setup_chat_display(self):
        self.chat_display = tk.Text(
            self.right_frame,
            bg="#1e1e1e", fg="white",
            font=("Arial", 12),
            wrap="word", state=tk.DISABLED
        )
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

    # 단톡방 메시지 처리 먼저
        if self.active_room:
            self.send_room_message(msg)
            return  # 단톡방 메시지 전송 후 종료

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
    
    def save_room_chats(self):
        for room, chats in self.chat_rooms.items():
            path = f"chat_room_{room}.json"
        with open(path, "w", encoding="utf-8") as f:
                json.dump(chats, f, ensure_ascii=False, indent=4)

    def load_room_chats(self):
        import glob
        for filename in glob.glob("chat_room_*.json"):
            room = filename.replace("chat_room_", "").replace(".json", "")
            try:
                with open(filename, "r", encoding="utf-8") as f:
                self.chat_rooms[room] = json.load(f)
            except:
                self.chat_rooms[room] = []
                self.refresh_room_list()

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

    if "room" in data:
        # 단톡 메시지 처리
        room = data["room"]
        if room not in app.chat_rooms:
            app.chat_rooms[room] = []
        app.chat_rooms[room].append({
            "sender": data["sender"],
            "message": data["message"],
            "time": data["timestamp"]
        })
        if app.active_room == room:
            app.display_room_chat()
        return  # 개인 메시지와 겹치지 않게 종료

    # 개인 메시지 처리
    if data["sender"] not in app.friends:
        app.friends.append(data["sender"])
        app.save_friends()
        app.refresh_friend_list()

    if app.active_friend == data["sender"]:
        app.append_chat(data["sender"], data["message"], data["timestamp"])

        app.save_chat(data["sender"], app.username, data["message"], data["timestamp"])

    def create_room(self):
        name = simpledialog.askstring("단톡방 생성", "방 이름 입력:")
        if name and name not in self.chat_rooms:
            self.chat_rooms[name] = []
            self.room_listbox.insert(tk.END, name)

    def delete_room(self):
        sel = self.room_listbox.curselection()
        if sel:
            room = self.room_listbox.get(sel[0])
            if room in self.chat_rooms:
                del self.chat_rooms[room]
                self.room_listbox.delete(sel[0])
                if self.active_room == room:
                    self.active_room = None
                    self.chat_display.config(state=tk.NORMAL)
                    self.chat_display.delete(1.0, tk.END)
                    self.chat_display.config(state=tk.DISABLED)

    def select_room(self, event):
        sel = self.room_listbox.curselection()
        if sel:
            self.active_room = self.room_listbox.get(sel[0])
            self.display_room_chat()

    def display_room_chat(self):
        self.chat_display.config(state=tk.NORMAL)
        self.chat_display.delete(1.0, tk.END)
        if self.active_room and self.active_room in self.chat_rooms:
            for entry in self.chat_rooms[self.active_room]:
                self.chat_display.insert(tk.END, f"{entry['time']} | {entry['sender']}: {entry['message']}\n")
        self.chat_display.config(state=tk.DISABLED)

    def send_room_message(self, msg):
        if not msg or not self.active_room:
            return
        now = time.strftime('%H:%M:%S')
        self.rooms[self.active_room].append({
            "sender": self.username,
            "message": msg,
            "time": now
            })
        self.display_room_chat()

        try:
            sio.emit("broadcast_room_message", {
                "room": self.active_room,
                "sender": self.username,
                "message": msg,
                "timestamp": now
                })
        except:
            print("단톡방 서버 전송 실패")
    
    # 서버에 전송
        try:
            sio.emit("send_message", {
                "room": self.active_room,
                "sender": self.username,
                "message": msg,
                "timestamp": now
                })
        except:
            print("단톡 서버 전송 실패")
    def on_close(self):
        self.save_room_chats()
        self.root.destroy()