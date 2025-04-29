import tkinter as tk
from tkinter import messagebox
import json
import os
import socketio
import time

sio = socketio.Client()
sio.connect('http://localhost:5000')  # 서버 주소 수정 가능

class MainScreen:
    def __init__(self, master, username):
        self.master = master
        self.username = username
        self.active_friend = None
        self.friends = []
        self.friend_buttons = {}
        self.chat_logs = {}  # 친구별 채팅 기록

        self.master.title(f"{username}님 ZeroTalk에 오신 것을 환영합니다")
        self.master.geometry("1000x600")

        self.create_frames()
        self.create_friend_list_area()
        self.create_chat_area()
        self.load_friends()

    def create_frames(self):
        self.left_frame = tk.Frame(self.master, width=250, bg="#202020")
        self.left_frame.pack(side="left", fill="y")

        self.right_frame = tk.Frame(self.master, bg="#1e1e1e")
        self.right_frame.pack(side="right", fill="both", expand=True)

    def create_friend_list_area(self):
        title = tk.Label(self.left_frame, text="친구 목록", bg="#202020", fg="white", font=("Helvetica", 14))
        title.pack(pady=10)

        self.friend_list_frame = tk.Frame(self.left_frame, bg="#202020")
        self.friend_list_frame.pack(fill="both", expand=True)

        self.friend_entry = tk.Entry(self.left_frame)
        self.friend_entry.pack(padx=10, pady=5)

        btn_add = tk.Button(self.left_frame, text="친구 추가", command=self.add_friend)
        btn_add.pack(padx=10, pady=5)

        btn_del = tk.Button(self.left_frame, text="친구 삭제", command=self.delete_selected_friend)
        btn_del.pack(padx=10, pady=5)

    def create_chat_area(self):
        self.chat_display = tk.Text(
            self.right_frame,
            bg="#1e1e1e",
            fg="white",
            font=("Helvetica", 12),
            state=tk.DISABLED,
            wrap="word"
        )
        self.chat_display.pack(fill="both", expand=True, padx=10, pady=(10, 5))

        self.chat_input_frame = tk.Frame(self.right_frame, bg="#1e1e1e")
        self.chat_input_frame.pack(fill="x", padx=10, pady=(0, 10))

        self.chat_entry = tk.Entry(self.chat_input_frame, font=("Helvetica", 12))
        self.chat_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))

        send_btn = tk.Button(self.chat_input_frame, text="전송", command=self.send_message)
        send_btn.pack(side="right")

    def send_message(self):
        message = self.chat_entry.get().strip()
        if not message or not self.active_friend:
            return

        data = {
            "sender": self.username,
            "receiver": self.active_friend,
            "message": message,
            "timestamp": time.strftime("%H:%M:%S")
        }

        sio.emit("send_message", data)
        self.append_chat(self.username, message)
        self.chat_entry.delete(0, tk.END)

    def append_chat(self, sender, message):
        self.chat_display.config(state=tk.NORMAL)
        self.chat_display.insert(tk.END, f"{sender}: {message}\n")
        self.chat_display.config(state=tk.DISABLED)
        self.chat_display.see(tk.END)

@sio.on('receive_message')
def on_receive(data):
    # 이 부분은 실시간 수신처리
    app = MainScreen.active_instance
    if app.active_friend == data["sender"]:
        app.append_chat(data["sender"], data["message"])

    # SocketIO 실시간 채팅 클라이언트
import socketio

sio = socketio.Client()

try:
    sio.connect('http://localhost:5000')
except Exception as e:
    print("서버 연결 실패:", e)

@sio.on('receive_message')
def on_receive(data):
    message = f"{data['user']}: {data['message']}"
    try:
        self.chat_display.config(state=tk.NORMAL)
        self.chat_display.insert(tk.END, message + "\n")
        self.chat_display.config(state=tk.DISABLED)
        self.chat_display.see(tk.END)
    except:
        pass  # 아직 chat_display가 없을 때 대비

class MainScreen:
    active_instance = None  # SocketIO에서 접근 위해 클래스 변수로 등록

    def __init__(self, root, username):
        MainScreen.active_instance = self  # socketio 핸들링을 위해
        self.root = root
        self.username = username
        self.active_friend = None

        self.root.title(f"{username}님 - ZeroTalk")
        self.root.geometry("800x500")

        self.left_frame = tk.Frame(self.root, bg='#2c2f33', width=200)
        self.left_frame.pack(side="left", fill="y")

        self.right_frame = tk.Frame(self.root, bg='#23272a')
        self.right_frame.pack(side="right", expand=True, fill="both")

        self.friends_listbox = tk.Listbox(
            self.left_frame, bg="#2c2f33", fg="white",
            selectbackground="skyblue", font=("Helvetica", 12)
        )
        self.friends_listbox.pack(pady=10, padx=10, fill="y", expand=True)
        self.friends_listbox.bind("<<ListboxSelect>>", self.select_friend)

        add_btn = tk.Button(self.left_frame, text="친구 추가", command=self.add_friend)
        add_btn.pack(pady=(0, 5))

        del_btn = tk.Button(self.left_frame, text="친구 삭제", command=self.delete_friend)
        del_btn.pack()

        self.create_chat_area()
        self.load_friends()
    
    def send_message(self):
    message = self.chat_entry.get()
    if message.strip() == "":
        return

    # 채팅창에 내 메시지 표시
    self.chat_display.config(state=tk.NORMAL)
    self.chat_display.insert(tk.END, f"나: {message}\n")
    self.chat_display.config(state=tk.DISABLED)
    self.chat_display.see(tk.END)

    # 서버로 메시지 전송
    try:
        sio.emit('send_message', {
            'user': self.username,
            'message': message
        })
    except Exception as e:
        print("서버 전송 오류:", e)

    self.chat_entry.delete(0, tk.END)
    def load_friends(self):
        self.friends = []
        if os.path.exists("friends.json"):
            with open("friends.json", "r", encoding="utf-8") as f:
                try:
                    all_data = json.load(f)
                    self.friends = all_data.get(self.username, [])
                except json.JSONDecodeError:
                    self.friends = []

        self.refresh_friend_list()

    def save_friends(self):
        all_data = {}
        if os.path.exists("friends.json"):
            with open("friends.json", "r", encoding="utf-8") as f:
                try:
                    all_data = json.load(f)
                except json.JSONDecodeError:
                    all_data = {}

        all_data[self.username] = self.friends

        with open("friends.json", "w", encoding="utf-8") as f:
            json.dump(all_data, f, ensure_ascii=False, indent=4)

    def refresh_friend_list(self):
        self.friends_listbox.delete(0, tk.END)
        for friend in self.friends:
            self.friends_listbox.insert(tk.END, friend)

    def add_friend(self):
        new_friend = tk.simpledialog.askstring("친구 추가", "추가할 친구 이름:")
        if new_friend and new_friend not in self.friends:
            self.friends.append(new_friend)
            self.save_friends()
            self.refresh_friend_list()

    def delete_friend(self):
        selected = self.friends_listbox.curselection()
        if selected:
            friend = self.friends_listbox.get(selected)
            if friend in self.friends:
                self.friends.remove(friend)
                self.save_friends()
                self.refresh_friend_list()

    def select_friend(self, event):
        selected = self.friends_listbox.curselection()
        if selected:
            self.active_friend = self.friends_listbox.get(selected)
            self.chat_display.config(state=tk.NORMAL)
            self.chat_display.insert(tk.END, f"--- {self.active_friend}님과의 대화 시작 ---\n")
            self.chat_display.config(state=tk.DISABLED)

    def create_chat_area(self):
        # 채팅 출력 창
        self.chat_display = tk.Text(self.right_frame, bg='#1e1e1e', fg='white',
                                    font=("Helvetica", 12), wrap="word")
        self.chat_display.pack(padx=10, pady=10, fill="both", expand=True)
        self.chat_display.config(state=tk.DISABLED)

        # 채팅 입력창
        self.input_entry = tk.Entry(self.right_frame, font=("Helvetica", 12))
        self.input_entry.pack(fill='x', padx=10, pady=(0, 5))
        self.input_entry.bind("<Return>", self.send_message)

        # 전송 버튼
        send_btn = tk.Button(self.right_frame, text="전송", command=self.send_message)
        send_btn.pack(pady=(0, 10))

    def send_message(self, event=None):
        message = self.input_entry.get().strip()
        if not message or not self.active_friend:
            return

        full_msg = f"{self.username}: {message}\n"
        self.append_chat(full_msg)
        self.save_chat(self.active_friend, full_msg)
        self.input_entry.delete(0, tk.END)

    def append_chat(self, message):
        self.chat_display.config(state=tk.NORMAL)
        self.chat_display.insert(tk.END, message)
        self.chat_display.config(state=tk.DISABLED)
        self.chat_display.see(tk.END)

    def save_chat(self, friend_name, message):
        file_path = f"chat_{self.username}_{friend_name}.json"
        chats = []
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as f:
                try:
                    chats = json.load(f)
                except json.JSONDecodeError:
                    chats = []

        chats.append({"user": self.username, "message": message.strip()})

        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(chats, f, ensure_ascii=False, indent=4)

    def load_chat(self, friend_name):
        file_path = f"chat_{self.username}_{friend_name}.json"
        self.chat_display.config(state=tk.NORMAL)
        self.chat_display.delete(1.0, tk.END)

        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as f:
                try:
                    chats = json.load(f)
                    for chat in chats:
                        msg = f"{chat['user']}: {chat['message']}\n"
                        self.chat_display.insert(tk.END, msg)
                except json.JSONDecodeError:
                    self.chat_display.insert(tk.END, "(이전 채팅 불러오기 실패)\n")

        self.chat_display.config(state=tk.DISABLED)

    def select_friend(self, event):
        selected = self.friends_listbox.curselection()
        if selected:
            self.active_friend = self.friends_listbox.get(selected)
            self.load_chat(self.active_friend)

    import tkinter as tk from tkinter import messagebox import json import os import time

class MainScreen: def init(self, root, username): self.root = root self.username = username self.active_friend = None

self.root.title(f"{username}님 - ZeroTalk")
    self.root.geometry("800x500")
    self.root.configure(bg='#1e1e1e')

    self.left_frame = tk.Frame(self.root, width=200, bg='#252526')
    self.left_frame.pack(side="left", fill="y")

    self.right_frame = tk.Frame(self.root, bg='#1e1e1e')
    self.right_frame.pack(side="right", expand=True, fill="both")

    self.friends_label = tk.Label(self.left_frame, text="친구 목록", fg='white', bg='#252526', font=("Arial", 12))
    self.friends_label.pack(pady=10)

    self.friends_listbox = tk.Listbox(self.left_frame, bg='#1e1e1e', fg='white', selectbackground='#007acc')
    self.friends_listbox.pack(fill="both", expand=True, padx=10, pady=5)
    self.friends_listbox.bind("<<ListboxSelect>>", self.select_friend)

    self.friend_entry = tk.Entry(self.left_frame)
    self.friend_entry.pack(pady=5, padx=10, fill="x")

    self.add_button = tk.Button(self.left_frame, text="+ 친구 추가", command=self.add_friend)
    self.add_button.pack(pady=5, padx=10, fill="x")

    self.delete_button = tk.Button(self.left_frame, text="- 삭제", command=self.delete_friend)
    self.delete_button.pack(pady=5, padx=10, fill="x")

    self.chat_display = tk.Text(self.right_frame, bg='#1e1e1e', fg='white', wrap="word",
                                 font=("Helvetica", 12), state=tk.DISABLED)
    self.chat_display.pack(padx=10, pady=10, fill="both", expand=True)

    self.input_frame = tk.Frame(self.right_frame, bg='#2d2d30')
    self.input_frame.pack(fill="x", padx=10, pady=5)

    self.input_entry = tk.Entry(self.input_frame, font=("Helvetica", 12))
    self.input_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
    self.input_entry.bind("<Return>", self.send_message)

    self.send_button = tk.Button(self.input_frame, text="전송", command=self.send_message)
    self.send_button.pack(side="right")

    self.load_friends()

def add_friend(self):
    name = self.friend_entry.get().strip()
    if name and name not in self.friends_listbox.get(0, tk.END):
        self.friends_listbox.insert(tk.END, name)
        self.save_friends()
        self.friend_entry.delete(0, tk.END)

def delete_friend(self):
    selected = self.friends_listbox.curselection()
    if selected:
        self.friends_listbox.delete(selected)
        self.save_friends()
        self.chat_display.config(state=tk.NORMAL)
        self.chat_display.delete(1.0, tk.END)
        self.chat_display.config(state=tk.DISABLED)
        self.active_friend = None

def load_friends(self):
    path = f"friends_{self.username}.json"
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            try:
                friends = json.load(f)
                for friend in friends:
                    self.friends_listbox.insert(tk.END, friend)
            except:
                pass

def save_friends(self):
    path = f"friends_{self.username}.json"
    friends = list(self.friends_listbox.get(0, tk.END))
    with open(path, "w", encoding="utf-8") as f:
        json.dump(friends, f, ensure_ascii=False, indent=4)

def send_message(self, event=None):
    message = self.input_entry.get().strip()
    if not message or not self.active_friend:
        return

    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    full_msg = f"{self.username} ({timestamp}): {message}\n"
    self.append_chat(full_msg)
    self.save_chat(self.active_friend, full_msg)
    self.input_entry.delete(0, tk.END)

def append_chat(self, message):
    self.chat_display.config(state=tk.NORMAL)
    self.chat_display.insert(tk.END, message)
    self.chat_display.config(state=tk.DISABLED)
    self.chat_display.see(tk.END)

def save_chat(self, friend_name, message):
    file_path = f"chat_{self.username}_{friend_name}.json"
    chats = []
    if os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8") as f:
            try:
                chats = json.load(f)
            except:
                chats = []

    chats.append({"user": self.username, "message": message.strip()})

    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(chats, f, ensure_ascii=False, indent=4)

def load_chat(self, friend_name):
    file_path = f"chat_{self.username}_{friend_name}.json"
    self.chat_display.config(state=tk.NORMAL)
    self.chat_display.delete(1.0, tk.END)

    if os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8") as f:
            try:
                chats = json.load(f)
                for chat in chats:
                    msg = f"{chat['message']}\n"
                    self.chat_display.insert(tk.END, msg)
            except:
                self.chat_display.insert(tk.END, "(대화 불러오기 실패)\n")

    self.chat_display.config(state=tk.DISABLED)

def select_friend(self, event):
    selected = self.friends_listbox.curselection()
    if selected:
        self.active_friend = self.friends_listbox.get(selected)
        self.load_chat(self.active_friend)

# zerotalk_main.py

import tkinter as tk
from tkinter import messagebox
import json, os, time

# 로그인 화면
class LoginScreen:
    def __init__(self, root):
        self.root = root
        self.root.title("ZeroTalk 로그인")
        self.root.geometry("300x200")
        
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
                json.dump({"admin": "1234"}, f)
        with open("user_data.json", "r") as f:
            self.users = json.load(f)

    def login(self):
        uid = self.id_entry.get()
        pw = self.pw_entry.get()

        if uid in self.users and self.users[uid] == pw:
            self.root.destroy()
            root = tk.Tk()
            MainScreen(root, uid)
            root.mainloop()
        else:
            messagebox.showerror("실패", "ID 또는 PW 오류")
            self.save_log("실패", uid)

    def save_log(self, status, uid):
        log = {
            "status": status,
            "id": uid,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        path = "zerotalk_logs.json"
        logs = []
        if os.path.exists(path):
            with open(path, "r") as f:
                try:
                    logs = json.load(f)
                except:
                    logs = []
        logs.append(log)
        with open(path, "w") as f:
            json.dump(logs, f, ensure_ascii=False, indent=4)


# 메인화면
class MainScreen:
    def __init__(self, root, my_id):
        self.root = root
        self.my_id = my_id
        self.root.title(f"{my_id} - ZeroTalk")
        self.root.geometry("700x500")

        self.left_frame = tk.Frame(root, width=200, bg="#202020")
        self.left_frame.pack(side="left", fill="y")

        self.right_frame = tk.Frame(root, bg="#1e1e1e")
        self.right_frame.pack(side="right", fill="both", expand=True)

        tk.Label(self.left_frame, text="친구 목록", bg="#202020", fg="white").pack(pady=10)
        self.friend_listbox = tk.Listbox(self.left_frame, bg="#2c2c2c", fg="white")
        self.friend_listbox.pack(fill="y", expand=True, padx=10, pady=5)
        self.friend_listbox.bind("<<ListboxSelect>>", self.load_chat)

        self.chat_listbox = tk.Listbox(self.right_frame, bg="black", fg="white")
        self.chat_listbox.pack(fill="both", expand=True, padx=10, pady=10)

        self.input_frame = tk.Frame(self.right_frame, bg="#1e1e1e")
        self.input_frame.pack(fill="x", padx=10, pady=5)

        self.message_entry = tk.Entry(self.input_frame, font=("Arial", 12))
        self.message_entry.pack(side="left", fill="x", expand=True, padx=(0,5))
        self.message_entry.bind("<Return>", self.send_message)

        self.send_btn = tk.Button(self.input_frame, text="전송", command=self.send_message)
        self.send_btn.pack(side="right")

        # 예시 친구들
        self.friends = ["guest", "user1", "user2"]
        for friend in self.friends:
            if friend != self.my_id:
                self.friend_listbox.insert(tk.END, friend)

        self.current_chat_target = None

    def get_chat_file(self, friend_id):
        return f"chat_{self.my_id}_{friend_id}.json"

    def load_chat(self, event):
        if not self.friend_listbox.curselection():
            return
        index = self.friend_listbox.curselection()[0]
        target = self.friend_listbox.get(index)
        self.current_chat_target = target
        self.chat_listbox.delete(0, tk.END)

        path = self.get_chat_file(target)
        if os.path.exists(path):
            with open(path, "r") as f:
                messages = json.load(f)
                for msg in messages:
                    self.chat_listbox.insert(tk.END, f"{msg['user']}: {msg['message']}")

    def send_message(self, event=None):
        msg = self.message_entry.get().strip()
        if not msg or not self.current_chat_target:
            return

        self.chat_listbox.insert(tk.END, f"{self.my_id}: {msg}")
        self.message_entry.delete(0, tk.END)

        path = self.get_chat_file(self.current_chat_target)
        messages = []
        if os.path.exists(path):
            with open(path, "r") as f:
                try:
                    messages = json.load(f)
                except:
                    messages = []
        messages.append({"user": self.my_id, "message": msg})
        with open(path, "w") as f:
            json.dump(messages, f, ensure_ascii=False, indent=4)

# 실행
    def start_zerotalk():
        root = tk.Tk()
        LoginScreen(root)
        root.mainloop()


if __name__ == "__main__":
    start_zerotalk()

# zerotalk_main.py

FRIEND_FILE = "friends.json"

# 로그인 화면
class LoginScreen:
    def __init__(self, root):
        self.root = root
        self.root.title("ZeroTalk 로그인")
        self.root.geometry("300x200")
        
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
                json.dump({"admin": "1234"}, f)
        with open("user_data.json", "r") as f:
            self.users = json.load(f)

    def login(self):
        uid = self.id_entry.get()
        pw = self.pw_entry.get()

        if uid in self.users and self.users[uid] == pw:
            self.root.destroy()
            root = tk.Tk()
            MainScreen(root, uid)
            root.mainloop()
        else:
            messagebox.showerror("실패", "ID 또는 PW 오류")
            self.save_log("실패", uid)

    def save_log(self, status, uid):
        log = {
            "status": status,
            "id": uid,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        path = "zerotalk_logs.json"
        logs = []
        if os.path.exists(path):
            with open(path, "r") as f:
                try:
                    logs = json.load(f)
                except:
                    logs = []
        logs.append(log)
        with open(path, "w") as f:
            json.dump(logs, f, ensure_ascii=False, indent=4)


# 메인화면
class MainScreen:
    def __init__(self, root, my_id):
        self.root = root
        self.my_id = my_id
        self.root.title(f"{my_id} - ZeroTalk")
        self.root.geometry("800x550")

        self.left_frame = tk.Frame(root, width=200, bg="#202020")
        self.left_frame.pack(side="left", fill="y")

        self.right_frame = tk.Frame(root, bg="#1e1e1e")
        self.right_frame.pack(side="right", fill="both", expand=True)

        tk.Label(self.left_frame, text="친구 목록", bg="#202020", fg="white").pack(pady=5)

        self.friend_listbox = tk.Listbox(self.left_frame, bg="#2c2c2c", fg="white")
        self.friend_listbox.pack(fill="y", expand=True, padx=10, pady=5)
        self.friend_listbox.bind("<<ListboxSelect>>", self.load_chat)

        tk.Button(self.left_frame, text="친구 추가", command=self.add_friend).pack(fill="x", padx=10, pady=2)
        tk.Button(self.left_frame, text="친구 삭제", command=self.remove_friend).pack(fill="x", padx=10)

        self.chat_listbox = tk.Listbox(self.right_frame, bg="black", fg="white")
        self.chat_listbox.pack(fill="both", expand=True, padx=10, pady=10)

        self.input_frame = tk.Frame(self.right_frame, bg="#1e1e1e")
        self.input_frame.pack(fill="x", padx=10, pady=5)

        self.message_entry = tk.Text(self.input_frame, height=3, font=("Arial", 12))
        self.message_entry.pack(side="left", fill="x", expand=True, padx=(0,5))
        self.message_entry.bind("<Return>", self.on_enter)

        self.send_btn = tk.Button(self.input_frame, text="전송", command=self.send_message)
        self.send_btn.pack(side="right")

        self.load_friends()
        self.current_chat_target = None

    def get_chat_file(self, friend_id):
        return f"chat_{self.my_id}_{friend_id}.json"

    def load_friends(self):
        self.friends = []
        if os.path.exists(FRIEND_FILE):
            with open(FRIEND_FILE, "r") as f:
                all_data = json.load(f)
                self.friends = all_data.get(self.my_id, [])
        else:
            with open(FRIEND_FILE, "w") as f:
                json.dump({}, f)
        self.refresh_friend_list()

    def refresh_friend_list(self):
        self.friend_listbox.delete(0, tk.END)
        for friend in self.friends:
            self.friend_listbox.insert(tk.END, friend)

    def add_friend(self):
        new = tk.simpledialog.askstring("친구 추가", "친구 아이디:")
        if new and new not in self.friends and new != self.my_id:
            self.friends.append(new)
            self.save_friends()
            self.refresh_friend_list()

    def remove_friend(self):
        selected = self.friend_listbox.curselection()
        if selected:
            index = selected[0]
            friend = self.friend_listbox.get(index)
            self.friends.remove(friend)
            self.save_friends()
            self.refresh_friend_list()
            self.chat_listbox.delete(0, tk.END)

    def save_friends(self):
        if os.path.exists(FRIEND_FILE):
            with open(FRIEND_FILE, "r") as f:
                data = json.load(f)
        else:
            data = {}
        data[self.my_id] = self.friends
        with open(FRIEND_FILE, "w") as f:
            json.dump(data, f, ensure_ascii=False, indent=4)

    def load_chat(self, event):
        if not self.friend_listbox.curselection():
            return
        index = self.friend_listbox.curselection()[0]
        target = self.friend_listbox.get(index)
        self.current_chat_target = target
        self.chat_listbox.delete(0, tk.END)

        path = self.get_chat_file(target)
        if os.path.exists(path):
            with open(path, "r") as f:
                messages = json.load(f)
                for msg in messages:
                    self.chat_listbox.insert(tk.END, f"{msg['user']}: {msg['message']}")

    def on_enter(self, event):
        if event.state & 0x0001:  # Shift + Enter
            return
        self.send_message()
        return "break"

    def send_message(self):
        msg = self.message_entry.get("1.0", tk.END).strip()
        if not msg or not self.current_chat_target:
            return

        self.chat_listbox.insert(tk.END, f"{self.my_id}: {msg}")
        self.message_entry.delete("1.0", tk.END)

        path = self.get_chat_file(self.current_chat_target)
        messages = []
        if os.path.exists(path):
            with open(path, "r") as f:
                try:
                    messages = json.load(f)
                except:
                    messages = []
        messages.append({"user": self.my_id, "message": msg})
        with open(path, "w") as f:
            json.dump(messages, f, ensure_ascii=False, indent=4)


# 실행
    def start_zerotalk():
    root = tk.Tk()
    LoginScreen(root)
    root.mainloop()


if __name__ == "__main__":
    start_zerotalk()
        