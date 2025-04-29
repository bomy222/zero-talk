import tkinter as tk

# -------------------------------
# 메인 화면 연결 임포트
# -------------------------------

# -------------------------------
# 로그인 성공 후 메인 화면 진입 함수
# -------------------------------
def go_to_main_screen(root, username):
    # 현재 창(root) 파괴
    root.destroy()

    # 새로운 메인 창 생성
    main_root = tk.Tk()
    app = MainScreen(main_root, username)
    main_root.mainloop()

from tkinter import messagebox
import random

class MainScreen(tk.Frame):
    def __init__(self, master, username):
        super().__init__(master)
        self.master = master
        self.username = username
        self.friends = []
        self.friend_buttons = []
        self.pack(fill="both", expand=True)
        self.create_widgets()
        self.after(5000, self.update_friend_status)  # 5초마다 상태 업데이트

    def create_widgets(self):
        # 상단 타이틀
        title = tk.Label(self, text=f"ZeroTalk에 오신 것을 환영합니다, {self.username}님!", font=("Helvetica", 18))
        title.pack(pady=20)

        # 친구 목록 프레임
        list_frame = tk.Frame(self)
        list_frame.pack(pady=10)

        self.canvas = tk.Canvas(list_frame, width=300, height=400)
        scrollbar = tk.Scrollbar(list_frame, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = tk.Frame(self.canvas)

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(
                scrollregion=self.canvas.bbox("all")
            )
        )

        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=scrollbar.set)

        self.canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # 친구 추가 버튼
        add_friend_button = tk.Button(self, text="친구 추가", command=self.add_friend)
        add_friend_button.pack(pady=10)

    def add_friend(self):
        friend_name = f"친구{len(self.friends)+1}"
        friend_info = {"name": friend_name, "status": "online"}
        self.friends.append(friend_info)

        button = tk.Button(self.scrollable_frame, text=f"{friend_name} (online)", fg="lime", width=30)
        button.pack(pady=5)
        self.friend_buttons.append(button)

    def update_friend_status(self):
        for i, friend in enumerate(self.friends):
            new_status = random.choice(["online", "offline"])
            friend["status"] = new_status

            button = self.friend_buttons[i]
            status_color = "lime" if new_status == "online" else "gray"
            button.config(text=f"{friend['name']} ({new_status})", fg=status_color)

        self.after(5000, self.update_friend_status)  # 5초마다 반복

    def __init__(self, master, username):
        super().__init__(master)
        self.master = master
        self.username = username
        self.pack(fill="both", expand=True)
        self.create_widgets()

    def create_widgets(self):
        # 메인 타이틀
        title = tk.Label(self, text=f"ZeroTalk - 환영합니다, {self.username}님!", font=("Helvetica", 20, "bold"))
        title.pack(pady=30)

        # 버튼 프레임
        button_frame = tk.Frame(self)
        button_frame.pack(pady=20)

        # 채팅방 입장 버튼
        chat_button = tk.Button(button_frame, text="채팅방 입장", width=20, height=2, command=self.enter_chat_room)
        chat_button.grid(row=0, column=0, padx=10, pady=10)

        # 친구 목록 보기 버튼
        friends_button = tk.Button(button_frame, text="친구 목록 보기", width=20, height=2, command=self.show_friends)
        friends_button.grid(row=0, column=1, padx=10, pady=10)

        # 설정 버튼
        settings_button = tk.Button(button_frame, text="설정", width=20, height=2, command=self.open_settings)
        settings_button.grid(row=1, column=0, padx=10, pady=10)

        # 로그아웃 버튼
        logout_button = tk.Button(button_frame, text="로그아웃", width=20, height=2, command=self.logout)
        logout_button.grid(row=1, column=1, padx=10, pady=10)

    def enter_chat_room(self):
        messagebox.showinfo("알림", "채팅방 입장 기능은 곧 추가됩니다!")

    def show_friends(self):
        messagebox.showinfo("알림", "친구 목록 기능은 곧 추가됩니다!")

    def open_settings(self):
        messagebox.showinfo("알림", "설정 기능은 곧 추가됩니다!")

    def logout(self):
        confirm = messagebox.askyesno("로그아웃", "로그아웃 하시겠습니까?")
        if confirm:
            self.master.destroy()

    def __init__(self, master):
        self.master = master
        self.master.title("ZeroTalk 메인 화면")
        self.master.geometry("900x600")
        self.master.configure(bg='black')  # 전체 배경 검정색

        # 메인 프레임 생성 (전체를 감싸는 기본 틀)
        self.main_frame = tk.Frame(self.master, bg='black')
        self.main_frame.pack(fill='both', expand=True)

        # 왼쪽 친구 리스트 영역 만들기
        self.create_friend_list()

        # 오른쪽 채팅창 영역 만들기
        self.create_chat_area()

    def create_friend_list(self):
        """
        친구 리스트를 만드는 함수
        왼쪽에 위치하고, 스크롤 가능하게 구성한다.
        """
        # 왼쪽 프레임 (친구 리스트 감싸는 부분)
        self.left_frame = tk.Frame(self.main_frame, bg='#1e1e1e', width=300)
        self.left_frame.pack(side='left', fill='y')

        # 친구 리스트 제목
        title = tk.Label(self.left_frame, text="친구 목록", bg='#1e1e1e', fg='white', font=("Helvetica", 16))
        title.pack(pady=10)

        # 친구 리스트를 위한 캔버스 생성
        self.friend_canvas = tk.Canvas(self.left_frame, bg='#2e2e2e', highlightthickness=0)
        self.friend_canvas.pack(side='left', fill='both', expand=True)

        # 스크롤바 생성
        self.friend_scrollbar = ttk.Scrollbar(self.left_frame, orient='vertical', command=self.friend_canvas.yview)
        self.friend_scrollbar.pack(side='right', fill='y')

        # 캔버스와 스크롤바 연결
        self.friend_canvas.configure(yscrollcommand=self.friend_scrollbar.set)

        # 캔버스 안에 실제 프레임을 삽입 (친구 버튼들 들어갈 곳)
        self.friend_list_frame = tk.Frame(self.friend_canvas, bg='#2e2e2e')
        self.friend_canvas.create_window((0,0), window=self.friend_list_frame, anchor='nw')

        # 사이즈 변화 감지해서 스크롤 적용
        self.friend_list_frame.bind(
            "<Configure>",
            lambda e: self.friend_canvas.configure(
                scrollregion=self.friend_canvas.bbox("all")
            )
        )

        # 임시 친구 목록 추가 (나중에 서버 데이터로 대체 예정)
        self.add_dummy_friends()

    def add_dummy_friends(self):
        """
        임시로 20명의 친구 추가하는 함수
        나중에 서버에서 친구 목록 받아오게 수정할 예정
        """
        for i in range(20):
            friend_name = f"친구 {i+1}"
            friend_button = tk.Button(
                self.friend_list_frame,
                text=friend_name,
                bg='#3e3e3e',
                fg='white',
                relief='flat',
                anchor='w',
                padx=10,
                pady=5,
                command=lambda name=friend_name: self.open_chat_with(name)
            )
            friend_button.pack(fill='x', pady=2)
    
    def create_chat_area(self):
        """
        채팅창을 만드는 함수
        오른쪽 영역을 구성한다.
        """
        # 오른쪽 프레임 (채팅창 전체 영역)
        self.right_frame = tk.Frame(self.main_frame, bg='#121212')
        self.right_frame.pack(side='left', fill='both', expand=True)

        # 채팅 내용 표시하는 리스트박스
        self.chat_listbox = tk.Listbox(
            self.right_frame,
            bg='#121212',
            fg='white',
            font=("Helvetica", 12),
            selectbackground='#333333',
            activestyle='none'
        )
        self.chat_listbox.pack(fill='both', expand=True, padx=10, pady=10)

        # 채팅 입력 프레임 (하단)
        self.input_frame = tk.Frame(self.right_frame, bg='#1e1e1e')
        self.input_frame.pack(fill='x', padx=10, pady=5)

        # 채팅 입력창
        self.chat_entry = tk.Entry(
            self.input_frame,
            bg='#2e2e2e',
            fg='white',
            font=("Helvetica", 12),
            relief='flat'
        )
        self.chat_entry.pack(side='left', fill='x', expand=True, padx=(0,5))

        # 전송 버튼
        self.send_button = tk.Button(
            self.input_frame,
            text="전송",
            bg='#4e4e4e',
            fg='white',
            relief='flat',
            command=self.send_message
        )
        self.send_button.pack(side='right')

    def open_chat_with(self, friend_name):
        """
        친구를 클릭했을 때 호출되는 함수
        채팅방 제목 변경 + 채팅창 초기화
        """
        self.chat_listbox.delete(0, tk.END)
        self.chat_listbox.insert(tk.END, f"[{friend_name}]님과의 대화가 시작되었습니다.")

    def send_message(self):
        """
        채팅 메시지 전송하는 함수
        입력창에 입력한 텍스트를 리스트박스에 추가한다.
        """
        message = self.chat_entry.get()
        if message.strip() != "":
            self.chat_listbox.insert(tk.END, f"나: {message}")
            self.chat_entry.delete(0, tk.END)

    def __init__(self, master):
        self.master = master
        self.master.title("ZeroTalk 메인 화면")
        self.master.geometry("1000x650")
        self.master.configure(bg='black')

        # 메인 프레임
        self.main_frame = tk.Frame(self.master, bg='black')
        self.main_frame.pack(fill='both', expand=True)

        # 왼쪽 친구 리스트
        self.create_friend_list()

        # 오른쪽 채팅창
        self.create_chat_area()

    def create_friend_list(self):
        """
        친구 리스트 + 상태표시를 위한 프레임
        """
        self.left_frame = tk.Frame(self.main_frame, bg='#1e1e1e', width=300)
        self.left_frame.pack(side='left', fill='y')

        title = tk.Label(self.left_frame, text="친구 목록", bg='#1e1e1e', fg='white', font=("Helvetica", 16))
        title.pack(pady=10)

        # 캔버스 + 스크롤
        self.friend_canvas = tk.Canvas(self.left_frame, bg='#2e2e2e', highlightthickness=0)
        self.friend_canvas.pack(side='left', fill='both', expand=True)

        self.friend_scrollbar = ttk.Scrollbar(self.left_frame, orient='vertical', command=self.friend_canvas.yview)
        self.friend_scrollbar.pack(side='right', fill='y')

        self.friend_canvas.configure(yscrollcommand=self.friend_scrollbar.set)

        self.friend_list_frame = tk.Frame(self.friend_canvas, bg='#2e2e2e')
        self.friend_canvas.create_window((0,0), window=self.friend_list_frame, anchor='nw')

        self.friend_list_frame.bind(
            "<Configure>",
            lambda e: self.friend_canvas.configure(
                scrollregion=self.friend_canvas.bbox("all")
            )
        )
    def create_friend_list(self):
        """친구 리스트 생성하는 함수"""

        self.friend_list_frame = tk.Frame(self)
        self.friend_list_frame.pack(side="left", fill="y", padx=10, pady=10)

        # 샘플 친구 목록
        self.friends = [
            {"name": "Alice", "status": "online"},
            {"name": "Bob", "status": "offline"},
            {"name": "Charlie", "status": "online"},
            {"name": "David", "status": "offline"},
            {"name": "Eve", "status": "online"},
        ]

        self.friend_buttons = []

        for idx, friend in enumerate(self.friends):
            status_color = "lime" if friend["status"] == "online" else "gray"
            button = tk.Button(
                self.friend_list_frame,
                text=friend["name"],
                fg=status_color,
                command=lambda f=friend: self.open_chat_with(f)
            )
            button.pack(pady=5, fill="x")
            self.friend_buttons.append(button)

    def open_chat_with(self, friend):
        """친구 클릭 시 채팅창으로 넘어가는 함수"""
        messagebox.showinfo("채팅 시작", f"{friend['name']}님과 채팅을 시작합니다.")

        # 임시 친구 데이터
        self.friends = [
            {"name": "친구 1", "status": "online"},
            {"name": "친구 2", "status": "offline"},
            {"name": "친구 3", "status": "online"},
            {"name": "친구 4", "status": "offline"},
            {"name": "친구 5", "status": "online"},
            {"name": "친구 6", "status": "offline"},
            {"name": "친구 7", "status": "online"},
            {"name": "친구 8", "status": "offline"},
            {"name": "친구 9", "status": "online"},
            {"name": "친구 10", "status": "offline"},
        ]

        # 친구 리스트 출력
        self.friend_buttons = []
        self.add_friends()

    def add_friends(self):
        """
        친구 목록을 버튼으로 추가하는 함수
        온라인은 초록색, 오프라인은 회색 표시
        """
        for friend in self.friends:
            status_color = 'lime' if friend["status"] == "online" else 'gray'
            button_frame = tk.Frame(self.friend_list_frame, bg='#2e2e2e')
            button_frame.pack(fill='x', pady=2)

            # 상태 점 표시
            status_dot = tk.Label(
                button_frame,
                text="●",
                fg=status_color,
                bg='#2e2e2e',
                font=("Helvetica", 12)
            )
            status_dot.pack(side='left', padx=5)

            # 친구 버튼
            friend_button = tk.Button(
                button_frame,
                text=friend["name"],
                bg='#3e3e3e',
                fg='white',
                relief='flat',
                anchor='w',
                padx=10,
                pady=5,
                command=lambda name=friend["name"]: self.open_chat_with(name)
            )
            friend_button.pack(fill='x', expand=True)

            self.friend_buttons.append(friend_button)

    def create_chat_area(self):
        """
        채팅창 + 제목 표시
        """
        self.right_frame = tk.Frame(self.main_frame, bg='#121212')
        self.right_frame.pack(side='left', fill='both', expand=True)

        # 채팅 상대 이름 표시
        self.chat_title = tk.Label(
            self.right_frame,
            text="채팅 상대를 선택하세요",
            bg='#121212',
            fg='white',
            font=("Helvetica", 18)
        )
        self.chat_title.pack(pady=10)

        # 채팅 내용
        self.chat_listbox = tk.Listbox(
            self.right_frame,
            bg='#121212',
            fg='white',
            font=("Helvetica", 12),
            selectbackground='#333333',
            activestyle='none'
        )
        self.chat_listbox.pack(fill='both', expand=True, padx=10, pady=(0,10))

        # 입력창
        self.input_frame = tk.Frame(self.right_frame, bg='#1e1e1e')
        self.input_frame.pack(fill='x', padx=10, pady=5)

        self.chat_entry = tk.Entry(
            self.input_frame,
            bg='#2e2e2e',
            fg='white',
            font=("Helvetica", 12),
            relief='flat'
        )
        self.chat_entry.pack(side='left', fill='x', expand=True, padx=(0,5))

        self.send_button = tk.Button(
            self.input_frame,
            text="전송",
            bg='#4e4e4e',
            fg='white',
            relief='flat',
            command=self.send_message
        )
        self.send_button.pack(side='right')

    def open_chat_with(self, friend_name):
        """
        친구 클릭 시 채팅방 열기
        """
        self.chat_listbox.delete(0, tk.END)
        self.chat_title.config(text=f"{friend_name}님과의 대화")
        self.chat_listbox.insert(tk.END, f"[{friend_name}]님과 대화가 시작되었습니다.")

    def send_message(self):
        """
        채팅 전송
        """
        message = self.chat_entry.get()
        if message.strip() != "":
            self.chat_listbox.insert(tk.END, f"나: {message}")
            self.chat_entry.delete(0, tk.END)

    def __init__(self, master):
        self.master = master
        self.master.title("ZeroTalk 메인 화면")
        self.master.geometry("1000x650")
        self.master.configure(bg='black')

        self.main_frame = tk.Frame(self.master, bg='black')
        self.main_frame.pack(fill='both', expand=True)

        self.create_friend_list()
        self.create_chat_area()

    def create_friend_list(self):
        self.left_frame = tk.Frame(self.main_frame, bg='#1e1e1e', width=300)
        self.left_frame.pack(side='left', fill='y')

        title = tk.Label(self.left_frame, text="친구 목록", bg='#1e1e1e', fg='white', font=("Helvetica", 16))
        title.pack(pady=10)

        self.friend_canvas = tk.Canvas(self.left_frame, bg='#2e2e2e', highlightthickness=0)
        self.friend_canvas.pack(side='left', fill='both', expand=True)

        self.friend_scrollbar = ttk.Scrollbar(self.left_frame, orient='vertical', command=self.friend_canvas.yview)
        self.friend_scrollbar.pack(side='right', fill='y')

        self.friend_canvas.configure(yscrollcommand=self.friend_scrollbar.set)

        self.friend_list_frame = tk.Frame(self.friend_canvas, bg='#2e2e2e')
        self.friend_canvas.create_window((0,0), window=self.friend_list_frame, anchor='nw')

        self.friend_list_frame.bind(
            "<Configure>",
            lambda e: self.friend_canvas.configure(
                scrollregion=self.friend_canvas.bbox("all")
            )
        )

        self.friends = [
            {"name": "친구 1", "status": "online"},
            {"name": "친구 2", "status": "offline"},
            {"name": "친구 3", "status": "online"},
            {"name": "친구 4", "status": "offline"},
            {"name": "친구 5", "status": "online"},
        ]

        self.friend_buttons = []
        self.add_friends()

    def add_friends(self):
        for friend in self.friends:
            status_color = 'lime' if friend["status"] == "online" else 'gray'
            button_frame = tk.Frame(self.friend_list_frame, bg='#2e2e2e')
            button_frame.pack(fill='x', pady=2)

            status_dot = tk.Label(
                button_frame,
                text="●",
                fg=status_color,
                bg='#2e2e2e',
                font=("Helvetica", 12)
            )
            status_dot.pack(side='left', padx=5)

            friend_button = tk.Button(
                button_frame,
                text=friend["name"],
                bg='#3e3e3e',
                fg='white',
                relief='flat',
                anchor='w',
                padx=10,
                pady=5,
                command=lambda name=friend["name"]: self.open_chat_with(name)
            )
            friend_button.pack(fill='x', expand=True)

            self.friend_buttons.append(friend_button)

    def create_chat_area(self):
        self.right_frame = tk.Frame(self.main_frame, bg='#121212')
        self.right_frame.pack(side='left', fill='both', expand=True)

        self.chat_title = tk.Label(
            self.right_frame,
            text="채팅 상대를 선택하세요",
            bg='#121212',
            fg='white',
            font=("Helvetica", 18)
        )
        self.chat_title.pack(pady=10)

        # 채팅 메시지 캔버스
        self.chat_canvas = tk.Canvas(self.right_frame, bg='#121212', highlightthickness=0)
        self.chat_canvas.pack(fill='both', expand=True, padx=10)

        self.chat_frame = tk.Frame(self.chat_canvas, bg='#121212')
        self.chat_canvas.create_window((0,0), window=self.chat_frame, anchor='nw')

        self.chat_scrollbar = ttk.Scrollbar(self.right_frame, orient='vertical', command=self.chat_canvas.yview)
        self.chat_scrollbar.place(relx=1.0, rely=0, relheight=0.9, anchor='ne')
        self.chat_canvas.configure(yscrollcommand=self.chat_scrollbar.set)

        self.chat_frame.bind(
            "<Configure>",
            lambda e: self.chat_canvas.configure(
                scrollregion=self.chat_canvas.bbox("all")
            )
        )

        self.input_frame = tk.Frame(self.right_frame, bg='#1e1e1e')
        self.input_frame.pack(fill='x', padx=10, pady=5)

        self.chat_entry = tk.Entry(
            self.input_frame,
            bg='#2e2e2e',
            fg='white',
            font=("Helvetica", 12),
            relief='flat'
        )
        self.chat_entry.pack(side='left', fill='x', expand=True, padx=(0,5))

        self.send_button = tk.Button(
            self.input_frame,
            text="전송",
            bg='#4e4e4e',
            fg='white',
            relief='flat',
            command=self.send_message
        )
        self.send_button.pack(side='right')

    def open_chat_with(self, friend_name):
        """
        친구 클릭시
        """
        for widget in self.chat_frame.winfo_children():
            widget.destroy()
        self.chat_title.config(text=f"{friend_name}님과의 대화")

        # 시작 메시지
        self.add_message(f"{friend_name}님과 대화가 시작되었습니다.", sender="other")

    def add_message(self, text, sender="me"):
        """
        채팅 추가
        sender = 'me' 또는 'other'
        """
        if sender == "me":
            frame = tk.Frame(self.chat_frame, bg='#121212')
            frame.pack(anchor='e', pady=2, padx=5, fill='x')

            msg = tk.Label(
                frame,
                text=text,
                bg='#3e3e3e',
                fg='white',
                font=("Helvetica", 12),
                padx=10,
                pady=5,
                wraplength=300,
                justify='right'
            )
            msg.pack(anchor='e', padx=10)
        else:
            frame = tk.Frame(self.chat_frame, bg='#121212')
            frame.pack(anchor='w', pady=2, padx=5, fill='x')

            msg = tk.Label(
                frame,
                text=text,
                bg='#1e1e1e',
                fg='white',
                font=("Helvetica", 12),
                padx=10,
                pady=5,
                wraplength=300,
                justify='left'
            )
            msg.pack(anchor='w', padx=10)

        self.chat_canvas.update_idletasks()
        self.chat_canvas.yview_moveto(1.0)

    def send_message(self):
        """
        메시지 보내기
        """
        message = self.chat_entry.get()
        if message.strip() != "":
            self.add_message(f"나: {message}", sender="me")
            self.chat_entry.delete(0, tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = MainScreenApp(root)
    root.mainloop()