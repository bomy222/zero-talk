import tkinter as tk
from templates.login import LoginScreen

def start_zerotalk():
    root = tk.Tk()
    app = LoginScreen(root)
    root.mainloop

def start_main_screen(username):
    root = tk.Tk()
    root.title("ZeroTalk 메인 화면")
    root.geometry("1000x650")
    app = MainScreen(root, username)
    root.mainloop()

def go_to_main_screen(root, username):
    root.destroy()  # 기존 로그인 창 닫고
    main_root = tk.Tk()  # 새 창 열고
    app = MainScreen(main_root, username)
    main_root.mainloop()

class ZeroTalkApp:
    def __init__(self, master):
        self.master = master
        self.master.title("ZeroTalk 메신저")
        self.master.geometry("450x750")
        self.user_id = None
        self.password = None
        self.wallet = {}
        self.friends = []
        self.blocked = []
        self.load_user_data()
        self.login_frame = None
        self.main_frame = None
        self.build_login_screen()

    def load_user_data(self):
        if os.path.exists('user_data.json'):
            with open('user_data.json', 'r', encoding='utf-8') as f:
                self.user_data = json.load(f)
        else:
            self.user_data = {}

    def save_user_data(self):
        with open('user_data.json', 'w', encoding='utf-8') as f:
            json.dump(self.user_data, f, ensure_ascii=False, indent=4)

    def save_log(self, action, details=""):
        log_entry = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "user": self.user_id,
            "action": action,
            "details": details
        }
        if os.path.exists('zerotalk_logs.json'):
            with open('zerotalk_logs.json', 'r', encoding='utf-8') as f:
                logs = json.load(f)
        else:
            logs = []
        logs.append(log_entry)
        with open('zerotalk_logs.json', 'w', encoding='utf-8') as f:
            json.dump(logs, f, ensure_ascii=False, indent=4)

    def build_login_screen(self):
        self.clear_screen()
        self.login_frame = tk.Frame(self.master)
        self.login_frame.pack(pady=100)

        tk.Label(self.login_frame, text="ZeroTalk 로그인", font=("Arial", 20, "bold")).pack(pady=20)

        tk.Label(self.login_frame, text="아이디", font=("Arial", 12)).pack()
        self.id_entry = tk.Entry(self.login_frame, font=("Arial", 14))
        self.id_entry.pack(pady=5)

        tk.Label(self.login_frame, text="비밀번호", font=("Arial", 12)).pack()
        self.pw_entry = tk.Entry(self.login_frame, show="*", font=("Arial", 14))
        self.pw_entry.pack(pady=5)

        tk.Button(self.login_frame, text="로그인", font=("Arial", 14, "bold"), width=15, command=self.login).pack(pady=10)
        tk.Button(self.login_frame, text="회원가입", font=("Arial", 12), width=15, command=self.build_signup_screen).pack()

    def login(self):
        id_ = self.id_entry.get().strip()
        pw = self.pw_entry.get().strip()

        if id_ in self.user_data and self.user_data[id_]['password'] == pw:
            self.user_id = id_
            self.password = pw
            self.wallet = self.user_data[id_].get('wallet', self.generate_wallet())
            self.friends = self.user_data[id_].get('friends', [])
            self.blocked = self.user_data[id_].get('blocked', [])
            self.save_log("로그인 성공")
            self.build_main_screen()
        else:
            messagebox.showerror("로그인 실패", "아이디 또는 비밀번호가 틀렸습니다.")
            self.save_log("로그인 실패", f"시도 ID: {id_}")

    def signup(self):
        id_ = self.id_entry.get().strip()
        pw = self.pw_entry.get().strip()

        if not id_ or not pw:
            messagebox.showwarning("경고", "아이디와 비밀번호를 모두 입력해주세요.")
            return

        if id_ in self.user_data:
            messagebox.showerror("회원가입 실패", "이미 존재하는 아이디입니다.")
            return

        self.user_data[id_] = {
            'password': pw,
            'wallet': self.generate_wallet(),
            'friends': [],
            'blocked': [],
            'sent_requests': [],
            'received_requests': []
        }
        self.save_user_data()
        messagebox.showinfo("회원가입 완료", "회원가입이 완료되었습니다.")
        self.save_log("회원가입", f"가입 ID: {id_}")

    def generate_wallet(self):
        wallet_address = ''.join(random.choices(string.ascii_letters + string.digits, k=42))
        return {'address': wallet_address, 'balance': 0.0}

    def build_signup_screen(self):
        self.clear_screen()
        signup_frame = tk.Frame(self.master)
        signup_frame.pack(pady=100)

        tk.Label(signup_frame, text="ZeroTalk 회원가입", font=("Arial", 20, "bold")).pack(pady=20)

        tk.Label(signup_frame, text="새 아이디", font=("Arial", 12)).pack()
        self.new_id_entry = tk.Entry(signup_frame, font=("Arial", 14))
        self.new_id_entry.pack(pady=5)

        tk.Label(signup_frame, text="새 비밀번호", font=("Arial", 12)).pack()
        self.new_pw_entry = tk.Entry(signup_frame, font=("Arial", 14), show="*")
        self.new_pw_entry.pack(pady=5)

        tk.Button(signup_frame, text="가입 완료", font=("Arial", 14, "bold"), width=15, command=self.finish_signup).pack(pady=10)
        tk.Button(signup_frame, text="뒤로가기", font=("Arial", 12), width=15, command=self.build_login_screen).pack()

    def finish_signup(self):
        new_id = self.new_id_entry.get().strip()
        new_pw = self.new_pw_entry.get().strip()

        if not new_id or not new_pw:
            messagebox.showwarning("경고", "아이디와 비밀번호를 모두 입력해주세요.")
            return

        if new_id in self.user_data:
            messagebox.showerror("회원가입 실패", "이미 존재하는 아이디입니다.")
            return

        self.user_data[new_id] = {
            'password': new_pw,
            'wallet': self.generate_wallet(),
            'friends': [],
            'blocked': [],
            'sent_requests': [],
            'received_requests': []
        }
        self.save_user_data()
        messagebox.showinfo("회원가입 완료", "가입이 완료되었습니다.")
        self.save_log("회원가입 완료", f"가입 ID: {new_id}")
        self.build_login_screen()

    def clear_screen(self):
        for widget in self.master.winfo_children():
            widget.destroy()

    def build_main_screen(self):
        self.clear_screen()
        self.main_frame = tk.Frame(self.master)
        self.main_frame.pack(fill="both", expand=True)

        tk.Label(self.main_frame, text=f"환영합니다, {self.user_id}님", font=("Arial", 20, "bold")).pack(pady=20)

        tk.Button(self.main_frame, text="친구 목록", font=("Arial", 14), width=20, command=self.show_friends_window).pack(pady=10)
        tk.Button(self.main_frame, text="채팅방", font=("Arial", 14), width=20, command=self.show_chat_window).pack(pady=10)
        tk.Button(self.main_frame, text="내 지갑 보기", font=("Arial", 14), width=20, command=self.open_wallet_window).pack(pady=10)
        tk.Button(self.main_frame, text="친구 요청 확인", font=("Arial", 14), width=20, command=self.check_received_requests).pack(pady=10)
        tk.Button(self.main_frame, text="친구 요청 보내기", font=("Arial", 14), width=20, command=self.request_friend).pack(pady=10)
        tk.Button(self.main_frame, text="로그아웃", font=("Arial", 12), width=15, command=self.logout).pack(pady=20)

    def logout(self):
        self.save_log("로그아웃")
        self.user_id = None
        self.password = None
        self.friends = []
        self.blocked = []
        self.wallet = {}
        self.build_login_screen()

    def show_friends_window(self):
        self.clear_screen()
        self.friends_frame = tk.Frame(self.master)
        self.friends_frame.pack(fill="both", expand=True)

        tk.Label(self.friends_frame, text="친구 목록", font=("Arial", 20, "bold")).pack(pady=20)

        self.friend_listbox = tk.Listbox(self.friends_frame, font=("Arial", 12))
        self.friend_listbox.pack(pady=10, fill="both", expand=True)

        for friend in self.friends:
            self.friend_listbox.insert(tk.END, friend)

        tk.Button(self.friends_frame, text="친구 삭제", font=("Arial", 12), width=15, command=self.delete_friend).pack(pady=5)
        tk.Button(self.friends_frame, text="뒤로가기", font=("Arial", 12), width=15, command=self.build_main_screen).pack(pady=5)

    def delete_friend(self):
        selected = self.friend_listbox.curselection()
        if not selected:
            messagebox.showerror("오류", "삭제할 친구를 선택해주세요.")
            return
        friend_id = self.friend_listbox.get(selected)

        confirm = messagebox.askyesno("확인", f"{friend_id}님을 친구 목록에서 삭제하시겠습니까?")
        if confirm:
            self.friends.remove(friend_id)
            self.user_data[self.user_id]['friends'] = self.friends
            self.save_user_data()
            self.save_log("친구 삭제", f"{friend_id}")
            self.show_friends_window()

    def open_wallet_window(self):
        self.clear_screen()
        self.wallet_frame = tk.Frame(self.master)
        self.wallet_frame.pack(fill="both", expand=True)

        tk.Label(self.wallet_frame, text="내 지갑", font=("Arial", 20, "bold")).pack(pady=20)

        wallet_address = self.wallet.get('address', '지갑 없음')
        wallet_balance = self.wallet.get('balance', 0.0)

        tk.Label(self.wallet_frame, text=f"주소: {wallet_address}", font=("Arial", 12)).pack(pady=5)
        tk.Label(self.wallet_frame, text=f"잔액: {wallet_balance:.2f} TLK", font=("Arial", 12)).pack(pady=5)

        tk.Button(self.wallet_frame, text="코인 보내기", font=("Arial", 14), width=20, command=self.send_coin_window).pack(pady=10)
        tk.Button(self.wallet_frame, text="뒤로가기", font=("Arial", 12), width=15, command=self.build_main_screen).pack(pady=10)

    def send_coin_window(self):
        self.clear_screen()
        self.send_frame = tk.Frame(self.master)
        self.send_frame.pack(fill="both", expand=True)

        tk.Label(self.send_frame, text="코인 보내기", font=("Arial", 20, "bold")).pack(pady=20)

        tk.Label(self.send_frame, text="받는 사람 ID", font=("Arial", 12)).pack(pady=5)
        self.recipient_entry = tk.Entry(self.send_frame, font=("Arial", 12))
        self.recipient_entry.pack(pady=5)

        tk.Label(self.send_frame, text="보낼 금액 (TLK)", font=("Arial", 12)).pack(pady=5)
        self.amount_entry = tk.Entry(self.send_frame, font=("Arial", 12))
        self.amount_entry.pack(pady=5)

        tk.Button(self.send_frame, text="전송하기", font=("Arial", 14), width=20, command=self.send_coin).pack(pady=10)
        tk.Button(self.send_frame, text="뒤로가기", font=("Arial", 12), width=15, command=self.open_wallet_window).pack(pady=10)

    def send_coin(self):
        recipient = self.recipient_entry.get().strip()
        amount_text = self.amount_entry.get().strip()

        if not recipient or not amount_text:
            messagebox.showerror("오류", "모든 입력란을 채워주세요.")
            return

        try:
            amount = float(amount_text)
            if amount <= 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("오류", "수량은 양의 숫자여야 합니다.")
            return

        if recipient not in self.user_data:
            messagebox.showerror("오류", "받는 사용자가 존재하지 않습니다.")
            return

        tlk_fee = amount * 0.01  # 1% 구매 수수료
        total_amount = amount + tlk_fee

        if self.wallet['balance'] < total_amount:
            messagebox.showerror("오류", f"잔액 부족: {amount} TLK + 수수료 {tlk_fee:.2f} TLK 필요")
            return

        # 송금 및 수수료 계산
        self.wallet['balance'] -= total_amount
        self.user_data[self.user_id]['wallet']['balance'] = self.wallet['balance']
        self.user_data[recipient]['wallet']['balance'] += amount

        self.save_user_data()
        self.save_log("코인 전송", f"{recipient}에게 {amount} TLK 전송, 수수료 {tlk_fee:.2f} TLK 부과")

        messagebox.showinfo("전송 성공", f"{recipient}님에게 {amount} TLK 전송 완료\n(수수료 {tlk_fee:.2f} TLK 차감)")
        self.open_wallet_window()

    def show_chat_window(self):
        self.clear_screen()
        self.chat_frame = tk.Frame(self.master)
        self.chat_frame.pack(fill="both", expand=True)

        tk.Label(self.chat_frame, text="채팅방", font=("Arial", 20, "bold")).pack(pady=20)

        self.chat_log = tk.Text(self.chat_frame, state="disabled", height=20, bg="#f4f4f4", font=("Arial", 12))
        self.chat_log.pack(pady=10, fill="both", expand=True)

        self.chat_entry = tk.Entry(self.chat_frame, font=("Arial", 12))
        self.chat_entry.pack(pady=5, fill="x", padx=10)
        self.chat_entry.bind("<Return>", self.send_chat_message)

        send_btn = tk.Button(self.chat_frame, text="메시지 보내기", font=("Arial", 12), command=self.send_chat_message)
        send_btn.pack(pady=5)

        back_btn = tk.Button(self.chat_frame, text="뒤로가기", font=("Arial", 12), command=self.build_main_screen)
        back_btn.pack(pady=10)

    def send_chat_message(self, event=None):
        message = self.chat_entry.get().strip()

        if not message:
            return

        self.chat_log.config(state="normal")
        self.chat_log.insert(tk.END, f"{self.user_id}: {message}\n")
        self.chat_log.config(state="disabled")
        self.chat_log.see(tk.END)

        self.chat_entry.delete(0, tk.END)
        self.save_log("채팅", f"메시지: {message}")

    def show_notification(self, message):
        popup = tk.Toplevel(self.master)
        popup.title("알림")
        popup.geometry("300x100")
        tk.Label(popup, text=message, font=("Arial", 12)).pack(pady=10)
        tk.Button(popup, text="확인", command=popup.destroy).pack(pady=5)

    def backup_data(self):
        backup_filename = f"backup_{time.strftime('%Y%m%d_%H%M%S')}.json"
        with open(backup_filename, 'w', encoding='utf-8') as f:
            json.dump(self.user_data, f, ensure_ascii=False, indent=4)
        self.save_log("백업", f"파일 생성: {backup_filename}")
        self.show_notification("백업이 완료되었습니다.")

    def show_settings(self):
        self.clear_screen()
        self.settings_frame = tk.Frame(self.master)
        self.settings_frame.pack(fill="both", expand=True)

        tk.Label(self.settings_frame, text="설정", font=("Arial", 20, "bold")).pack(pady=20)

        tk.Button(self.settings_frame, text="비밀번호 변경", font=("Arial", 14), command=self.change_password).pack(pady=10)
        tk.Button(self.settings_frame, text="데이터 백업", font=("Arial", 14), command=self.backup_data).pack(pady=10)
        tk.Button(self.settings_frame, text="뒤로가기", font=("Arial", 12), command=self.build_main_screen).pack(pady=20)

    def change_password(self):
        self.clear_screen()
        self.change_pw_frame = tk.Frame(self.master)
        self.change_pw_frame.pack(fill="both", expand=True)

        tk.Label(self.change_pw_frame, text="비밀번호 변경", font=("Arial", 20, "bold")).pack(pady=20)

        tk.Label(self.change_pw_frame, text="현재 비밀번호", font=("Arial", 12)).pack(pady=5)
        self.current_pw_entry = tk.Entry(self.change_pw_frame, show="*", font=("Arial", 12))
        self.current_pw_entry.pack(pady=5)

        tk.Label(self.change_pw_frame, text="새 비밀번호", font=("Arial", 12)).pack(pady=5)
        self.new_pw_entry = tk.Entry(self.change_pw_frame, show="*", font=("Arial", 12))
        self.new_pw_entry.pack(pady=5)

        tk.Button(self.change_pw_frame, text="변경하기", font=("Arial", 14), command=self.update_password).pack(pady=10)
        tk.Button(self.change_pw_frame, text="뒤로가기", font=("Arial", 12), command=self.show_settings).pack(pady=10)

    def update_password(self):
        current_pw = self.current_pw_entry.get().strip()
        new_pw = self.new_pw_entry.get().strip()

        if not current_pw or not new_pw:
            messagebox.showerror("오류", "모든 입력란을 채워주세요.")
            return

        if current_pw != self.user_data[self.user_id]['password']:
            messagebox.showerror("오류", "현재 비밀번호가 틀렸습니다.")
            return

        self.user_data[self.user_id]['password'] = new_pw
        self.save_user_data()
        self.save_log("비밀번호 변경", f"ID: {self.user_id}")
        messagebox.showinfo("완료", "비밀번호가 성공적으로 변경되었습니다.")
        self.build_main_screen()

    def open_tlk_transaction_log(self):
        self.clear_screen()
        self.transaction_frame = tk.Frame(self.master)
        self.transaction_frame.pack(fill="both", expand=True)

        tk.Label(self.transaction_frame, text="송금 기록 (TLK)", font=("Arial", 20, "bold")).pack(pady=20)

        if os.path.exists('log_data.json'):
            with open('log_data.json', 'r', encoding='utf-8') as f:
                logs = json.load(f)

            user_logs = [log for log in logs if log['user'] == self.user_id and log['action'] == '코인 전송']

            if user_logs:
                for log in user_logs:
                    info = f"{log['time']}: {log['details']}"
                    tk.Label(self.transaction_frame, text=info, font=("Arial", 10)).pack(pady=2)
            else:
                tk.Label(self.transaction_frame, text="송금 기록이 없습니다.", font=("Arial", 12)).pack(pady=10)
        else:
            tk.Label(self.transaction_frame, text="로그 데이터가 없습니다.", font=("Arial", 12)).pack(pady=10)

        tk.Button(self.transaction_frame, text="뒤로가기", font=("Arial", 12), command=self.open_wallet_window).pack(pady=20)

    def open_wallet_window(self):
        self.clear_screen()
        self.wallet_frame = tk.Frame(self.master)
        self.wallet_frame.pack(fill="both", expand=True)

        tk.Label(self.wallet_frame, text="내 지갑", font=("Arial", 20, "bold")).pack(pady=20)

        address = self.wallet.get('address', '지갑 없음')
        balance = self.wallet.get('balance', 0)

        tk.Label(self.wallet_frame, text=f"주소: {address}", font=("Arial", 12)).pack(pady=5)
        tk.Label(self.wallet_frame, text=f"잔액: {balance} TLK", font=("Arial", 12)).pack(pady=5)

        tk.Button(self.wallet_frame, text="TLK 보내기", font=("Arial", 14), command=self.send_coin_window).pack(pady=10)
        tk.Button(self.wallet_frame, text="송금 기록 보기", font=("Arial", 14), command=self.open_tlk_transaction_log).pack(pady=10)
        tk.Button(self.wallet_frame, text="뒤로가기", font=("Arial", 12), command=self.build_main_screen).pack(pady=20)

    def send_coin_window(self):
        self.clear_screen()
        self.send_frame = tk.Frame(self.master)
        self.send_frame.pack(fill="both", expand=True)

        tk.Label(self.send_frame, text="코인 보내기", font=("Arial", 20, "bold")).pack(pady=20)

        tk.Label(self.send_frame, text="받는 사람 ID", font=("Arial", 12)).pack(pady=5)
        self.recipient_entry = tk.Entry(self.send_frame, font=("Arial", 12))
        self.recipient_entry.pack(pady=5)

        tk.Label(self.send_frame, text="보낼 수량 (TLK)", font=("Arial", 12)).pack(pady=5)
        self.amount_entry = tk.Entry(self.send_frame, font=("Arial", 12))
        self.amount_entry.pack(pady=5)

        tk.Button(self.send_frame, text="보내기", font=("Arial", 14), command=self.process_send_coin).pack(pady=10)
        tk.Button(self.send_frame, text="뒤로가기", font=("Arial", 12), command=self.open_wallet_window).pack(pady=20)

    def process_send_coin(self):
        recipient = self.recipient_entry.get().strip()
        amount_text = self.amount_entry.get().strip()

        if not recipient or not amount_text:
            messagebox.showerror("오류", "모든 입력란을 채워주세요.")
            return

        if recipient not in self.user_data:
            messagebox.showerror("오류", "받는 사용자가 존재하지 않습니다.")
            return

        try:
            amount = float(amount_text)
            if amount <= 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("오류", "수량은 양의 숫자여야 합니다.")
            return

        fee = round(amount * 0.01, 2)  # 수수료 1%
        total_required = amount + fee

        if self.wallet['balance'] < total_required:
            messagebox.showerror("오류", f"잔액이 부족합니다. 수수료 포함 필요: {total_required} TLK")
            return

        # 전송 처리
        self.wallet['balance'] -= total_required
        self.user_data[self.user_id]['wallet']['balance'] = self.wallet['balance']
        self.user_data[recipient]['wallet']['balance'] += amount

        self.save_user_data()
        self.save_log("코인 전송", f"To: {recipient}, Amount: {amount}, Fee: {fee}")

        messagebox.showinfo("성공", f"{recipient}님에게 {amount} TLK 전송 완료!\n(수수료 {fee} TLK 발생)")
        self.open_wallet_window()

    def theme_selector(self):
        self.clear_screen()
        self.theme_frame = tk.Frame(self.master)
        self.theme_frame.pack(fill="both", expand=True)

        tk.Label(self.theme_frame, text="테마 선택", font=("Arial", 20, "bold")).pack(pady=20)

        themes = ["핑크", "화이트", "다크", "보라", "블루"]
        for t in themes:
            tk.Button(self.theme_frame, text=t, font=("Arial", 14),
                      command=lambda theme=t: self.apply_theme(theme)).pack(pady=5)

        tk.Button(self.theme_frame, text="뒤로가기", font=("Arial", 12), command=self.build_main_screen).pack(pady=20)

    def apply_theme(self, theme_name):
        theme_colors = {
            "핑크": "#ffe4e1",
            "화이트": "#ffffff",
            "다크": "#333333",
            "보라": "#d8bfd8",
            "블루": "#add8e6"
        }
        selected_color = theme_colors.get(theme_name, "#ffffff")
        self.master.configure(bg=selected_color)
        self.save_log("테마 변경", f"선택한 테마: {theme_name}")
        messagebox.showinfo("테마 적용", f"{theme_name} 테마가 적용되었습니다.")

    def open_marketplace(self):
        self.clear_screen()
        self.market_frame = tk.Frame(self.master)
        self.market_frame.pack(fill="both", expand=True)

        tk.Label(self.market_frame, text="NFT 마켓플레이스 (BomiNFT)", font=("Arial", 20, "bold")).pack(pady=20)

        nft_items = [
            {"name": "핑크 보미", "price": 100},
            {"name": "블루 보미", "price": 150},
            {"name": "다크 보미", "price": 200}
        ]

        for nft in nft_items:
            frame = tk.Frame(self.market_frame)
            frame.pack(pady=5)

            tk.Label(frame, text=f"{nft['name']} - {nft['price']} TLK", font=("Arial", 12)).pack(side="left", padx=5)
            tk.Button(frame, text="구매", font=("Arial", 12),
                      command=lambda n=nft: self.purchase_nft(n)).pack(side="left", padx=5)

        tk.Button(self.market_frame, text="뒤로가기", font=("Arial", 12), command=self.build_main_screen).pack(pady=20)

    def purchase_nft(self, nft):
        if self.wallet['balance'] < nft['price']:
            messagebox.showerror("구매 실패", "잔액이 부족합니다.")
            return

        confirm = messagebox.askyesno("구매 확인", f"{nft['name']}를 {nft['price']} TLK로 구매하시겠습니까?")
        if confirm:
            self.wallet['balance'] -= nft['price']
            self.user_data[self.user_id]['wallet']['balance'] = self.wallet['balance']
            self.save_user_data()
            self.save_log("NFT 구매", f"{nft['name']} - {nft['price']} TLK")
            messagebox.showinfo("구매 완료", f"{nft['name']}를 구매했습니다!")
            self.open_wallet_window()

    def open_settings(self):
        self.clear_screen()
        self.settings_frame = tk.Frame(self.master)
        self.settings_frame.pack(fill="both", expand=True)

        tk.Label(self.settings_frame, text="설정", font=("Arial", 20, "bold")).pack(pady=20)

        tk.Button(self.settings_frame, text="비밀번호 변경", font=("Arial", 14),
                  command=self.change_password).pack(pady=10)

        tk.Button(self.settings_frame, text="2단계 인증 설정", font=("Arial", 14),
                  command=self.setup_two_factor_auth).pack(pady=10)

        tk.Button(self.settings_frame, text="테마 선택", font=("Arial", 14),
                  command=self.theme_selector).pack(pady=10)

        tk.Button(self.settings_frame, text="뒤로가기", font=("Arial", 12),
                  command=self.build_main_screen).pack(pady=20)

    def change_password(self):
        self.clear_screen()
        self.change_pw_frame = tk.Frame(self.master)
        self.change_pw_frame.pack(fill="both", expand=True)

        tk.Label(self.change_pw_frame, text="비밀번호 변경", font=("Arial", 20, "bold")).pack(pady=20)

        tk.Label(self.change_pw_frame, text="현재 비밀번호", font=("Arial", 12)).pack(pady=5)
        self.current_pw_entry = tk.Entry(self.change_pw_frame, font=("Arial", 12), show="*")
        self.current_pw_entry.pack(pady=5)

        tk.Label(self.change_pw_frame, text="새 비밀번호", font=("Arial", 12)).pack(pady=5)
        self.new_pw_entry = tk.Entry(self.change_pw_frame, font=("Arial", 12), show="*")
        self.new_pw_entry.pack(pady=5)

        tk.Button(self.change_pw_frame, text="변경", font=("Arial", 14),
                  command=self.process_change_password).pack(pady=10)

        tk.Button(self.change_pw_frame, text="뒤로가기", font=("Arial", 12),
                  command=self.open_settings).pack(pady=10)

    def process_change_password(self):
        current_pw = self.current_pw_entry.get()
        new_pw = self.new_pw_entry.get()

        if current_pw != self.user_data[self.user_id]['password']:
            messagebox.showerror("오류", "현재 비밀번호가 틀립니다.")
            return

        self.user_data[self.user_id]['password'] = new_pw
        self.save_user_data()
        messagebox.showinfo("완료", "비밀번호가 변경되었습니다.")
        self.open_settings()

    def setup_two_factor_auth(self):
        self.clear_screen()
        self.two_factor_frame = tk.Frame(self.master)
        self.two_factor_frame.pack(fill="both", expand=True)

        tk.Label(self.two_factor_frame, text="2단계 인증 설정", font=("Arial", 20, "bold")).pack(pady=20)

        tk.Label(self.two_factor_frame, text="패턴 등록 (숫자 4자리)", font=("Arial", 12)).pack(pady=5)
        self.pattern_entry = tk.Entry(self.two_factor_frame, font=("Arial", 12))
        self.pattern_entry.pack(pady=5)

        tk.Label(self.two_factor_frame, text="백업 번호 등록 (선택)", font=("Arial", 12)).pack(pady=5)
        self.backup_entry = tk.Entry(self.two_factor_frame, font=("Arial", 12))
        self.backup_entry.pack(pady=5)

        tk.Button(self.two_factor_frame, text="등록하기", font=("Arial", 14),
                  command=self.save_two_factor_auth).pack(pady=10)

        tk.Button(self.two_factor_frame, text="뒤로가기", font=("Arial", 12),
                  command=self.open_settings).pack(pady=10)

    def save_two_factor_auth(self):
        pattern = self.pattern_entry.get().strip()
        backup = self.backup_entry.get().strip()

        if not (pattern.isdigit() and len(pattern) == 4):
            messagebox.showerror("오류", "패턴은 4자리 숫자만 가능합니다.")
            return

        self.user_data[self.user_id]['two_factor'] = {
            "pattern": pattern,
            "backup": backup
        }
        self.save_user_data()
        messagebox.showinfo("완료", "2단계 인증이 등록되었습니다.")
        self.open_settings()

    def validate_two_factor_auth(self):
        if 'two_factor' not in self.user_data[self.user_id]:
            return True

        auth_win = tk.Toplevel(self.master)
        auth_win.title("2단계 인증")
        auth_win.geometry("300x200")

        tk.Label(auth_win, text="등록된 패턴 입력", font=("Arial", 14)).pack(pady=20)
        pattern_entry = tk.Entry(auth_win, font=("Arial", 12), show="*")
        pattern_entry.pack(pady=10)

        def check_pattern():
            entered = pattern_entry.get()
            correct = self.user_data[self.user_id]['two_factor']['pattern']
            if entered == correct:
                messagebox.showinfo("확인", "인증 성공")
                auth_win.destroy()
                return True
            else:
                messagebox.showerror("실패", "패턴이 틀립니다.")
                return False

        tk.Button(auth_win, text="확인", font=("Arial", 14), command=check_pattern).pack(pady=20)

    def open_tlk_transaction_log(self):
        self.clear_screen()
        self.tlk_log_frame = tk.Frame(self.master)
        self.tlk_log_frame.pack(fill="both", expand=True)

        tk.Label(self.tlk_log_frame, text="TLK 송금 기록", font=("Arial", 20, "bold")).pack(pady=20)

        if not os.path.exists('log_data.json'):
            tk.Label(self.tlk_log_frame, text="기록이 없습니다.", font=("Arial", 12)).pack(pady=10)
            tk.Button(self.tlk_log_frame, text="뒤로가기", font=("Arial", 12),
                      command=self.open_wallet_window).pack(pady=20)
            return

        with open('log_data.json', 'r', encoding='utf-8') as f:
            logs = json.load(f)

        for log in logs:
            if log['action'] == "코인 전송" and log['user'] == self.user_id:
                tk.Label(self.tlk_log_frame, text=f"{log['time']} - {log['details']}",
                         font=("Arial", 10)).pack(pady=2)

        tk.Button(self.tlk_log_frame, text="뒤로가기", font=("Arial", 12),
                  command=self.open_wallet_window).pack(pady=20)

    def theme_selector(self):
        self.clear_screen()
        self.theme_frame = tk.Frame(self.master)
        self.theme_frame.pack(fill="both", expand=True)

        tk.Label(self.theme_frame, text="테마 선택", font=("Arial", 20, "bold")).pack(pady=20)

        tk.Button(self.theme_frame, text="기본 화이트", font=("Arial", 14),
                  command=lambda: self.apply_theme("white")).pack(pady=10)
        tk.Button(self.theme_frame, text="핑크 테마", font=("Arial", 14),
                  command=lambda: self.apply_theme("pink")).pack(pady=10)
        tk.Button(self.theme_frame, text="다크 모드", font=("Arial", 14),
                  command=lambda: self.apply_theme("dark")).pack(pady=10)

        tk.Button(self.theme_frame, text="뒤로가기", font=("Arial", 12),
                  command=self.open_settings).pack(pady=20)

    def apply_theme(self, theme):
        if theme == "white":
            self.master.configure(bg="white")
        elif theme == "pink":
            self.master.configure(bg="#ffe4e1")
        elif theme == "dark":
            self.master.configure(bg="#1e1e1e")
        else:
            self.master.configure(bg="white")

        self.user_data[self.user_id]['theme'] = theme
        self.save_user_data()
        messagebox.showinfo("테마 변경", f"{theme} 테마가 적용되었습니다.")
        self.open_settings()

    def open_wallet_window(self):
        self.clear_screen()
        self.wallet_frame = tk.Frame(self.master)
        self.wallet_frame.pack(fill="both", expand=True)

        tk.Label(self.wallet_frame, text="ZeroTalk Wallet", font=("Arial", 20, "bold")).pack(pady=20)

        wallet = self.user_data[self.user_id]['wallet']
        eth_balance = wallet.get('eth', 0)
        btc_balance = wallet.get('btc', 0)
        tlk_balance = wallet.get('tlk', 0)

        tk.Label(self.wallet_frame, text=f"ETH 잔액: {eth_balance}", font=("Arial", 14)).pack(pady=5)
        tk.Label(self.wallet_frame, text=f"BTC 잔액: {btc_balance}", font=("Arial", 14)).pack(pady=5)
        tk.Label(self.wallet_frame, text=f"TLK 잔액: {tlk_balance}", font=("Arial", 14)).pack(pady=5)

        tk.Button(self.wallet_frame, text="코인 전송", font=("Arial", 14), command=self.open_send_coin).pack(pady=10)
        tk.Button(self.wallet_frame, text="TLK 구매", font=("Arial", 14), command=self.open_buy_tlk).pack(pady=10)
        tk.Button(self.wallet_frame, text="송금 기록", font=("Arial", 14), command=self.open_tlk_transaction_log).pack(pady=10)

        tk.Button(self.wallet_frame, text="뒤로가기", font=("Arial", 12),
                  command=self.build_main_screen).pack(pady=20)

    def open_send_coin(self):
        self.clear_screen()
        self.send_frame = tk.Frame(self.master)
        self.send_frame.pack(fill="both", expand=True)

        tk.Label(self.send_frame, text="코인 전송", font=("Arial", 20, "bold")).pack(pady=20)

        tk.Label(self.send_frame, text="받는 ID", font=("Arial", 12)).pack(pady=5)
        self.recipient_entry = tk.Entry(self.send_frame)
        self.recipient_entry.pack(pady=5)

        tk.Label(self.send_frame, text="전송 코인 선택", font=("Arial", 12)).pack(pady=5)
        self.coin_var = tk.StringVar(self.master)
        self.coin_var.set("tlk")  # 기본은 TLK
        tk.OptionMenu(self.send_frame, self.coin_var, "tlk", "eth", "btc").pack(pady=5)

        tk.Label(self.send_frame, text="수량", font=("Arial", 12)).pack(pady=5)
        self.amount_entry = tk.Entry(self.send_frame)
        self.amount_entry.pack(pady=5)

        tk.Button(self.send_frame, text="전송하기", font=("Arial", 14),
                  command=self.send_coin_action).pack(pady=10)

        tk.Button(self.send_frame, text="뒤로가기", font=("Arial", 12),
                  command=self.open_wallet_window).pack(pady=20)

    def send_coin_action(self):
        recipient = self.recipient_entry.get().strip()
        coin_type = self.coin_var.get()
        amount_text = self.amount_entry.get().strip()

        if not recipient or not amount_text:
            messagebox.showerror("오류", "모든 입력란을 채워주세요.")
            return

        try:
            amount = float(amount_text)
            if amount <= 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("오류", "올바른 수량을 입력하세요.")
            return

        if recipient not in self.user_data:
            messagebox.showerror("오류", "받는 사용자가 존재하지 않습니다.")
            return

        if self.user_data[self.user_id]['wallet'][coin_type] < amount:
            messagebox.showerror("오류", "잔액 부족")
            return

        # 전송
        self.user_data[self.user_id]['wallet'][coin_type] -= amount
        self.user_data[recipient]['wallet'][coin_type] += amount
        self.save_user_data()

        self.save_log("코인 전송", f"{coin_type.upper()} {amount} -> {recipient}")
        messagebox.showinfo("성공", f"{recipient}님에게 {amount} {coin_type.upper()} 전송 완료!")
        self.open_wallet_window()

    def open_buy_tlk(self):
        self.clear_screen()
        self.buy_tlk_frame = tk.Frame(self.master)
        self.buy_tlk_frame.pack(fill="both", expand=True)

        tk.Label(self.buy_tlk_frame, text="TLK 구매", font=("Arial", 20, "bold")).pack(pady=20)

        tk.Label(self.buy_tlk_frame, text="구매할 TLK 수량", font=("Arial", 12)).pack(pady=5)
        self.buy_tlk_entry = tk.Entry(self.buy_tlk_frame)
        self.buy_tlk_entry.pack(pady=5)

        tk.Button(self.buy_tlk_frame, text="구매하기", font=("Arial", 14),
                  command=self.buy_tlk_action).pack(pady=10)

        tk.Button(self.buy_tlk_frame, text="뒤로가기", font=("Arial", 12),
                  command=self.open_wallet_window).pack(pady=20)

    def buy_tlk_action(self):
        amount_text = self.buy_tlk_entry.get().strip()

        try:
            amount = float(amount_text)
            if amount <= 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("오류", "올바른 수량을 입력하세요.")
            return

        self.user_data[self.user_id]['wallet']['tlk'] += amount
        self.save_user_data()
        self.save_log("TLK 구매", f"TLK {amount} 구매 완료")
        messagebox.showinfo("성공", f"TLK {amount}개 구매 완료!")
        self.open_wallet_window()

    def open_tlk_transaction_log(self):
        self.clear_screen()
        self.log_frame = tk.Frame(self.master)
        self.log_frame.pack(fill="both", expand=True)

        tk.Label(self.log_frame, text="송금 기록", font=("Arial", 20, "bold")).pack(pady=20)

        if os.path.exists('log_data.json'):
            with open('log_data.json', 'r', encoding='utf-8') as f:
                logs = json.load(f)
        else:
            logs = []

        user_logs = [log for log in logs if log['user'] == self.user_id and "전송" in log['action']]

        if not user_logs:
            tk.Label(self.log_frame, text="송금 기록이 없습니다.", font=("Arial", 14)).pack(pady=10)
        else:
            listbox = tk.Listbox(self.log_frame, font=("Arial", 12))
            listbox.pack(fill="both", expand=True, padx=10, pady=10)

            for log in reversed(user_logs):
                listbox.insert(tk.END, f"[{log['time']}] {log['details']}")

        tk.Button(self.log_frame, text="뒤로가기", font=("Arial", 12),
                  command=self.open_wallet_window).pack(pady=20)

    def open_settings(self):
        self.clear_screen()
        self.settings_frame = tk.Frame(self.master)
        self.settings_frame.pack(fill="both", expand=True)

        tk.Label(self.settings_frame, text="설정", font=("Arial", 20, "bold")).pack(pady=20)

        tk.Button(self.settings_frame, text="비밀번호 변경", font=("Arial", 14),
                  command=self.change_password).pack(pady=10)
        tk.Button(self.settings_frame, text="테마 변경", font=("Arial", 14),
                  command=self.theme_selector).pack(pady=10)
        tk.Button(self.settings_frame, text="다국어 설정", font=("Arial", 14),
                  command=self.language_selector).pack(pady=10)
        tk.Button(self.settings_frame, text="뒤로가기", font=("Arial", 12),
                  command=self.build_main_screen).pack(pady=20)

    def change_password(self):
        self.clear_screen()
        self.change_pw_frame = tk.Frame(self.master)
        self.change_pw_frame.pack(fill="both", expand=True)

        tk.Label(self.change_pw_frame, text="비밀번호 변경", font=("Arial", 20, "bold")).pack(pady=20)

        tk.Label(self.change_pw_frame, text="현재 비밀번호", font=("Arial", 12)).pack(pady=5)
        self.current_pw_entry = tk.Entry(self.change_pw_frame, show="*")
        self.current_pw_entry.pack(pady=5)

        tk.Label(self.change_pw_frame, text="새 비밀번호", font=("Arial", 12)).pack(pady=5)
        self.new_pw_entry = tk.Entry(self.change_pw_frame, show="*")
        self.new_pw_entry.pack(pady=5)

        tk.Button(self.change_pw_frame, text="변경하기", font=("Arial", 14),
                  command=self.change_password_action).pack(pady=10)

        tk.Button(self.change_pw_frame, text="뒤로가기", font=("Arial", 12),
                  command=self.open_settings).pack(pady=20)

    def change_password_action(self):
        current_pw = self.current_pw_entry.get().strip()
        new_pw = self.new_pw_entry.get().strip()

        if not current_pw or not new_pw:
            messagebox.showerror("오류", "모든 입력란을 채워주세요.")
            return

        if current_pw != self.user_data[self.user_id]['password']:
            messagebox.showerror("오류", "현재 비밀번호가 일치하지 않습니다.")
            return

        self.user_data[self.user_id]['password'] = new_pw
        self.save_user_data()
        self.save_log("비밀번호 변경", f"성공")
        messagebox.showinfo("성공", "비밀번호가 변경되었습니다.")
        self.build_main_screen()

    def language_selector(self):
        self.clear_screen()
        self.language_frame = tk.Frame(self.master)
        self.language_frame.pack(fill="both", expand=True)

        tk.Label(self.language_frame, text="언어 설정", font=("Arial", 20, "bold")).pack(pady=20)

        tk.Button(self.language_frame, text="한국어 (Korean)", font=("Arial", 14),
                  command=lambda: self.set_language("ko")).pack(pady=10)
        tk.Button(self.language_frame, text="영어 (English)", font=("Arial", 14),
                  command=lambda: self.set_language("en")).pack(pady=10)
        tk.Button(self.language_frame, text="일본어 (Japanese)", font=("Arial", 14),
                  command=lambda: self.set_language("jp")).pack(pady=10)
        tk.Button(self.language_frame, text="베트남어 (Vietnamese)", font=("Arial", 14),
                  command=lambda: self.set_language("vi")).pack(pady=10)
        tk.Button(self.language_frame, text="중국어 (Chinese)", font=("Arial", 14),
                  command=lambda: self.set_language("zh")).pack(pady=10)

        tk.Button(self.language_frame, text="뒤로가기", font=("Arial", 12),
                  command=self.open_settings).pack(pady=20)

    def set_language(self, lang_code):
        self.user_data[self.user_id]['language'] = lang_code
        self.save_user_data()
        messagebox.showinfo("성공", f"언어가 {lang_code.upper()}로 변경되었습니다.")
        self.open_settings()

    def theme_selector(self):
        self.clear_screen()
        self.theme_frame = tk.Frame(self.master)
        self.theme_frame.pack(fill="both", expand=True)

        tk.Label(self.theme_frame, text="테마 선택", font=("Arial", 20, "bold")).pack(pady=20)

        tk.Button(self.theme_frame, text="라이트 모드", font=("Arial", 14),
                  command=lambda: self.set_theme("light")).pack(pady=10)
        tk.Button(self.theme_frame, text="다크 모드", font=("Arial", 14),
                  command=lambda: self.set_theme("dark")).pack(pady=10)
        tk.Button(self.theme_frame, text="핑크 모드", font=("Arial", 14),
                  command=lambda: self.set_theme("pink")).pack(pady=10)

        tk.Button(self.theme_frame, text="뒤로가기", font=("Arial", 12),
                  command=self.open_settings).pack(pady=20)

    def set_theme(self, theme_name):
        self.user_data[self.user_id]['theme'] = theme_name
        self.save_user_data()
        messagebox.showinfo("성공", f"{theme_name.capitalize()} 테마가 적용되었습니다.")
        self.apply_theme()

    def apply_theme(self):
        theme = self.user_data[self.user_id].get('theme', 'light')

        if theme == "light":
            self.master.config(bg="white")
        elif theme == "dark":
            self.master.config(bg="#2c2c2c")
        elif theme == "pink":
            self.master.config(bg="#ffe6f0")
        else:
            self.master.config(bg="white")

    def open_marketplace(self):
        self.clear_screen()
        self.market_frame = tk.Frame(self.master)
        self.market_frame.pack(fill="both", expand=True)

        tk.Label(self.market_frame, text="NFT 마켓", font=("Arial", 20, "bold")).pack(pady=20)

        self.nft_listbox = tk.Listbox(self.market_frame, font=("Arial", 12))
        self.nft_listbox.pack(pady=10, fill="both", expand=True)

        for nft in self.available_nfts:
            self.nft_listbox.insert(tk.END, f"{nft['name']} - {nft['price']} TLK")

        tk.Button(self.market_frame, text="NFT 구매", font=("Arial", 14),
                  command=self.purchase_nft).pack(pady=10)
        tk.Button(self.market_frame, text="뒤로가기", font=("Arial", 12),
                  command=self.build_main_screen).pack(pady=20)

    def purchase_nft(self):
        selected = self.nft_listbox.curselection()
        if not selected:
            messagebox.showerror("오류", "구매할 NFT를 선택하세요.")
            return

        nft = self.available_nfts[selected[0]]
        price = nft['price']

        if self.wallet['balance'] < price:
            messagebox.showerror("오류", "잔액이 부족합니다.")
            return

        confirm = messagebox.askyesno("구매 확인", f"{nft['name']}을(를) {price} TLK에 구매하시겠습니까?")
        if confirm:
            self.wallet['balance'] -= price
            self.user_data[self.user_id]['wallet']['balance'] = self.wallet['balance']

            owned_nfts = self.user_data[self.user_id].get('nfts', [])
            owned_nfts.append(nft)
            self.user_data[self.user_id]['nfts'] = owned_nfts

            self.save_user_data()
            self.save_log("NFT 구매", f"{nft['name']} ({price} TLK)")
            messagebox.showinfo("구매 완료", f"{nft['name']} NFT가 내 소장품에 추가되었습니다.")
            self.build_main_screen()

    def initialize_nft_market(self):
        self.available_nfts = [
            {"name": "핑크 고래", "price": 50},
            {"name": "바이올렛 토끼", "price": 75},
            {"name": "골드 독수리", "price": 100},
            {"name": "제로 크리스탈", "price": 200},
            {"name": "플래티넘 여우", "price": 300},
        ]

    def open_my_nfts(self):
        self.clear_screen()
        self.my_nft_frame = tk.Frame(self.master)
        self.my_nft_frame.pack(fill="both", expand=True)

        tk.Label(self.my_nft_frame, text="내 NFT 소장품", font=("Arial", 20, "bold")).pack(pady=20)

        my_nfts = self.user_data[self.user_id].get('nfts', [])

        if not my_nfts:
            tk.Label(self.my_nft_frame, text="소장한 NFT가 없습니다.", font=("Arial", 14)).pack(pady=10)
        else:
            listbox = tk.Listbox(self.my_nft_frame, font=("Arial", 12))
            listbox.pack(pady=10, fill="both", expand=True)

            for nft in my_nfts:
                listbox.insert(tk.END, nft['name'])

        tk.Button(self.my_nft_frame, text="뒤로가기", font=("Arial", 12),
                  command=self.build_main_screen).pack(pady=20)

    def open_settings(self):
        self.clear_screen()
        self.settings_frame = tk.Frame(self.master)
        self.settings_frame.pack(fill="both", expand=True)

        tk.Label(self.settings_frame, text="설정", font=("Arial", 20, "bold")).pack(pady=20)

        tk.Button(self.settings_frame, text="테마 변경", font=("Arial", 14),
                  command=self.theme_selector).pack(pady=10)
        tk.Button(self.settings_frame, text="다국어 설정", font=("Arial", 14),
                  command=self.language_selector).pack(pady=10)
        tk.Button(self.settings_frame, text="내 NFT 보기", font=("Arial", 14),
                  command=self.open_my_nfts).pack(pady=10)
        tk.Button(self.settings_frame, text="뒤로가기", font=("Arial", 12),
                  command=self.build_main_screen).pack(pady=20)

    def language_selector(self):
        self.clear_screen()
        self.lang_frame = tk.Frame(self.master)
        self.lang_frame.pack(fill="both", expand=True)

        tk.Label(self.lang_frame, text="언어 선택", font=("Arial", 20, "bold")).pack(pady=20)

        languages = ["한국어", "English", "日本語", "中文", "Español", "Français", "Deutsch", "Português", "العربية"]
        self.language_var = tk.StringVar(value=self.user_data[self.user_id].get('language', "한국어"))

        for lang in languages:
            tk.Radiobutton(self.lang_frame, text=lang, variable=self.language_var, value=lang,
                           font=("Arial", 14)).pack(anchor="w", padx=20)

        tk.Button(self.lang_frame, text="저장", font=("Arial", 14),
                  command=self.save_language).pack(pady=20)
        tk.Button(self.lang_frame, text="뒤로가기", font=("Arial", 12),
                  command=self.open_settings).pack(pady=10)

    def save_language(self):
        selected_lang = self.language_var.get()
        self.user_data[self.user_id]['language'] = selected_lang
        self.save_user_data()
        messagebox.showinfo("성공", f"{selected_lang}로 언어가 설정되었습니다.")
        self.build_main_screen()

    def show_coin_prices(self):
        self.clear_screen()
        self.coin_frame = tk.Frame(self.master)
        self.coin_frame.pack(fill="both", expand=True)

        tk.Label(self.coin_frame, text="코인 실시간 시세", font=("Arial", 20, "bold")).pack(pady=20)

        self.coin_prices_box = tk.Text(self.coin_frame, font=("Arial", 12), height=15, state="disabled")
        self.coin_prices_box.pack(pady=10, fill="both", expand=True)

        tk.Button(self.coin_frame, text="새로고침", font=("Arial", 14),
                  command=self.update_coin_prices).pack(pady=5)
        tk.Button(self.coin_frame, text="뒤로가기", font=("Arial", 12),
                  command=self.build_main_screen).pack(pady=10)

        self.update_coin_prices()

    def update_coin_prices(self):
        try:
            import requests
            coins = ['bitcoin', 'ethereum', 'solana', 'ripple', 'tron']
            response = requests.get(
                'https://api.coingecko.com/api/v3/simple/price',
                params={'ids': ','.join(coins), 'vs_currencies': 'usd'}
            )
            data = response.json()

            self.coin_prices_box.config(state="normal")
            self.coin_prices_box.delete("1.0", tk.END)

            for coin in coins:
                price = data[coin]['usd']
                self.coin_prices_box.insert(tk.END, f"{coin.capitalize()}: ${price:,.2f}\n")

            self.coin_prices_box.config(state="disabled")
        except Exception as e:
            messagebox.showerror("오류", f"시세 조회 실패: {str(e)}")

    def open_wallet_screen(self):
        self.clear_screen()
        self.wallet_frame = tk.Frame(self.master)
        self.wallet_frame.pack(fill="both", expand=True)

        tk.Label(self.wallet_frame, text="내 지갑", font=("Arial", 20, "bold")).pack(pady=20)

        tk.Label(self.wallet_frame, text=f"주소: {self.wallet['address']}", font=("Arial", 12)).pack(pady=5)
        tk.Label(self.wallet_frame, text=f"잔액: {self.wallet['balance']} TLK", font=("Arial", 12)).pack(pady=5)

        tk.Button(self.wallet_frame, text="코인 송금", font=("Arial", 14),
                  command=self.open_send_coin_window).pack(pady=10)
        tk.Button(self.wallet_frame, text="뒤로가기", font=("Arial", 12),
                  command=self.build_main_screen).pack(pady=20)

    def open_send_coin_window(self):
        self.wallet_frame.destroy()
        self.send_coin_frame = tk.Frame(self.master)
        self.send_coin_frame.pack(fill="both", expand=True)

        tk.Label(self.send_coin_frame, text="코인 보내기", font=("Arial", 20, "bold")).pack(pady=20)

        tk.Label(self.send_coin_frame, text="받는 사람 지갑 주소", font=("Arial", 12)).pack(pady=5)
        self.send_address_entry = tk.Entry(self.send_coin_frame)
        self.send_address_entry.pack(pady=5)

        tk.Label(self.send_coin_frame, text="보낼 금액 (TLK)", font=("Arial", 12)).pack(pady=5)
        self.send_amount_entry = tk.Entry(self.send_coin_frame)
        self.send_amount_entry.pack(pady=5)

        tk.Button(self.send_coin_frame, text="송금하기", font=("Arial", 14),
                  command=self.confirm_send_coin).pack(pady=10)
        tk.Button(self.send_coin_frame, text="뒤로가기", font=("Arial", 12),
                  command=self.open_wallet_screen).pack(pady=20)

    def confirm_send_coin(self):
        address = self.send_address_entry.get().strip()
        amount_text = self.send_amount_entry.get().strip()

        if not address or not amount_text:
            messagebox.showerror("오류", "모든 항목을 채워주세요.")
            return

        try:
            amount = float(amount_text)
            if amount <= 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("오류", "금액은 양수여야 합니다.")
            return

        if self.wallet['balance'] < amount:
            messagebox.showerror("오류", "잔액이 부족합니다.")
            return

        confirm = messagebox.askyesno("확인", f"{amount} TLK를 보내시겠습니까?")
        if confirm:
            self.wallet['balance'] -= amount
            self.save_user_data()
            self.save_log("코인 전송", f"{amount} TLK to {address}")
            messagebox.showinfo("완료", f"{amount} TLK를 송금했습니다.")
            self.open_wallet_screen()

    def open_my_nfts(self):
        self.clear_screen()
        self.nft_frame = tk.Frame(self.master)
        self.nft_frame.pack(fill="both", expand=True)

        tk.Label(self.nft_frame, text="내 NFT 컬렉션", font=("Arial", 20, "bold")).pack(pady=20)

        if self.user_data[self.user_id].get('nfts'):
            for nft in self.user_data[self.user_id]['nfts']:
                nft_label = tk.Label(self.nft_frame, text=f"{nft['name']} - {nft['description']}",
                                     font=("Arial", 12), wraplength=350)
                nft_label.pack(pady=5)
        else:
            tk.Label(self.nft_frame, text="보유한 NFT가 없습니다.", font=("Arial", 12)).pack(pady=10)

        tk.Button(self.nft_frame, text="뒤로가기", font=("Arial", 12),
                  command=self.build_main_screen).pack(pady=20)

    def open_nft_market(self):
        self.clear_screen()
        self.market_frame = tk.Frame(self.master)
        self.market_frame.pack(fill="both", expand=True)

        tk.Label(self.market_frame, text="NFT 마켓", font=("Arial", 20, "bold")).pack(pady=20)

        self.nft_market_list = [
            {"name": "제로 드래곤", "description": "희귀 드래곤 NFT", "price": 100},
            {"name": "제로 유니콘", "description": "전설의 유니콘 NFT", "price": 150},
            {"name": "제로 고양이", "description": "귀여운 고양이 NFT", "price": 50},
        ]

        for idx, nft in enumerate(self.nft_market_list):
            frame = tk.Frame(self.market_frame)
            frame.pack(pady=5)

            tk.Label(frame, text=f"{nft['name']} - {nft['price']} TLK", font=("Arial", 12)).pack(side="left", padx=10)
            tk.Button(frame, text="구매", font=("Arial", 10),
                      command=lambda idx=idx: self.purchase_nft(idx)).pack(side="right", padx=10)

        tk.Button(self.market_frame, text="뒤로가기", font=("Arial", 12),
                  command=self.build_main_screen).pack(pady=20)

    def purchase_nft(self, idx):
        nft = self.nft_market_list[idx]
        price = nft['price']

        if self.wallet['balance'] < price:
            messagebox.showerror("구매 실패", "잔액이 부족합니다.")
            return

        confirm = messagebox.askyesno("구매 확인", f"{nft['name']}를 {price} TLK로 구매하시겠습니까?")
        if confirm:
            self.wallet['balance'] -= price
            user_nfts = self.user_data[self.user_id].get('nfts', [])
            user_nfts.append(nft)
            self.user_data[self.user_id]['nfts'] = user_nfts
            self.save_user_data()
            self.save_log("NFT 구매", f"{nft['name']} ({price} TLK)")
            messagebox.showinfo("구매 완료", f"{nft['name']} NFT를 구매했습니다.")
            self.open_nft_market()

    def change_theme(self):
        self.clear_screen()
        self.theme_frame = tk.Frame(self.master)
        self.theme_frame.pack(fill="both", expand=True)

        tk.Label(self.theme_frame, text="테마 변경", font=("Arial", 20, "bold")).pack(pady=20)

        themes = ["연핑크", "화이트", "다크", "블루", "퍼플"]

        self.theme_var = tk.StringVar(value=self.user_data[self.user_id].get('theme', "연핑크"))

        for theme in themes:
            tk.Radiobutton(self.theme_frame, text=theme, variable=self.theme_var, value=theme,
                           font=("Arial", 14)).pack(anchor="w", padx=20)

        tk.Button(self.theme_frame, text="테마 저장", font=("Arial", 14),
                  command=self.save_theme).pack(pady=20)
        tk.Button(self.theme_frame, text="뒤로가기", font=("Arial", 12),
                  command=self.open_settings).pack(pady=10)

    def save_theme(self):
        selected_theme = self.theme_var.get()
        self.user_data[self.user_id]['theme'] = selected_theme
        self.save_user_data()
        messagebox.showinfo("완료", f"{selected_theme} 테마가 적용되었습니다.")
        self.build_main_screen()

    def setup_theme_colors(self):
        theme = self.user_data[self.user_id].get('theme', '연핑크')

        if theme == "연핑크":
            self.bg_color = "#ffe6f0"
            self.text_color = "#000000"
            self.button_color = "#ff99cc"
        elif theme == "화이트":
            self.bg_color = "#ffffff"
            self.text_color = "#000000"
            self.button_color = "#cccccc"
        elif theme == "다크":
            self.bg_color = "#222222"
            self.text_color = "#ffffff"
            self.button_color = "#444444"
        elif theme == "블루":
            self.bg_color = "#e6f2ff"
            self.text_color = "#000000"
            self.button_color = "#99ccff"
        elif theme == "퍼플":
            self.bg_color = "#f3e6ff"
            self.text_color = "#000000"
            self.button_color = "#cc99ff"
        else:
            self.bg_color = "#ffffff"
            self.text_color = "#000000"
            self.button_color = "#cccccc"

    def apply_theme(self):
        self.master.configure(bg=self.bg_color)
        for widget in self.master.winfo_children():
            try:
                widget.configure(bg=self.bg_color, fg=self.text_color)
            except:
                pass

    def switch_screen(self, screen_func):
        self.clear_screen()
        self.setup_theme_colors()
        self.apply_theme()
        screen_func()

    def build_main_screen(self):
        self.switch_screen(self.build_main_screen_content)

    def build_main_screen_content(self):
        self.main_frame = tk.Frame(self.master, bg=self.bg_color)
        self.main_frame.pack(fill="both", expand=True)

        tk.Label(self.main_frame, text=f"ZeroTalk - {self.user_id}", font=("Arial", 20, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=20)

        tk.Button(self.main_frame, text="친구 목록", font=("Arial", 14),
                  command=self.show_friends_window).pack(pady=10)

        tk.Button(self.main_frame, text="채팅하기", font=("Arial", 14),
                  command=self.show_chat_window).pack(pady=10)

        tk.Button(self.main_frame, text="지갑 보기", font=("Arial", 14),
                  command=self.open_wallet_screen).pack(pady=10)

        tk.Button(self.main_frame, text="NFT 마켓", font=("Arial", 14),
                  command=self.open_nft_market).pack(pady=10)

        tk.Button(self.main_frame, text="설정", font=("Arial", 14),
                  command=self.open_settings).pack(pady=10)

        tk.Button(self.main_frame, text="로그아웃", font=("Arial", 12),
                  command=self.logout).pack(pady=20)

    def open_settings(self):
        self.switch_screen(self.open_settings_content)

    def open_settings_content(self):
        self.settings_frame = tk.Frame(self.master, bg=self.bg_color)
        self.settings_frame.pack(fill="both", expand=True)

        tk.Label(self.settings_frame, text="설정", font=("Arial", 20, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=20)

        tk.Button(self.settings_frame, text="테마 변경", font=("Arial", 14),
                  command=self.change_theme).pack(pady=10)

        tk.Button(self.settings_frame, text="비밀번호 변경", font=("Arial", 14),
                  command=self.change_password).pack(pady=10)

        tk.Button(self.settings_frame, text="수익 분석 보기", font=("Arial", 14),
                  command=self.open_revenue_dashboard).pack(pady=10)

        tk.Button(self.settings_frame, text="뒤로 가기", font=("Arial", 12),
                  command=self.build_main_screen).pack(pady=20)

    def change_password(self):
        self.clear_screen()

        tk.Label(self.master, text="기존 비밀번호", font=("Arial", 14)).pack(pady=10)
        self.old_pw_entry = tk.Entry(self.master, show="*")
        self.old_pw_entry.pack(pady=5)

        tk.Label(self.master, text="새 비밀번호", font=("Arial", 14)).pack(pady=10)
        self.new_pw_entry = tk.Entry(self.master, show="*")
        self.new_pw_entry.pack(pady=5)

        tk.Button(self.master, text="비밀번호 변경", font=("Arial", 14),
                  command=self.update_password).pack(pady=20)
        tk.Button(self.master, text="뒤로 가기", font=("Arial", 12),
                  command=self.build_main_screen).pack()

    def update_password(self):
        old_pw = self.old_pw_entry.get()
        new_pw = self.new_pw_entry.get()

        if self.user_data[self.user_id]['password'] != old_pw:
            messagebox.showerror("오류", "기존 비밀번호가 일치하지 않습니다.")
            return

        if len(new_pw) < 4:
            messagebox.showerror("오류", "새 비밀번호는 최소 4자 이상이어야 합니다.")
            return

        self.user_data[self.user_id]['password'] = new_pw
        self.save_user_data()
        messagebox.showinfo("완료", "비밀번호가 변경되었습니다.")
        self.build_main_screen()

    def open_revenue_dashboard(self):
        self.clear_screen()

        self.revenue_frame = tk.Frame(self.master, bg=self.bg_color)
        self.revenue_frame.pack(fill="both", expand=True)

        tk.Label(self.revenue_frame, text="수익 대시보드", font=("Arial", 20, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=20)

        total_tlk_sales = self.calculate_total_tlk_sales()
        total_nft_sales = self.calculate_total_nft_sales()

        tk.Label(self.revenue_frame, text=f"TLK 토큰 판매 수익: {total_tlk_sales} 원",
                 font=("Arial", 14), bg=self.bg_color, fg=self.text_color).pack(pady=10)

        tk.Label(self.revenue_frame, text=f"NFT 판매 수익: {total_nft_sales} 원",
                 font=("Arial", 14), bg=self.bg_color, fg=self.text_color).pack(pady=10)

        tk.Button(self.revenue_frame, text="뒤로 가기", font=("Arial", 12),
                  command=self.build_main_screen).pack(pady=20)

    def calculate_total_tlk_sales(self):
        total = 0
        if os.path.exists('tlk_sales.json'):
            with open('tlk_sales.json', 'r') as f:
                sales = json.load(f)
            for sale in sales:
                total += sale.get('amount', 0)
        return total * 1000  # TLK 1개 1,000원 고정

    def calculate_total_nft_sales(self):
        total = 0
        if os.path.exists('nft_sales.json'):
            with open('nft_sales.json', 'r') as f:
                sales = json.load(f)
            for sale in sales:
                total += sale.get('price', 0)
        return total * 1000

    def open_coin_market(self):
        self.clear_screen()

        self.coin_market_frame = tk.Frame(self.master, bg=self.bg_color)
        self.coin_market_frame.pack(fill="both", expand=True)

        tk.Label(self.coin_market_frame, text="코인 시세 보기", font=("Arial", 20, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=20)

        # 시세 조회 예시 (실제 구현 시 API 연동)
        coin_prices = {
            "Bitcoin (BTC)": "89,000,000 원",
            "Ethereum (ETH)": "4,500,000 원",
            "Solana (SOL)": "140,000 원",
            "XRP (XRP)": "800 원",
            "TRON (TRX)": "150 원"
        }

        for coin, price in coin_prices.items():
            tk.Label(self.coin_market_frame, text=f"{coin}: {price}",
                     font=("Arial", 14), bg=self.bg_color, fg=self.text_color).pack(pady=5)

        tk.Button(self.coin_market_frame, text="뒤로가기", font=("Arial", 12),
                  command=self.build_main_screen).pack(pady=20)

    def launch_nft_store(self):
        self.clear_screen()

        self.nft_store_frame = tk.Frame(self.master, bg=self.bg_color)
        self.nft_store_frame.pack(fill="both", expand=True)

        tk.Label(self.nft_store_frame, text="NFT 스토어", font=("Arial", 20, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=20)

        self.list_nft_products()

        tk.Button(self.nft_store_frame, text="뒤로가기", font=("Arial", 12),
                  command=self.build_main_screen).pack(pady=20)

    def list_nft_products(self):
        nft_products = [
            {"title": "제로 유니콘 #1", "price": 200},
            {"title": "제로 드래곤 #5", "price": 300},
            {"title": "제로 고양이 #7", "price": 100}
        ]

        for nft in nft_products:
            frame = tk.Frame(self.nft_store_frame, bg=self.bg_color)
            frame.pack(pady=10)

            tk.Label(frame, text=f"{nft['title']} - {nft['price']} TLK",
                     font=("Arial", 12), bg=self.bg_color, fg=self.text_color).pack(side="left", padx=5)

            tk.Button(frame, text="구매", command=lambda n=nft: self.buy_nft(n)).pack(side="right", padx=5)

    def buy_nft(self, nft):
        confirm = messagebox.askyesno("구매 확인", f"{nft['title']}를 {nft['price']} TLK에 구매하시겠습니까?")
        if confirm:
            if self.wallet['balance'] >= nft['price']:
                self.wallet['balance'] -= nft['price']
                self.user_data[self.user_id]['wallet']['balance'] = self.wallet['balance']

                owned_nfts = self.user_data[self.user_id].get('owned_nfts', [])
                owned_nfts.append(nft)
                self.user_data[self.user_id]['owned_nfts'] = owned_nfts

                self.save_user_data()
                self.save_log("NFT 구매", nft['title'])
                messagebox.showinfo("구매 완료", f"{nft['title']} NFT를 구매했습니다.")
            else:
                messagebox.showerror("오류", "잔액이 부족합니다.")

    def view_owned_nfts(self):
        self.clear_screen()

        self.owned_nfts_frame = tk.Frame(self.master, bg=self.bg_color)
        self.owned_nfts_frame.pack(fill="both", expand=True)

        tk.Label(self.owned_nfts_frame, text="내 NFT 보관함", font=("Arial", 20, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=20)

        owned_nfts = self.user_data[self.user_id].get('owned_nfts', [])

        if not owned_nfts:
            tk.Label(self.owned_nfts_frame, text="보유한 NFT가 없습니다.",
                     font=("Arial", 14), bg=self.bg_color, fg=self.text_color).pack(pady=10)
        else:
            for nft in owned_nfts:
                tk.Label(self.owned_nfts_frame, text=f"{nft['title']} - {nft['price']} TLK",
                         font=("Arial", 12), bg=self.bg_color, fg=self.text_color).pack(pady=5)

        tk.Button(self.owned_nfts_frame, text="뒤로가기", font=("Arial", 12),
                  command=self.build_main_screen).pack(pady=20)

    def view_chat_history(self):
        self.clear_screen()

        self.chat_history_frame = tk.Frame(self.master, bg=self.bg_color)
        self.chat_history_frame.pack(fill="both", expand=True)

        tk.Label(self.chat_history_frame, text="채팅 기록 보기", font=("Arial", 20, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=20)

        chat_file = f"chat_history_{self.user_id}.json"

        if not os.path.exists(chat_file):
            tk.Label(self.chat_history_frame, text="채팅 기록이 없습니다.",
                     font=("Arial", 14), bg=self.bg_color, fg=self.text_color).pack(pady=10)
        else:
            with open(chat_file, 'r', encoding='utf-8') as f:
                chats = json.load(f)
            for chat in chats:
                tk.Label(self.chat_history_frame, text=f"{chat['time']} - {chat['message']}",
                         font=("Arial", 10), bg=self.bg_color, fg=self.text_color).pack(anchor="w", padx=10)

        tk.Button(self.chat_history_frame, text="뒤로가기", font=("Arial", 12),
                  command=self.build_main_screen).pack(pady=20)

    def save_chat(self, message):
        chat_file = f"chat_history_{self.user_id}.json"
        chat_log = []

        if os.path.exists(chat_file):
            with open(chat_file, 'r', encoding='utf-8') as f:
                chat_log = json.load(f)

        chat_log.append({
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "message": message
        })

        with open(chat_file, 'w', encoding='utf-8') as f:
            json.dump(chat_log, f, ensure_ascii=False, indent=4)

    def send_chat_message(self, event=None):
        message = self.chat_entry.get().strip()

        if not message:
            return

        self.chat_log.config(state="normal")
        formatted_message = f"{self.user_id}: {message}"
        self.chat_log.insert(tk.END, formatted_message + "\n")
        self.chat_log.config(state="disabled")
        self.chat_log.see(tk.END)

        self.save_chat(formatted_message)
        self.chat_entry.delete(0, tk.END)

    def add_block_user(self):
        selected = self.friend_listbox.curselection()

        if not selected:
            messagebox.showerror("오류", "차단할 친구를 선택하세요.")
            return

        friend_id = self.friend_listbox.get(selected)

        confirm = messagebox.askyesno("확인", f"{friend_id}님을 차단하시겠습니까?")
        if confirm:
            self.blocked.append(friend_id)
            self.user_data[self.user_id]['blocked'] = self.blocked
            self.friends.remove(friend_id)
            self.user_data[self.user_id]['friends'] = self.friends
            self.save_user_data()
            self.friend_listbox.delete(selected)
            messagebox.showinfo("완료", f"{friend_id}님을 차단했습니다.")

    def view_blocked_list(self):
        self.clear_screen()

        self.blocked_frame = tk.Frame(self.master, bg=self.bg_color)
        self.blocked_frame.pack(fill="both", expand=True)

        tk.Label(self.blocked_frame, text="차단된 사용자", font=("Arial", 20, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=20)

        if not self.blocked:
            tk.Label(self.blocked_frame, text="차단된 사용자가 없습니다.",
                     font=("Arial", 14), bg=self.bg_color, fg=self.text_color).pack(pady=10)
        else:
            for user in self.blocked:
                tk.Label(self.blocked_frame, text=user,
                         font=("Arial", 12), bg=self.bg_color, fg=self.text_color).pack(pady=5)

        tk.Button(self.blocked_frame, text="뒤로가기", font=("Arial", 12),
                  command=self.build_main_screen).pack(pady=20)

    def withdraw_account(self):
        confirm = messagebox.askyesno("회원 탈퇴", "정말로 탈퇴하시겠습니까?\n모든 데이터가 삭제됩니다.")

        if confirm:
            if self.user_id in self.user_data:
                del self.user_data[self.user_id]
                self.save_user_data()
                self.save_log("회원 탈퇴", f"ID: {self.user_id}")
                messagebox.showinfo("탈퇴 완료", "회원 탈퇴가 완료되었습니다.")
                self.user_id = None
                self.password = None
                self.friends = []
                self.blocked = []
                self.wallet = {}
                self.build_login_screen()

    def open_settings_window(self):
        self.clear_screen()

        self.settings_frame = tk.Frame(self.master, bg=self.bg_color)
        self.settings_frame.pack(fill="both", expand=True)

        tk.Label(self.settings_frame, text="설정", font=("Arial", 20, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=20)

        tk.Button(self.settings_frame, text="배경 테마 변경", font=("Arial", 14),
                  command=self.open_theme_selector).pack(pady=10)

        tk.Button(self.settings_frame, text="차단 목록 보기", font=("Arial", 14),
                  command=self.view_blocked_list).pack(pady=10)

        tk.Button(self.settings_frame, text="회원 탈퇴", font=("Arial", 14),
                  command=self.withdraw_account).pack(pady=10)

        tk.Button(self.settings_frame, text="뒤로 가기", font=("Arial", 12),
                  command=self.build_main_screen).pack(pady=20)

    def open_theme_selector(self):
        self.theme_win = tk.Toplevel(self.master)
        self.theme_win.title("테마 변경")
        self.theme_win.geometry("300x300")

        tk.Label(self.theme_win, text="테마 색상 선택", font=("Arial", 14)).pack(pady=10)

        colors = [("화이트", "white", "black"),
                  ("블랙", "black", "white"),
                  ("핑크", "#ffe6f0", "#99004d"),
                  ("민트", "#e0f7fa", "#00695c"),
                  ("네이비", "#1a237e", "white")]

        for name, bg, fg in colors:
            btn = tk.Button(self.theme_win, text=name, bg=bg, fg=fg,
                            command=lambda b=bg, f=fg: self.change_theme(b, f))
            btn.pack(pady=5, fill="x", padx=20)

    def change_theme(self, bg, fg):
        self.bg_color = bg
        self.text_color = fg
        self.theme_win.destroy()
        self.build_main_screen()

    def show_wallet_screen(self):
        self.clear_screen()

        self.wallet_frame = tk.Frame(self.master, bg=self.bg_color)
        self.wallet_frame.pack(fill="both", expand=True)

        tk.Label(self.wallet_frame, text="내 지갑", font=("Arial", 20, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=20)

        address = self.wallet.get('address', '주소 없음')
        balance = self.wallet.get('balance', 0)

        tk.Label(self.wallet_frame, text=f"지갑 주소: {address}",
                 font=("Arial", 12), bg=self.bg_color, fg=self.text_color).pack(pady=5)

        tk.Label(self.wallet_frame, text=f"잔액: {balance} TLK",
                 font=("Arial", 12), bg=self.bg_color, fg=self.text_color).pack(pady=5)

        tk.Button(self.wallet_frame, text="코인 전송", font=("Arial", 14),
                  command=self.send_coin_screen).pack(pady=10)

        tk.Button(self.wallet_frame, text="뒤로 가기", font=("Arial", 12),
                  command=self.build_main_screen).pack(pady=20)

    def send_coin_screen(self):
        self.clear_screen()

        self.send_frame = tk.Frame(self.master, bg=self.bg_color)
        self.send_frame.pack(fill="both", expand=True)

        tk.Label(self.send_frame, text="코인 전송", font=("Arial", 20, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=20)

        tk.Label(self.send_frame, text="받는 사람 ID", font=("Arial", 14),
                 bg=self.bg_color, fg=self.text_color).pack(pady=5)
        self.recipient_entry = tk.Entry(self.send_frame)
        self.recipient_entry.pack(pady=5)

        tk.Label(self.send_frame, text="보낼 수량 (TLK)", font=("Arial", 14),
                 bg=self.bg_color, fg=self.text_color).pack(pady=5)
        self.amount_entry = tk.Entry(self.send_frame)
        self.amount_entry.pack(pady=5)

        tk.Button(self.send_frame, text="전송하기", font=("Arial", 14),
                  command=self.confirm_send_coin).pack(pady=10)

        tk.Button(self.send_frame, text="뒤로 가기", font=("Arial", 12),
                  command=self.show_wallet_screen).pack(pady=20)

    def confirm_send_coin(self):
        recipient = self.recipient_entry.get().strip()
        amount_text = self.amount_entry.get().strip()

        if not recipient or not amount_text:
            messagebox.showerror("오류", "모든 항목을 입력해주세요.")
            return

        if recipient == self.user_id:
            messagebox.showerror("오류", "자기 자신에게 보낼 수 없습니다.")
            return

        try:
            amount = float(amount_text)
            if amount <= 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("오류", "수량은 양의 숫자여야 합니다.")
            return

        if recipient not in self.user_data:
            messagebox.showerror("오류", "존재하지 않는 사용자입니다.")
            return

        total_tlk_required = amount * 1.01

        if self.wallet['balance'] < total_tlk_required:
            messagebox.showerror("오류", f"수수료 포함 최소 {total_tlk_required:.2f} TLK가 필요합니다.")
            return

        confirm = messagebox.askyesno("확인", f"{recipient}님에게 {amount} TLK를 전송하시겠습니까?\n(수수료 1% 별도)")
        if confirm:
            self.wallet['balance'] -= total_tlk_required
            self.user_data[self.user_id]['wallet']['balance'] = self.wallet['balance']
            self.user_data[recipient]['wallet']['balance'] += amount
            self.save_user_data()
            self.save_log("코인 전송", f"받는 사람: {recipient}, 수량: {amount} TLK")
            messagebox.showinfo("성공", f"{recipient}님에게 {amount} TLK를 전송했습니다.")
            self.show_wallet_screen()

    def view_blocked_list(self):
        self.clear_screen()

        self.blocked_frame = tk.Frame(self.master, bg=self.bg_color)
        self.blocked_frame.pack(fill="both", expand=True)

        tk.Label(self.blocked_frame, text="차단 목록", font=("Arial", 20, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=20)

        if self.blocked:
            self.blocked_listbox = tk.Listbox(self.blocked_frame)
            self.blocked_listbox.pack(pady=10, fill="both", expand=True)

            for blocked_user in self.blocked:
                self.blocked_listbox.insert(tk.END, blocked_user)

            tk.Button(self.blocked_frame, text="차단 해제", font=("Arial", 14),
                      command=self.unblock_user).pack(pady=10)
        else:
            tk.Label(self.blocked_frame, text="차단된 사용자가 없습니다.",
                     font=("Arial", 14), bg=self.bg_color, fg=self.text_color).pack(pady=20)

        tk.Button(self.blocked_frame, text="뒤로 가기", font=("Arial", 12),
                  command=self.build_main_screen).pack(pady=20)

    def unblock_user(self):
        selected = self.blocked_listbox.curselection()

        if not selected:
            messagebox.showerror("오류", "해제할 사용자를 선택하세요.")
            return

        blocked_user = self.blocked_listbox.get(selected)

        confirm = messagebox.askyesno("확인", f"{blocked_user}님을 차단 해제하시겠습니까?")
        if confirm:
            self.blocked.remove(blocked_user)
            self.user_data[self.user_id]['blocked'] = self.blocked
            self.save_user_data()
            self.blocked_listbox.delete(selected)
            messagebox.showinfo("완료", f"{blocked_user}님을 차단 해제했습니다.")

    def withdraw_account(self):
        confirm = messagebox.askyesno("회원 탈퇴 확인", "정말로 회원 탈퇴하시겠습니까?\n모든 데이터가 삭제됩니다.")
        if confirm:
            del self.user_data[self.user_id]
            self.save_user_data()
            messagebox.showinfo("탈퇴 완료", "회원 탈퇴가 완료되었습니다.")
            self.user_id = None
            self.password = None
            self.wallet = {}
            self.build_login_screen()

    def save_nft_transaction(self, nft_id, buyer_id):
        nft_record = {
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "nft_id": nft_id,
            "buyer": buyer_id
        }
        if os.path.exists('nft_transactions.json'):
            with open('nft_transactions.json', 'r') as f:
                transactions = json.load(f)
        else:
            transactions = []

        transactions.append(nft_record)

        with open('nft_transactions.json', 'w') as f:
            json.dump(transactions, f, indent=4)

    def open_nft_market(self):
        self.clear_screen()

        self.nft_market_frame = tk.Frame(self.master, bg=self.bg_color)
        self.nft_market_frame.pack(fill="both", expand=True)

        tk.Label(self.nft_market_frame, text="NFT 마켓", font=("Arial", 20, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=20)

        tk.Button(self.nft_market_frame, text="NFT 구매하기", font=("Arial", 14),
                  command=self.purchase_nft_window).pack(pady=10)

        tk.Button(self.nft_market_frame, text="내 NFT 보기", font=("Arial", 14),
                  command=self.view_my_nfts).pack(pady=10)

        tk.Button(self.nft_market_frame, text="뒤로 가기", font=("Arial", 12),
                  command=self.build_main_screen).pack(pady=20)

    def purchase_nft_window(self):
        self.clear_screen()

        self.purchase_frame = tk.Frame(self.master, bg=self.bg_color)
        self.purchase_frame.pack(fill="both", expand=True)

        tk.Label(self.purchase_frame, text="NFT 구매", font=("Arial", 20, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=20)

        tk.Label(self.purchase_frame, text="NFT ID 입력", font=("Arial", 14),
                 bg=self.bg_color, fg=self.text_color).pack(pady=5)
        self.nft_id_entry = tk.Entry(self.purchase_frame)
        self.nft_id_entry.pack(pady=5)

        tk.Label(self.purchase_frame, text="가격 (TLK)", font=("Arial", 14),
                 bg=self.bg_color, fg=self.text_color).pack(pady=5)
        self.nft_price_entry = tk.Entry(self.purchase_frame)
        self.nft_price_entry.pack(pady=5)

        tk.Button(self.purchase_frame, text="구매하기", font=("Arial", 14),
                  command=self.purchase_nft).pack(pady=10)

        tk.Button(self.purchase_frame, text="뒤로 가기", font=("Arial", 12),
                  command=self.open_nft_market).pack(pady=20)

    def purchase_nft(self):
        nft_id = self.nft_id_entry.get().strip()
        price_text = self.nft_price_entry.get().strip()

        if not nft_id or not price_text:
            messagebox.showerror("오류", "모든 항목을 입력해주세요.")
            return

        try:
            price = float(price_text)
            if price <= 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("오류", "가격은 양의 숫자여야 합니다.")
            return

        if self.wallet['balance'] < price:
            messagebox.showerror("오류", "잔액이 부족합니다.")
            return

        confirm = messagebox.askyesno("구매 확인", f"NFT {nft_id}를 {price} TLK에 구매하시겠습니까?")
        if confirm:
            self.wallet['balance'] -= price
            self.user_data[self.user_id]['wallet']['balance'] = self.wallet['balance']
            self.user_data[self.user_id].setdefault('nfts', []).append(nft_id)
            self.save_user_data()
            self.save_nft_transaction(nft_id, self.user_id)
            messagebox.showinfo("구매 완료", f"NFT {nft_id}를 성공적으로 구매했습니다.")
            self.open_nft_market()

    def view_my_nfts(self):
        self.clear_screen()

        self.my_nft_frame = tk.Frame(self.master, bg=self.bg_color)
        self.my_nft_frame.pack(fill="both", expand=True)

        tk.Label(self.my_nft_frame, text="내 NFT 목록", font=("Arial", 20, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=20)

        my_nfts = self.user_data[self.user_id].get('nfts', [])

        if my_nfts:
            for nft in my_nfts:
                tk.Label(self.my_nft_frame, text=f"NFT ID: {nft}", font=("Arial", 14),
                         bg=self.bg_color, fg=self.text_color).pack(pady=5)
        else:
            tk.Label(self.my_nft_frame, text="보유한 NFT가 없습니다.", font=("Arial", 14),
                     bg=self.bg_color, fg=self.text_color).pack(pady=10)

        tk.Button(self.my_nft_frame, text="뒤로 가기", font=("Arial", 12),
                  command=self.open_nft_market).pack(pady=20)

    def view_transaction_history(self):
        self.clear_screen()

        self.tx_history_frame = tk.Frame(self.master, bg=self.bg_color)
        self.tx_history_frame.pack(fill="both", expand=True)

        tk.Label(self.tx_history_frame, text="거래 내역", font=("Arial", 20, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=20)

        if os.path.exists('log_data.json'):
            with open('log_data.json', 'r') as f:
                logs = json.load(f)

            for log in logs[::-1]:  # 최근 거래부터 보여줌
                if log['user'] == self.user_id:
                    entry = f"{log['time']} - {log['action']} - {log['details']}"
                    tk.Label(self.tx_history_frame, text=entry, font=("Arial", 10),
                             bg=self.bg_color, fg=self.text_color).pack(pady=2)
        else:
            tk.Label(self.tx_history_frame, text="거래 기록이 없습니다.",
                     font=("Arial", 14), bg=self.bg_color, fg=self.text_color).pack(pady=10)

        tk.Button(self.tx_history_frame, text="뒤로 가기", font=("Arial", 12),
                  command=self.build_main_screen).pack(pady=20)

    def settings_window(self):
        self.clear_screen()

        self.settings_frame = tk.Frame(self.master, bg=self.bg_color)
        self.settings_frame.pack(fill="both", expand=True)

        tk.Label(self.settings_frame, text="설정", font=("Arial", 20, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=20)

        tk.Label(self.settings_frame, text="테마 선택", font=("Arial", 14),
                 bg=self.bg_color, fg=self.text_color).pack(pady=10)

        tk.Button(self.settings_frame, text="핑크 테마", font=("Arial", 12),
                  command=lambda: self.change_theme("pink")).pack(pady=5)

        tk.Button(self.settings_frame, text="다크 테마", font=("Arial", 12),
                  command=lambda: self.change_theme("dark")).pack(pady=5)

        tk.Button(self.settings_frame, text="화이트 테마", font=("Arial", 12),
                  command=lambda: self.change_theme("white")).pack(pady=5)

        tk.Label(self.settings_frame, text="언어 설정", font=("Arial", 14),
                 bg=self.bg_color, fg=self.text_color).pack(pady=20)

        tk.Button(self.settings_frame, text="한국어", font=("Arial", 12),
                  command=lambda: self.change_language("ko")).pack(pady=5)
        tk.Button(self.settings_frame, text="영어", font=("Arial", 12),
                  command=lambda: self.change_language("en")).pack(pady=5)
        tk.Button(self.settings_frame, text="일본어", font=("Arial", 12),
                  command=lambda: self.change_language("jp")).pack(pady=5)

        tk.Button(self.settings_frame, text="뒤로 가기", font=("Arial", 12),
                  command=self.build_main_screen).pack(pady=20)

    def change_theme(self, theme):
        if theme == "pink":
            self.bg_color = "#ffeaf2"
            self.text_color = "#c71585"
        elif theme == "dark":
            self.bg_color = "#1c1c1c"
            self.text_color = "#ffffff"
        elif theme == "white":
            self.bg_color = "#ffffff"
            self.text_color = "#000000"

        self.build_main_screen()

    def change_language(self, lang):
        # 다국어 지원은 추후 구현 (구조 준비)
        if lang == "ko":
            messagebox.showinfo("언어 변경", "한국어로 설정되었습니다.")
        elif lang == "en":
            messagebox.showinfo("Language Change", "Set to English.")
        elif lang == "jp":
            messagebox.showinfo("言語変更", "日本語に設定されました。")

    def open_support_window(self):
        self.clear_screen()

        self.support_frame = tk.Frame(self.master, bg=self.bg_color)
        self.support_frame.pack(fill="both", expand=True)

        tk.Label(self.support_frame, text="고객 지원", font=("Arial", 20, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=20)

        tk.Label(self.support_frame, text="문의사항이 있으면 아래 입력 후 제출하세요.",
                 font=("Arial", 14), bg=self.bg_color, fg=self.text_color).pack(pady=10)

        self.support_text = tk.Text(self.support_frame, height=10, font=("Arial", 12))
        self.support_text.pack(pady=10, padx=20, fill="both")

        tk.Button(self.support_frame, text="문의 제출", font=("Arial", 12),
                  command=self.submit_support).pack(pady=10)

        tk.Button(self.support_frame, text="뒤로 가기", font=("Arial", 12),
                  command=self.build_main_screen).pack(pady=10)

    def submit_support(self):
        support_message = self.support_text.get("1.0", tk.END).strip()

        if not support_message:
            messagebox.showwarning("경고", "내용을 입력해주세요.")
            return

        support_log = {
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "user": self.user_id,
            "support_message": support_message
        }

        if os.path.exists('support_logs.json'):
            with open('support_logs.json', 'r') as f:
                logs = json.load(f)
        else:
            logs = []

        logs.append(support_log)

        with open('support_logs.json', 'w') as f:
            json.dump(logs, f, indent=4)

        messagebox.showinfo("제출 완료", "문의가 성공적으로 접수되었습니다.")
        self.support_text.delete("1.0", tk.END)

    def open_nft_minting(self):
        self.clear_screen()

        self.mint_frame = tk.Frame(self.master, bg=self.bg_color)
        self.mint_frame.pack(fill="both", expand=True)

        tk.Label(self.mint_frame, text="NFT 발행하기", font=("Arial", 20, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=20)

        tk.Label(self.mint_frame, text="NFT 이름 입력", font=("Arial", 14),
                 bg=self.bg_color, fg=self.text_color).pack(pady=10)

        self.nft_name_entry = tk.Entry(self.mint_frame, font=("Arial", 14))
        self.nft_name_entry.pack(pady=5)

        tk.Button(self.mint_frame, text="NFT 발행", font=("Arial", 12),
                  command=self.mint_nft).pack(pady=10)

        tk.Button(self.mint_frame, text="뒤로 가기", font=("Arial", 12),
                  command=self.open_nft_market).pack(pady=10)

    def mint_nft(self):
        nft_name = self.nft_name_entry.get().strip()

        if not nft_name:
            messagebox.showwarning("경고", "NFT 이름을 입력하세요.")
            return

        if 'nfts' not in self.user_data[self.user_id]:
            self.user_data[self.user_id]['nfts'] = []

        self.user_data[self.user_id]['nfts'].append(nft_name)
        self.save_user_data()

        messagebox.showinfo("성공", f"NFT {nft_name} 발행 완료!")
        self.nft_name_entry.delete(0, tk.END)

    def open_about_page(self):
        self.clear_screen()

        self.about_frame = tk.Frame(self.master, bg=self.bg_color)
        self.about_frame.pack(fill="both", expand=True)

        tk.Label(self.about_frame, text="ZeroTalk 소개", font=("Arial", 20, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=20)

        description = (
            "ZeroTalk는 전세계 누구나 쓸 수 있는 독립 메신저입니다.\n"
            "- 전화번호, 이메일 없이 가입\n"
            "- 안전한 ID/비번 기반 인증\n"
            "- ETH, BTC, TLK, SOL, XRP, TRX 등 다중 코인 지갑 기능\n"
            "- NFT 마켓, 이모티콘, 그룹 채팅, 음성통화(개발중)\n\n"
            "당신의 자유로운 커뮤니케이션을 위한 최고의 선택!"
        )

        tk.Label(self.about_frame, text=description, font=("Arial", 12),
                 bg=self.bg_color, fg=self.text_color, justify="left").pack(pady=10, padx=20)

        tk.Button(self.about_frame, text="뒤로 가기", font=("Arial", 12),
                  command=self.build_main_screen).pack(pady=20)

    def open_notifications(self):
        self.clear_screen()

        self.notifications_frame = tk.Frame(self.master, bg=self.bg_color)
        self.notifications_frame.pack(fill="both", expand=True)

        tk.Label(self.notifications_frame, text="알림 설정", font=("Arial", 20, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=20)

        self.enable_noti_var = tk.BooleanVar(value=True)
        tk.Checkbutton(self.notifications_frame, text="메시지 알림 켜기",
                       font=("Arial", 14), bg=self.bg_color, fg=self.text_color,
                       variable=self.enable_noti_var).pack(pady=10)

        self.enable_coin_var = tk.BooleanVar(value=True)
        tk.Checkbutton(self.notifications_frame, text="코인 수신 알림 켜기",
                       font=("Arial", 14), bg=self.bg_color, fg=self.text_color,
                       variable=self.enable_coin_var).pack(pady=10)

        tk.Button(self.notifications_frame, text="저장하기", font=("Arial", 12),
                  command=self.save_notifications).pack(pady=20)

        tk.Button(self.notifications_frame, text="뒤로 가기", font=("Arial", 12),
                  command=self.build_main_screen).pack(pady=10)

    def save_notifications(self):
        self.user_data[self.user_id]['notifications'] = {
            'message_alert': self.enable_noti_var.get(),
            'coin_alert': self.enable_coin_var.get()
        }
        self.save_user_data()
        messagebox.showinfo("저장 완료", "알림 설정이 저장되었습니다.")

    def open_settings(self):
        self.clear_screen()

        self.settings_frame = tk.Frame(self.master, bg=self.bg_color)
        self.settings_frame.pack(fill="both", expand=True)

        tk.Label(self.settings_frame, text="설정", font=("Arial", 20, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=20)

        tk.Button(self.settings_frame, text="비밀번호 변경", font=("Arial", 14),
                  command=self.change_password_window).pack(pady=10)

        tk.Button(self.settings_frame, text="색상 테마 변경", font=("Arial", 14),
                  command=self.change_theme_window).pack(pady=10)

        tk.Button(self.settings_frame, text="뒤로 가기", font=("Arial", 12),
                  command=self.build_main_screen).pack(pady=20)

    def change_password_window(self):
        self.clear_screen()

        self.pw_change_frame = tk.Frame(self.master, bg=self.bg_color)
        self.pw_change_frame.pack(fill="both", expand=True)

        tk.Label(self.pw_change_frame, text="비밀번호 변경", font=("Arial", 20, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=20)

        tk.Label(self.pw_change_frame, text="현재 비밀번호", font=("Arial", 14),
                 bg=self.bg_color, fg=self.text_color).pack(pady=5)
        self.old_pw_entry = tk.Entry(self.pw_change_frame, show="*")
        self.old_pw_entry.pack(pady=5)

        tk.Label(self.pw_change_frame, text="새 비밀번호", font=("Arial", 14),
                 bg=self.bg_color, fg=self.text_color).pack(pady=5)
        self.new_pw_entry = tk.Entry(self.pw_change_frame, show="*")
        self.new_pw_entry.pack(pady=5)

        tk.Button(self.pw_change_frame, text="변경하기", font=("Arial", 12),
                  command=self.change_password).pack(pady=10)

        tk.Button(self.pw_change_frame, text="뒤로 가기", font=("Arial", 12),
                  command=self.open_settings).pack(pady=10)

    def change_password(self):
        old_pw = self.old_pw_entry.get().strip()
        new_pw = self.new_pw_entry.get().strip()

        if self.user_data[self.user_id]['password'] != old_pw:
            messagebox.showerror("오류", "현재 비밀번호가 일치하지 않습니다.")
            return

        if not new_pw or len(new_pw) < 4:
            messagebox.showerror("오류", "새 비밀번호는 최소 4자 이상이어야 합니다.")
            return

        self.user_data[self.user_id]['password'] = new_pw
        self.save_user_data()
        messagebox.showinfo("성공", "비밀번호가 변경되었습니다.")
        self.build_main_screen()

    def change_theme_window(self):
        self.clear_screen()

        self.theme_frame = tk.Frame(self.master, bg=self.bg_color)
        self.theme_frame.pack(fill="both", expand=True)

        tk.Label(self.theme_frame, text="테마 색상 변경", font=("Arial", 20, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=20)

        tk.Button(self.theme_frame, text="기본 핑크 테마", font=("Arial", 14),
                  command=lambda: self.apply_theme("#ffeaf2", "#ff4d94")).pack(pady=10)
        tk.Button(self.theme_frame, text="다크 모드", font=("Arial", 14),
                  command=lambda: self.apply_theme("#121212", "#bb86fc")).pack(pady=10)
        tk.Button(self.theme_frame, text="화이트 모드", font=("Arial", 14),
                  command=lambda: self.apply_theme("#ffffff", "#333333")).pack(pady=10)

        tk.Button(self.theme_frame, text="뒤로 가기", font=("Arial", 12),
                  command=self.open_settings).pack(pady=20)

    def apply_theme(self, bg_color, text_color):
        self.bg_color = bg_color
        self.text_color = text_color
        self.user_data[self.user_id]['theme'] = {
            'bg': bg_color,
            'text': text_color
        }
        self.save_user_data()
        messagebox.showinfo("변경 완료", "테마가 적용되었습니다.")
        self.build_main_screen()

    def open_marketplace(self):
        self.clear_screen()

        self.marketplace_frame = tk.Frame(self.master, bg=self.bg_color)
        self.marketplace_frame.pack(fill="both", expand=True)

        tk.Label(self.marketplace_frame, text="ZeroTalk NFT 마켓플레이스",
                 font=("Arial", 20, "bold"), bg=self.bg_color, fg=self.text_color).pack(pady=20)

        # 기본 NFT 리스트
        self.nft_items = [
            {"name": "제로톡 NFT #1", "price": 10},
            {"name": "제로톡 NFT #2", "price": 20},
            {"name": "제로톡 NFT #3", "price": 30},
        ]

        self.nft_listbox = tk.Listbox(self.marketplace_frame, font=("Arial", 14))
        self.nft_listbox.pack(pady=10, fill="both", expand=True)

        for item in self.nft_items:
            self.nft_listbox.insert(tk.END, f"{item['name']} - {item['price']} TLK")

        tk.Button(self.marketplace_frame, text="NFT 구매하기", font=("Arial", 12),
                  command=self.purchase_nft).pack(pady=10)

        tk.Button(self.marketplace_frame, text="뒤로 가기", font=("Arial", 12),
                  command=self.build_main_screen).pack(pady=10)

    def purchase_nft(self):
        selected = self.nft_listbox.curselection()

        if not selected:
            messagebox.showerror("오류", "구매할 NFT를 선택하세요.")
            return

        item = self.nft_items[selected[0]]
        price = item['price']

        if self.wallet['balance'] < price:
            messagebox.showerror("구매 실패", "잔액이 부족합니다.")
            return

        self.wallet['balance'] -= price
        self.user_data[self.user_id]['wallet']['balance'] = self.wallet['balance']
        self.user_data[self.user_id].setdefault('owned_nfts', []).append(item['name'])
        self.save_user_data()
        messagebox.showinfo("구매 완료", f"{item['name']} NFT를 구매했습니다!")

    def view_owned_nfts(self):
        self.clear_screen()

        self.owned_nfts_frame = tk.Frame(self.master, bg=self.bg_color)
        self.owned_nfts_frame.pack(fill="both", expand=True)

        tk.Label(self.owned_nfts_frame, text="보유 중인 NFT 목록",
                 font=("Arial", 20, "bold"), bg=self.bg_color, fg=self.text_color).pack(pady=20)

        owned_nfts = self.user_data[self.user_id].get('owned_nfts', [])

        if owned_nfts:
            for nft in owned_nfts:
                tk.Label(self.owned_nfts_frame, text=nft, font=("Arial", 14),
                         bg=self.bg_color, fg=self.text_color).pack(pady=5)
        else:
            tk.Label(self.owned_nfts_frame, text="NFT 없음", font=("Arial", 14),
                     bg=self.bg_color, fg=self.text_color).pack(pady=10)

        tk.Button(self.owned_nfts_frame, text="뒤로 가기", font=("Arial", 12),
                  command=self.build_main_screen).pack(pady=20)

    def open_coin_dashboard(self):
        self.clear_screen()

        self.coin_dashboard_frame = tk.Frame(self.master, bg=self.bg_color)
        self.coin_dashboard_frame.pack(fill="both", expand=True)

        tk.Label(self.coin_dashboard_frame, text="코인 대시보드", font=("Arial", 20, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=20)

        self.eth_balance_label = tk.Label(self.coin_dashboard_frame, text="ETH: 조회중...",
                                          font=("Arial", 14), bg=self.bg_color, fg=self.text_color)
        self.eth_balance_label.pack(pady=5)

        self.btc_balance_label = tk.Label(self.coin_dashboard_frame, text="BTC: 조회중...",
                                          font=("Arial", 14), bg=self.bg_color, fg=self.text_color)
        self.btc_balance_label.pack(pady=5)

        self.sol_balance_label = tk.Label(self.coin_dashboard_frame, text="SOL: 조회중...",
                                          font=("Arial", 14), bg=self.bg_color, fg=self.text_color)
        self.sol_balance_label.pack(pady=5)

        self.trx_balance_label = tk.Label(self.coin_dashboard_frame, text="TRX: 조회중...",
                                          font=("Arial", 14), bg=self.bg_color, fg=self.text_color)
        self.trx_balance_label.pack(pady=5)

        self.tlk_balance_label = tk.Label(self.coin_dashboard_frame, text=f"TLK 잔액: {self.wallet.get('balance', 0)}",
                                          font=("Arial", 14), bg=self.bg_color, fg=self.text_color)
        self.tlk_balance_label.pack(pady=10)

        tk.Button(self.coin_dashboard_frame, text="잔액 새로고침", font=("Arial", 12),
                  command=self.refresh_balances).pack(pady=10)

        tk.Button(self.coin_dashboard_frame, text="뒤로 가기", font=("Arial", 12),
                  command=self.build_main_screen).pack(pady=10)

    def refresh_balances(self):
        # API 연동이 아니므로 가상 데이터
        self.eth_balance_label.config(text="ETH: 1.234 ETH")
        self.btc_balance_label.config(text="BTC: 0.056 BTC")
        self.sol_balance_label.config(text="SOL: 12.5 SOL")
        self.trx_balance_label.config(text="TRX: 3000 TRX")
        self.tlk_balance_label.config(text=f"TLK 잔액: {self.wallet.get('balance', 0)}")
        messagebox.showinfo("새로고침 완료", "잔액이 갱신되었습니다.")

    def open_settings(self):
        self.clear_screen()

        self.settings_frame = tk.Frame(self.master, bg=self.bg_color)
        self.settings_frame.pack(fill="both", expand=True)

        tk.Label(self.settings_frame, text="ZeroTalk 설정", font=("Arial", 20, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=20)

        tk.Button(self.settings_frame, text="테마 변경", font=("Arial", 14),
                  command=self.change_theme_window).pack(pady=10)

        tk.Button(self.settings_frame, text="비밀번호 변경", font=("Arial", 14),
                  command=self.change_password_window).pack(pady=10)

        tk.Button(self.settings_frame, text="언어 설정", font=("Arial", 14),
                  command=self.change_language_window).pack(pady=10)

        tk.Button(self.settings_frame, text="뒤로 가기", font=("Arial", 12),
                  command=self.build_main_screen).pack(pady=20)

    def change_theme_window(self):
        self.clear_screen()

        self.theme_frame = tk.Frame(self.master, bg=self.bg_color)
        self.theme_frame.pack(fill="both", expand=True)

        tk.Label(self.theme_frame, text="테마 선택", font=("Arial", 20, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=20)

        tk.Button(self.theme_frame, text="연핑크 테마", font=("Arial", 14),
                  command=lambda: self.set_theme("#ffeaf2", "#cc3366")).pack(pady=10)

        tk.Button(self.theme_frame, text="다크 테마", font=("Arial", 14),
                  command=lambda: self.set_theme("#2c2c2c", "#f0f0f0")).pack(pady=10)

        tk.Button(self.theme_frame, text="화이트 테마", font=("Arial", 14),
                  command=lambda: self.set_theme("#ffffff", "#333333")).pack(pady=10)

        tk.Button(self.theme_frame, text="뒤로 가기", font=("Arial", 12),
                  command=self.open_settings).pack(pady=20)

    def set_theme(self, bg_color, text_color):
        self.bg_color = bg_color
        self.text_color = text_color
        self.build_main_screen()

    def change_password_window(self):
        self.clear_screen()

        self.change_pw_frame = tk.Frame(self.master, bg=self.bg_color)
        self.change_pw_frame.pack(fill="both", expand=True)

        tk.Label(self.change_pw_frame, text="비밀번호 변경", font=("Arial", 20, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=20)

        tk.Label(self.change_pw_frame, text="현재 비밀번호", font=("Arial", 14),
                 bg=self.bg_color, fg=self.text_color).pack(pady=5)
        self.current_pw_entry = tk.Entry(self.change_pw_frame, show="*")
        self.current_pw_entry.pack(pady=5)

        tk.Label(self.change_pw_frame, text="새 비밀번호", font=("Arial", 14),
                 bg=self.bg_color, fg=self.text_color).pack(pady=5)
        self.new_pw_entry = tk.Entry(self.change_pw_frame, show="*")
        self.new_pw_entry.pack(pady=5)

        tk.Button(self.change_pw_frame, text="변경하기", font=("Arial", 14),
                  command=self.change_password).pack(pady=10)

        tk.Button(self.change_pw_frame, text="뒤로 가기", font=("Arial", 12),
                  command=self.open_settings).pack(pady=10)

    def change_password(self):
        current_pw = self.current_pw_entry.get().strip()
        new_pw = self.new_pw_entry.get().strip()

        if not current_pw or not new_pw:
            messagebox.showerror("오류", "모든 입력란을 채워주세요.")
            return

        if current_pw != self.password:
            messagebox.showerror("오류", "현재 비밀번호가 틀립니다.")
            return

        if len(new_pw) < 4:
            messagebox.showerror("오류", "새 비밀번호는 4자 이상이어야 합니다.")
            return

        self.user_data[self.user_id]['password'] = new_pw
        self.save_user_data()
        self.password = new_pw
        messagebox.showinfo("완료", "비밀번호가 변경되었습니다.")
        self.build_main_screen()

    def change_language_window(self):
        self.clear_screen()

        self.language_frame = tk.Frame(self.master, bg=self.bg_color)
        self.language_frame.pack(fill="both", expand=True)

        tk.Label(self.language_frame, text="언어 설정", font=("Arial", 20, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=20)

        languages = ["한국어", "English", "日本語", "中文", "Español", "Français", "Deutsch", "العربية"]
        for lang in languages:
            tk.Button(self.language_frame, text=lang, font=("Arial", 14),
                      command=lambda l=lang: self.set_language(l)).pack(pady=5)

        tk.Button(self.language_frame, text="뒤로 가기", font=("Arial", 12),
                  command=self.open_settings).pack(pady=20)

    def set_language(self, language):
        self.language = language
        messagebox.showinfo("언어 변경", f"언어가 {language}로 변경되었습니다.")
        self.build_main_screen()

    def open_wallet_window(self):
        self.clear_screen()

        self.wallet_frame = tk.Frame(self.master, bg=self.bg_color)
        self.wallet_frame.pack(fill="both", expand=True)

        tk.Label(self.wallet_frame, text="ZeroTalk 지갑", font=("Arial", 20, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=20)

        wallet_info = self.user_data[self.user_id]['wallet']
        tk.Label(self.wallet_frame, text=f"지갑 주소: {wallet_info['address']}", font=("Arial", 12),
                 bg=self.bg_color, fg=self.text_color).pack(pady=5)
        tk.Label(self.wallet_frame, text=f"잔액 (TLK): {wallet_info['balance']}개", font=("Arial", 12),
                 bg=self.bg_color, fg=self.text_color).pack(pady=5)

        tk.Button(self.wallet_frame, text="코인 보내기", font=("Arial", 14),
                  command=self.open_send_coin_window).pack(pady=10)

        tk.Button(self.wallet_frame, text="뒤로 가기", font=("Arial", 12),
                  command=self.build_main_screen).pack(pady=10)

    def open_send_coin_window(self):
        self.clear_screen()

        self.send_frame = tk.Frame(self.master, bg=self.bg_color)
        self.send_frame.pack(fill="both", expand=True)

        tk.Label(self.send_frame, text="코인 전송", font=("Arial", 20, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=20)

        tk.Label(self.send_frame, text="받는 사람 ID", font=("Arial", 12),
                 bg=self.bg_color, fg=self.text_color).pack(pady=5)
        self.recipient_entry = tk.Entry(self.send_frame, font=("Arial", 12))
        self.recipient_entry.pack(pady=5)

        tk.Label(self.send_frame, text="보낼 수량 (TLK)", font=("Arial", 12),
                 bg=self.bg_color, fg=self.text_color).pack(pady=5)
        self.amount_entry = tk.Entry(self.send_frame, font=("Arial", 12))
        self.amount_entry.pack(pady=5)

        tk.Button(self.send_frame, text="전송하기", font=("Arial", 14),
                  command=self.send_coin).pack(pady=10)

        tk.Button(self.send_frame, text="뒤로 가기", font=("Arial", 12),
                  command=self.open_wallet_window).pack(pady=10)

    def send_coin(self):
        recipient = self.recipient_entry.get().strip()
        amount_text = self.amount_entry.get().strip()

        if not recipient or not amount_text:
            messagebox.showerror("오류", "모든 입력란을 채워주세요.")
            return

        if recipient not in self.user_data:
            messagebox.showerror("오류", "받는 사용자가 존재하지 않습니다.")
            return

        try:
            amount = float(amount_text)
            if amount <= 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("오류", "수량은 양수로 입력해야 합니다.")
            return

        sender_wallet = self.user_data[self.user_id]['wallet']
        recipient_wallet = self.user_data[recipient]['wallet']

        if sender_wallet['balance'] < amount:
            messagebox.showerror("오류", "잔액이 부족합니다.")
            return

        # TLK 수수료 계산 (1%)
        fee = amount * 0.01
        total_deduction = amount + fee

        if sender_wallet['balance'] < total_deduction:
            messagebox.showerror("오류", f"수수료 포함하여 {total_deduction:.2f} TLK가 필요합니다.")
            return

        # 송금 실행
        sender_wallet['balance'] -= total_deduction
        recipient_wallet['balance'] += amount
        self.user_data[self.user_id]['wallet'] = sender_wallet
        self.user_data[recipient]['wallet'] = recipient_wallet
        self.save_user_data()

        messagebox.showinfo("송금 완료", f"{recipient}님에게 {amount} TLK 전송 완료! (수수료: {fee:.2f} TLK 차감)")
        self.save_log("코인 전송", f"{self.user_id} → {recipient}: {amount} TLK (수수료 {fee:.2f})")
        self.open_wallet_window()

    def show_settings_window(self):
        self.clear_screen()

        self.settings_frame = tk.Frame(self.master, bg=self.bg_color)
        self.settings_frame.pack(fill="both", expand=True)

        tk.Label(self.settings_frame, text="설정", font=("Arial", 20, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=20)

        # 테마 변경
        tk.Label(self.settings_frame, text="테마 선택", font=("Arial", 14),
                 bg=self.bg_color, fg=self.text_color).pack(pady=10)

        theme_frame = tk.Frame(self.settings_frame, bg=self.bg_color)
        theme_frame.pack(pady=10)

        tk.Button(theme_frame, text="핑크 테마", command=lambda: self.change_theme('pink')).pack(side="left", padx=5)
        tk.Button(theme_frame, text="화이트 테마", command=lambda: self.change_theme('white')).pack(side="left", padx=5)
        tk.Button(theme_frame, text="블랙 테마", command=lambda: self.change_theme('black')).pack(side="left", padx=5)

        # 언어 변경 (다국어 설정 준비)
        tk.Label(self.settings_frame, text="언어 선택", font=("Arial", 14),
                 bg=self.bg_color, fg=self.text_color).pack(pady=10)

        self.language_var = tk.StringVar(value="한국어")
        language_menu = tk.OptionMenu(self.settings_frame, self.language_var,
                                      "한국어", "영어", "중국어", "일본어", "스페인어")
        language_menu.pack()

        # 저장 버튼
        tk.Button(self.settings_frame, text="저장", command=self.save_settings).pack(pady=20)

        # 뒤로 가기
        tk.Button(self.settings_frame, text="뒤로 가기", command=self.build_main_screen).pack(pady=10)

    def change_theme(self, theme):
        if theme == 'pink':
            self.bg_color = "#ffeaf2"
            self.text_color = "#d63384"
        elif theme == 'white':
            self.bg_color = "#ffffff"
            self.text_color = "#333333"
        elif theme == 'black':
            self.bg_color = "#1e1e1e"
            self.text_color = "#f0f0f0"
        self.build_main_screen()

    def save_settings(self):
        selected_language = self.language_var.get()
        self.user_data[self.user_id]['language'] = selected_language
        self.save_user_data()
        messagebox.showinfo("저장 완료", f"언어: {selected_language}\n테마 변경 완료!")
        self.save_log("설정 변경", f"언어: {selected_language}, 테마 변경")
        self.build_main_screen()

    def show_dashboard_window(self):
        self.clear_screen()

        self.dashboard_frame = tk.Frame(self.master, bg=self.bg_color)
        self.dashboard_frame.pack(fill="both", expand=True)

        tk.Label(self.dashboard_frame, text="대시보드", font=("Arial", 20, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=20)

        total_users = len(self.user_data)
        total_tlk = sum(u['wallet']['balance'] for u in self.user_data.values())
        blocked_count = len(self.user_data[self.user_id]['blocked'])

        tk.Label(self.dashboard_frame, text=f"총 가입자 수: {total_users}명", font=("Arial", 14),
                 bg=self.bg_color, fg=self.text_color).pack(pady=5)
        tk.Label(self.dashboard_frame, text=f"총 TLK 보유량: {total_tlk:.2f} TLK", font=("Arial", 14),
                 bg=self.bg_color, fg=self.text_color).pack(pady=5)
        tk.Label(self.dashboard_frame, text=f"차단한 유저 수: {blocked_count}명", font=("Arial", 14),
                 bg=self.bg_color, fg=self.text_color).pack(pady=5)

        tk.Button(self.dashboard_frame, text="뒤로 가기", command=self.build_main_screen).pack(pady=20)

    def show_nft_marketplace(self):
        self.clear_screen()

        self.market_frame = tk.Frame(self.master, bg=self.bg_color)
        self.market_frame.pack(fill="both", expand=True)

        tk.Label(self.market_frame, text="NFT 마켓플레이스", font=("Arial", 20, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=20)

        self.nft_items = [
            {"name": "핑크 토끼 NFT", "price": 50},
            {"name": "제로톡 VIP 카드", "price": 100},
            {"name": "플래티넘 티켓", "price": 200},
            {"name": "월드맵 아바타", "price": 300},
        ]

        for nft in self.nft_items:
            frame = tk.Frame(self.market_frame, bg=self.bg_color)
            frame.pack(pady=5)

            tk.Label(frame, text=f"{nft['name']} - {nft['price']} TLK",
                     font=("Arial", 14), bg=self.bg_color, fg=self.text_color).pack(side="left", padx=10)

            tk.Button(frame, text="구매", command=lambda n=nft: self.purchase_nft(n)).pack(side="left", padx=5)

        tk.Button(self.market_frame, text="뒤로 가기", command=self.build_main_screen).pack(pady=20)

    def purchase_nft(self, nft):
        if self.wallet['balance'] < nft['price']:
            messagebox.showerror("구매 실패", "잔액이 부족합니다.")
            return

        confirm = messagebox.askyesno("구매 확인", f"{nft['name']}을(를) 구매하시겠습니까?")
        if confirm:
            self.wallet['balance'] -= nft['price']
            self.user_data[self.user_id]['wallet']['balance'] = self.wallet['balance']
            self.user_data[self.user_id].setdefault('nft_inventory', []).append(nft['name'])
            self.save_user_data()
            messagebox.showinfo("구매 완료", f"{nft['name']}을(를) 구매하였습니다!")
            self.save_log("NFT 구매", f"NFT: {nft['name']} 가격: {nft['price']} TLK")

    def show_nft_inventory(self):
        self.clear_screen()

        self.inventory_frame = tk.Frame(self.master, bg=self.bg_color)
        self.inventory_frame.pack(fill="both", expand=True)

        tk.Label(self.inventory_frame, text="내 NFT 인벤토리", font=("Arial", 20, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=20)

        nfts = self.user_data[self.user_id].get('nft_inventory', [])

        if not nfts:
            tk.Label(self.inventory_frame, text="보유한 NFT가 없습니다.", font=("Arial", 14),
                     bg=self.bg_color, fg=self.text_color).pack(pady=10)
        else:
            for nft in nfts:
                tk.Label(self.inventory_frame, text=nft, font=("Arial", 14),
                         bg=self.bg_color, fg=self.text_color).pack(pady=5)

        tk.Button(self.inventory_frame, text="뒤로 가기", command=self.build_main_screen).pack(pady=20)

    def refresh_main_screen(self):
        # 로그인 완료 후, 메인으로 돌아올 때 모든 설정 반영
        self.clear_screen()
        self.build_main_screen()

    def view_wallet_transactions(self):
        self.clear_screen()

        self.wallet_tx_frame = tk.Frame(self.master, bg=self.bg_color)
        self.wallet_tx_frame.pack(fill="both", expand=True)

        tk.Label(self.wallet_tx_frame, text="지갑 거래 내역", font=("Arial", 20, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=20)

        if os.path.exists('wallet_logs.json'):
            with open('wallet_logs.json', 'r') as f:
                tx_logs = json.load(f)
        else:
            tx_logs = []

        user_tx_logs = [log for log in tx_logs if log['user'] == self.user_id]

        if not user_tx_logs:
            tk.Label(self.wallet_tx_frame, text="거래 내역이 없습니다.", font=("Arial", 14),
                     bg=self.bg_color, fg=self.text_color).pack(pady=10)
        else:
            for tx in user_tx_logs[-10:][::-1]:
                info = f"{tx['time']} | {tx['type']} | {tx['amount']} {tx['currency']} → {tx['recipient']}"
                tk.Label(self.wallet_tx_frame, text=info, font=("Arial", 10),
                         bg=self.bg_color, fg=self.text_color, anchor="w", justify="left").pack(padx=10, pady=2, fill="x")

        tk.Button(self.wallet_tx_frame, text="뒤로 가기", command=self.open_wallet_window).pack(pady=20)

    def save_wallet_transaction(self, tx_type, amount, currency, recipient):
        log_entry = {
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "user": self.user_id,
            "type": tx_type,
            "amount": amount,
            "currency": currency,
            "recipient": recipient
        }

        if os.path.exists('wallet_logs.json'):
            with open('wallet_logs.json', 'r') as f:
                logs = json.load(f)
        else:
            logs = []

        logs.append(log_entry)

        with open('wallet_logs.json', 'w') as f:
            json.dump(logs, f, indent=4)

    def switch_language(self, lang_code):
        # 기본적인 언어 설정
        self.language = lang_code
        messagebox.showinfo("언어 변경", f"언어가 {lang_code.upper()}로 변경되었습니다.")
        self.refresh_main_screen()

    def open_settings(self):
        self.clear_screen()

        self.settings_frame = tk.Frame(self.master, bg=self.bg_color)
        self.settings_frame.pack(fill="both", expand=True)

        tk.Label(self.settings_frame, text="설정", font=("Arial", 20, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=20)

        theme_btn = tk.Button(self.settings_frame, text="테마 변경", command=self.change_theme)
        theme_btn.pack(pady=10)

        lang_btn = tk.Button(self.settings_frame, text="언어 설정", command=self.change_language)
        lang_btn.pack(pady=10)

        tk.Button(self.settings_frame, text="뒤로 가기", command=self.build_main_screen).pack(pady=20)

    def change_theme(self):
        options = [("화이트", "white", "black"), ("다크", "black", "white"), ("핑크", "#ffe4e1", "#4b0082")]
        self.clear_screen()

        self.theme_frame = tk.Frame(self.master, bg=self.bg_color)
        self.theme_frame.pack(fill="both", expand=True)

        tk.Label(self.theme_frame, text="테마 선택", font=("Arial", 20, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=20)

        for name, bg, fg in options:
            tk.Button(self.theme_frame, text=name,
                      command=lambda b=bg, f=fg: self.apply_theme(b, f)).pack(pady=5)

        tk.Button(self.theme_frame, text="뒤로 가기", command=self.open_settings).pack(pady=20)

    def apply_theme(self, background, foreground):
        self.bg_color = background
        self.text_color = foreground
        self.refresh_main_screen()

    def change_language(self):
        self.clear_screen()

        self.lang_frame = tk.Frame(self.master, bg=self.bg_color)
        self.lang_frame.pack(fill="both", expand=True)

        tk.Label(self.lang_frame, text="언어 설정", font=("Arial", 20, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=20)

        langs = [("한국어", "ko"), ("영어", "en"), ("일본어", "jp"), ("베트남어", "vn"), ("중국어", "cn")]

        for name, code in langs:
            tk.Button(self.lang_frame, text=name, command=lambda c=code: self.switch_language(c)).pack(pady=5)

        tk.Button(self.lang_frame, text="뒤로 가기", command=self.open_settings).pack(pady=20)

    def open_wallet_market(self):
        self.clear_screen()

        self.market_frame = tk.Frame(self.master, bg=self.bg_color)
        self.market_frame.pack(fill="both", expand=True)

        tk.Label(self.market_frame, text="ZeroTalk NFT 마켓", font=("Arial", 20, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=20)

        # 가상의 NFT 상품 데이터
        nft_items = [
            {"name": "Zero NFT #1", "price": 10},
            {"name": "Zero NFT #2", "price": 25},
            {"name": "Zero NFT #3", "price": 50},
        ]

        self.nft_listbox = tk.Listbox(self.market_frame, font=("Arial", 12))
        for item in nft_items:
            self.nft_listbox.insert(tk.END, f"{item['name']} - {item['price']} TLK")
        self.nft_listbox.pack(pady=10, fill="both", expand=True)

        tk.Button(self.market_frame, text="구매하기", command=lambda: self.purchase_nft(nft_items)).pack(pady=10)
        tk.Button(self.market_frame, text="뒤로 가기", command=self.open_wallet_window).pack(pady=20)

    def purchase_nft(self, items):
        selection = self.nft_listbox.curselection()
        if not selection:
            messagebox.showerror("오류", "구매할 NFT를 선택하세요.")
            return

        selected_index = selection[0]
        selected_nft = items[selected_index]
        price = selected_nft['price']

        if self.wallet.get('tlk', 0) < price:
            messagebox.showerror("잔액 부족", "지갑에 충분한 TLK가 없습니다.")
            return

        # TLK 차감
        self.wallet['tlk'] -= price
        self.user_data[self.user_id]['wallet']['tlk'] = self.wallet['tlk']
        self.save_user_data()

        self.save_wallet_transaction("NFT 구매", price, "TLK", selected_nft['name'])
        messagebox.showinfo("구매 완료", f"{selected_nft['name']} NFT를 구매했습니다!")

        self.open_wallet_window()

    def refresh_main_screen(self):
        # 현재 어떤 화면에 있든 다시 메인 화면 불러오기
        try:
            self.main_frame.destroy()
        except:
            pass
        try:
            self.chat_frame.destroy()
        except:
            pass
        try:
            self.wallet_frame.destroy()
        except:
            pass
        try:
            self.settings_frame.destroy()
        except:
            pass
        try:
            self.lang_frame.destroy()
        except:
            pass
        try:
            self.market_frame.destroy()
        except:
            pass
        try:
            self.wallet_tx_frame.destroy()
        except:
            pass
        self.build_main_screen()

    def show_nft_inventory(self):
        self.clear_screen()

        self.nft_inventory_frame = tk.Frame(self.master, bg=self.bg_color)
        self.nft_inventory_frame.pack(fill="both", expand=True)

        tk.Label(self.nft_inventory_frame, text="내 NFT 보관함", font=("Arial", 20, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=20)

        if os.path.exists('wallet_logs.json'):
            with open('wallet_logs.json', 'r') as f:
                logs = json.load(f)
        else:
            logs = []

        nft_purchases = [log for log in logs if log['user'] == self.user_id and log['type'] == 'NFT 구매']

        if not nft_purchases:
            tk.Label(self.nft_inventory_frame, text="보유한 NFT가 없습니다.", font=("Arial", 14),
                     bg=self.bg_color, fg=self.text_color).pack(pady=10)
        else:
            for nft in nft_purchases:
                info = f"{nft['time']} - {nft['details']}"
                tk.Label(self.nft_inventory_frame, text=info, font=("Arial", 10),
                         bg=self.bg_color, fg=self.text_color, anchor="w", justify="left").pack(padx=10, pady=2, fill="x")

        tk.Button(self.nft_inventory_frame, text="뒤로 가기", command=self.open_wallet_window).pack(pady=20)

    def nft_marketplace_buttons(self):
        btn_frame = tk.Frame(self.wallet_frame, bg=self.bg_color)
        btn_frame.pack(pady=10)

        tk.Button(btn_frame, text="NFT 마켓", command=self.open_wallet_market).pack(side="left", padx=10)
        tk.Button(btn_frame, text="내 NFT 보기", command=self.show_nft_inventory).pack(side="left", padx=10)

    def open_settings_window(self):
        self.clear_screen()

        self.settings_frame = tk.Frame(self.master, bg=self.bg_color)
        self.settings_frame.pack(fill="both", expand=True)

        tk.Label(self.settings_frame, text="설정", font=("Arial", 20, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=20)

        # 언어 설정
        tk.Button(self.settings_frame, text="다국어 설정", command=self.open_language_settings).pack(pady=10)

        # 테마 변경
        tk.Button(self.settings_frame, text="테마 변경", command=self.change_theme).pack(pady=10)

        # 비밀번호 변경
        tk.Button(self.settings_frame, text="비밀번호 변경", command=self.change_password_window).pack(pady=10)

        # 로그아웃
        tk.Button(self.settings_frame, text="로그아웃", command=self.logout).pack(pady=20)

    def change_theme(self):
        theme_choice = messagebox.askquestion("테마 선택", "어두운 테마로 변경하시겠습니까? (예: 다크모드)")

        if theme_choice == "yes":
            self.bg_color = "#2b2b2b"
            self.text_color = "#ffffff"
        else:
            self.bg_color = "#f5f5f5"
            self.text_color = "#000000"

        self.refresh_main_screen()

    def open_language_settings(self):
        self.clear_screen()

        self.lang_frame = tk.Frame(self.master, bg=self.bg_color)
        self.lang_frame.pack(fill="both", expand=True)

        tk.Label(self.lang_frame, text="언어 설정", font=("Arial", 20, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=20)

        languages = ["한국어", "English", "日本語", "中文", "Español", "Français", "Deutsch", "Tiếng Việt", "ไทย", "عربي"]
        for lang in languages:
            tk.Button(self.lang_frame, text=lang, command=lambda l=lang: self.set_language(l)).pack(pady=5)

        tk.Button(self.lang_frame, text="뒤로 가기", command=self.open_settings_window).pack(pady=20)

    def set_language(self, lang):
        messagebox.showinfo("언어 설정 완료", f"선택된 언어: {lang}\n(향후 버전에서 언어별 UI 적용 예정)")
        self.open_settings_window()

    def change_password_window(self):
        self.clear_screen()

        self.password_frame = tk.Frame(self.master, bg=self.bg_color)
        self.password_frame.pack(fill="both", expand=True)

        tk.Label(self.password_frame, text="비밀번호 변경", font=("Arial", 20, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=20)

        tk.Label(self.password_frame, text="기존 비밀번호 입력", bg=self.bg_color, fg=self.text_color).pack(pady=5)
        self.old_pw_entry = tk.Entry(self.password_frame, show="*")
        self.old_pw_entry.pack(pady=5)

        tk.Label(self.password_frame, text="새 비밀번호 입력", bg=self.bg_color, fg=self.text_color).pack(pady=5)
        self.new_pw_entry = tk.Entry(self.password_frame, show="*")
        self.new_pw_entry.pack(pady=5)

        tk.Button(self.password_frame, text="비밀번호 변경", command=self.change_password).pack(pady=10)
        tk.Button(self.password_frame, text="뒤로 가기", command=self.open_settings_window).pack(pady=10)

    def change_password(self):
        old_pw = self.old_pw_entry.get()
        new_pw = self.new_pw_entry.get()

        if not old_pw or not new_pw:
            messagebox.showerror("오류", "모든 입력란을 채워주세요.")
            return

        if self.user_data[self.user_id]['password'] != old_pw:
            messagebox.showerror("오류", "기존 비밀번호가 일치하지 않습니다.")
            return

        self.user_data[self.user_id]['password'] = new_pw
        self.save_user_data()
        messagebox.showinfo("완료", "비밀번호가 변경되었습니다.")
        self.open_settings_window()

    def open_wallet_screen(self):
        self.clear_screen()

        self.wallet_frame = tk.Frame(self.master, bg=self.bg_color)
        self.wallet_frame.pack(fill="both", expand=True)

        tk.Label(self.wallet_frame, text="내 지갑", font=("Arial", 20, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=20)

        if self.wallet:
            tk.Label(self.wallet_frame, text=f"지갑주소: {self.wallet['address']}", 
                     bg=self.bg_color, fg=self.text_color, font=("Arial", 12)).pack(pady=5)

            tk.Label(self.wallet_frame, text=f"잔액: {self.wallet['balance']} TLK", 
                     bg=self.bg_color, fg=self.text_color, font=("Arial", 12)).pack(pady=5)

            tk.Button(self.wallet_frame, text="코인 송금", command=self.send_coin_screen).pack(pady=10)
            tk.Button(self.wallet_frame, text="거래 기록 보기", command=self.view_transaction_history).pack(pady=10)
        else:
            tk.Label(self.wallet_frame, text="지갑이 없습니다.", 
                     bg=self.bg_color, fg=self.text_color, font=("Arial", 12)).pack(pady=10)

        tk.Button(self.wallet_frame, text="뒤로 가기", command=self.show_main_screen).pack(pady=20)

    def send_coin_screen(self):
        self.clear_screen()

        self.send_frame = tk.Frame(self.master, bg=self.bg_color)
        self.send_frame.pack(fill="both", expand=True)

        tk.Label(self.send_frame, text="코인 송금", font=("Arial", 20, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=20)

        tk.Label(self.send_frame, text="받는 사람 ID 입력", 
                 bg=self.bg_color, fg=self.text_color).pack(pady=5)
        self.recipient_entry = tk.Entry(self.send_frame)
        self.recipient_entry.pack(pady=5)

        tk.Label(self.send_frame, text="보낼 수량 (TLK)", 
                 bg=self.bg_color, fg=self.text_color).pack(pady=5)
        self.amount_entry = tk.Entry(self.send_frame)
        self.amount_entry.pack(pady=5)

        tk.Button(self.send_frame, text="전송하기", command=self.send_coin).pack(pady=10)
        tk.Button(self.send_frame, text="뒤로 가기", command=self.open_wallet_screen).pack(pady=10)

    def send_coin(self):
        recipient = self.recipient_entry.get().strip()
        amount_text = self.amount_entry.get().strip()

        if not recipient or not amount_text:
            messagebox.showerror("오류", "모든 입력란을 채워주세요.")
            return

        if recipient not in self.user_data:
            messagebox.showerror("오류", "받는 사용자가 존재하지 않습니다.")
            return

        try:
            amount = float(amount_text)
            if amount <= 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("오류", "수량은 양의 숫자여야 합니다.")
            return

        # TLK 수수료 1% 부과 로직 추가
        fee = amount * 0.01
        total_amount = amount + fee

        if self.wallet['balance'] < total_amount:
            messagebox.showerror("오류", "잔액이 부족합니다.\n(송금액 + 1% 수수료 필요)")
            return

        # 전송
        self.wallet['balance'] -= total_amount
        self.user_data[self.user_id]['wallet']['balance'] = self.wallet['balance']
        self.user_data[recipient]['wallet']['balance'] += amount
        self.save_user_data()

        self.record_transaction(self.user_id, recipient, amount, fee)

        messagebox.showinfo("성공", f"{recipient}님에게 {amount} TLK 전송 완료!\n(수수료: {fee:.2f} TLK)")
        self.send_frame.destroy()
        self.open_wallet_screen()

    def view_transaction_history(self):
        if not os.path.exists('transaction_history.json'):
            messagebox.showinfo("알림", "거래 기록이 없습니다.")
            return

        with open('transaction_history.json', 'r', encoding='utf-8') as f:
            history = json.load(f)

        self.clear_screen()
        self.history_frame = tk.Frame(self.master, bg=self.bg_color)
        self.history_frame.pack(fill="both", expand=True)

        tk.Label(self.history_frame, text="거래 기록", font=("Arial", 20, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=20)

        if history:
            for tx in history:
                tx_text = (f"{tx['time']} | {tx['sender']} → {tx['recipient']} | "
                           f"{tx['amount']} TLK (수수료 {tx['fee']} TLK)")
                tk.Label(self.history_frame, text=tx_text, 
                         bg=self.bg_color, fg=self.text_color, font=("Arial", 10)).pack(pady=2)
        else:
            tk.Label(self.history_frame, text="기록 없음", 
                     bg=self.bg_color, fg=self.text_color).pack(pady=10)

        tk.Button(self.history_frame, text="뒤로 가기", command=self.open_wallet_screen).pack(pady=20)

    def record_transaction(self, sender, recipient, amount, fee):
        transaction = {
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "sender": sender,
            "recipient": recipient,
            "amount": amount,
            "fee": round(fee, 2)
        }
        if os.path.exists('transaction_history.json'):
            with open('transaction_history.json', 'r', encoding='utf-8') as f:
                history = json.load(f)
        else:
            history = []

        history.append(transaction)
        with open('transaction_history.json', 'w', encoding='utf-8') as f:
            json.dump(history, f, ensure_ascii=False, indent=4)

    def open_marketplace_screen(self):
        self.clear_screen()

        self.marketplace_frame = tk.Frame(self.master, bg=self.bg_color)
        self.marketplace_frame.pack(fill="both", expand=True)

        tk.Label(self.marketplace_frame, text="ZeroTalk NFT 마켓", font=("Arial", 20, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=20)

        tk.Button(self.marketplace_frame, text="NFT 목록 보기", command=self.show_nft_list).pack(pady=10)
        tk.Button(self.marketplace_frame, text="내 NFT 보기", command=self.show_my_nft).pack(pady=10)
        tk.Button(self.marketplace_frame, text="NFT 업로드", command=self.upload_nft_screen).pack(pady=10)
        tk.Button(self.marketplace_frame, text="뒤로 가기", command=self.show_main_screen).pack(pady=20)

    def show_nft_list(self):
        self.clear_screen()

        self.nft_list_frame = tk.Frame(self.master, bg=self.bg_color)
        self.nft_list_frame.pack(fill="both", expand=True)

        tk.Label(self.nft_list_frame, text="구매 가능한 NFT 목록", font=("Arial", 18, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=10)

        if not os.path.exists('nft_market.json'):
            tk.Label(self.nft_list_frame, text="등록된 NFT가 없습니다.", 
                     bg=self.bg_color, fg=self.text_color).pack(pady=10)
            tk.Button(self.nft_list_frame, text="뒤로 가기", command=self.open_marketplace_screen).pack(pady=10)
            return

        with open('nft_market.json', 'r', encoding='utf-8') as f:
            nft_list = json.load(f)

        for nft in nft_list:
            nft_frame = tk.Frame(self.nft_list_frame, bg=self.bg_color)
            nft_frame.pack(pady=5, padx=10, fill="x")

            info = f"제목: {nft['title']} | 가격: {nft['price']} TLK"
            tk.Label(nft_frame, text=info, bg=self.bg_color, fg=self.text_color, font=("Arial", 12)).pack(side="left")

            tk.Button(nft_frame, text="구매", command=lambda n=nft: self.purchase_nft(n)).pack(side="right", padx=5)

        tk.Button(self.nft_list_frame, text="뒤로 가기", command=self.open_marketplace_screen).pack(pady=20)

    def show_my_nft(self):
        self.clear_screen()

        self.my_nft_frame = tk.Frame(self.master, bg=self.bg_color)
        self.my_nft_frame.pack(fill="both", expand=True)

        tk.Label(self.my_nft_frame, text="내 NFT 목록", font=("Arial", 18, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=10)

        user_nfts = self.user_data[self.user_id].get('nfts', [])

        if not user_nfts:
            tk.Label(self.my_nft_frame, text="보유한 NFT가 없습니다.", 
                     bg=self.bg_color, fg=self.text_color).pack(pady=10)
        else:
            for nft in user_nfts:
                nft_text = f"제목: {nft['title']} | 발행자: {nft['creator']}"
                tk.Label(self.my_nft_frame, text=nft_text, 
                         bg=self.bg_color, fg=self.text_color, font=("Arial", 12)).pack(pady=5)

        tk.Button(self.my_nft_frame, text="뒤로 가기", command=self.open_marketplace_screen).pack(pady=20)

    def upload_nft_screen(self):
        self.clear_screen()

        self.upload_frame = tk.Frame(self.master, bg=self.bg_color)
        self.upload_frame.pack(fill="both", expand=True)

        tk.Label(self.upload_frame, text="NFT 업로드", font=("Arial", 18, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=20)

        tk.Label(self.upload_frame, text="NFT 제목 입력", 
                 bg=self.bg_color, fg=self.text_color).pack(pady=5)
        self.nft_title_entry = tk.Entry(self.upload_frame)
        self.nft_title_entry.pack(pady=5)

        tk.Label(self.upload_frame, text="판매 가격 (TLK)", 
                 bg=self.bg_color, fg=self.text_color).pack(pady=5)
        self.nft_price_entry = tk.Entry(self.upload_frame)
        self.nft_price_entry.pack(pady=5)

        tk.Button(self.upload_frame, text="NFT 등록", command=self.upload_nft).pack(pady=10)
        tk.Button(self.upload_frame, text="뒤로 가기", command=self.open_marketplace_screen).pack(pady=10)

    def upload_nft(self):
        title = self.nft_title_entry.get().strip()
        price_text = self.nft_price_entry.get().strip()

        if not title or not price_text:
            messagebox.showerror("오류", "모든 입력란을 채워주세요.")
            return

        try:
            price = float(price_text)
            if price <= 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("오류", "가격은 양의 숫자여야 합니다.")
            return

        nft = {
            "title": title,
            "price": price,
            "creator": self.user_id
        }

        if os.path.exists('nft_market.json'):
            with open('nft_market.json', 'r', encoding='utf-8') as f:
                nft_list = json.load(f)
        else:
            nft_list = []

        nft_list.append(nft)
        with open('nft_market.json', 'w', encoding='utf-8') as f:
            json.dump(nft_list, f, ensure_ascii=False, indent=4)

        messagebox.showinfo("성공", "NFT 등록 완료!")
        self.open_marketplace_screen()

    def purchase_nft(self, nft):
        if self.wallet['balance'] < nft['price']:
            messagebox.showerror("오류", "잔액이 부족합니다.")
            return

        self.wallet['balance'] -= nft['price']
        self.user_data[self.user_id]['wallet']['balance'] = self.wallet['balance']

        if 'nfts' not in self.user_data[self.user_id]:
            self.user_data[self.user_id]['nfts'] = []

        self.user_data[self.user_id]['nfts'].append(nft)

        with open('nft_market.json', 'r', encoding='utf-8') as f:
            nft_list = json.load(f)

        nft_list.remove(nft)

        with open('nft_market.json', 'w', encoding='utf-8') as f:
            json.dump(nft_list, f, ensure_ascii=False, indent=4)

        self.save_user_data()

        messagebox.showinfo("성공", f"{nft['title']} NFT 구매 완료!")
        self.open_marketplace_screen()

    def show_wallet_screen(self):
        self.clear_screen()

        self.wallet_frame = tk.Frame(self.master, bg=self.bg_color)
        self.wallet_frame.pack(fill="both", expand=True)

        tk.Label(self.wallet_frame, text="ZeroTalk 내 지갑", font=("Arial", 20, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=20)

        wallet_info = f"주소: {self.wallet.get('address', '없음')}\n" \
                      f"잔액: {self.wallet.get('balance', 0):,.2f} TLK"
        tk.Label(self.wallet_frame, text=wallet_info,
                 bg=self.bg_color, fg=self.text_color, font=("Arial", 12)).pack(pady=10)

        tk.Button(self.wallet_frame, text="코인 보내기", command=self.open_send_coin_screen).pack(pady=10)
        tk.Button(self.wallet_frame, text="뒤로 가기", command=self.show_main_screen).pack(pady=20)

    def open_send_coin_screen(self):
        self.clear_screen()

        self.send_coin_frame = tk.Frame(self.master, bg=self.bg_color)
        self.send_coin_frame.pack(fill="both", expand=True)

        tk.Label(self.send_coin_frame, text="ZeroTalk 코인 송금", font=("Arial", 20, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=20)

        tk.Label(self.send_coin_frame, text="받는사람 ID", 
                 bg=self.bg_color, fg=self.text_color).pack(pady=5)
        self.recipient_entry = tk.Entry(self.send_coin_frame)
        self.recipient_entry.pack(pady=5)

        tk.Label(self.send_coin_frame, text="보낼 금액 (TLK)", 
                 bg=self.bg_color, fg=self.text_color).pack(pady=5)
        self.amount_entry = tk.Entry(self.send_coin_frame)
        self.amount_entry.pack(pady=5)

        tk.Label(self.send_coin_frame, text="지갑 비밀번호 입력", 
                 bg=self.bg_color, fg=self.text_color).pack(pady=5)
        self.wallet_pw_entry = tk.Entry(self.send_coin_frame, show="*")
        self.wallet_pw_entry.pack(pady=5)

        tk.Button(self.send_coin_frame, text="전송하기", command=self.transfer_token).pack(pady=10)
        tk.Button(self.send_coin_frame, text="뒤로 가기", command=self.show_wallet_screen).pack(pady=10)

    def transfer_token(self):
        recipient = self.recipient_entry.get().strip()
        amount_text = self.amount_entry.get().strip()
        entered_pw = self.wallet_pw_entry.get().strip()

        if not recipient or not amount_text or not entered_pw:
            messagebox.showerror("오류", "모든 입력란을 채워주세요.")
            return

        if entered_pw != self.password:
            messagebox.showerror("오류", "지갑 비밀번호가 일치하지 않습니다.")
            return

        if recipient not in self.user_data:
            messagebox.showerror("오류", "존재하지 않는 사용자입니다.")
            return

        try:
            amount = float(amount_text)
            if amount <= 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("오류", "보낼 금액은 양수여야 합니다.")
            return

        # TLK 1% 수수료 자동계산
        fee = round(amount * 0.01, 2)
        total_amount = amount + fee

        if self.wallet['balance'] < total_amount:
            messagebox.showerror("오류", f"잔액이 부족합니다. (총 필요 수량: {total_amount} TLK)")
            return

        self.wallet['balance'] -= total_amount
        self.user_data[self.user_id]['wallet']['balance'] = self.wallet['balance']
        self.user_data[recipient]['wallet']['balance'] += amount
        self.save_user_data()

        messagebox.showinfo("성공", f"{recipient}님에게 {amount} TLK 송금 완료\n(수수료 {fee} TLK 차감됨)")
        self.show_wallet_screen()

    def update_coin_prices(self):
        try:
            with open('coin_prices.json', 'r', encoding='utf-8') as f:
                prices = json.load(f)
        except:
            prices = {
                'BTC': 75000000,
                'ETH': 5000000,
                'SOL': 200000,
                'XRP': 800,
                'TRX': 120
            }

        self.coin_prices = prices

    def show_coin_prices_screen(self):
        self.clear_screen()

        self.coin_prices_frame = tk.Frame(self.master, bg=self.bg_color)
        self.coin_prices_frame.pack(fill="both", expand=True)

        tk.Label(self.coin_prices_frame, text="ZeroTalk 실시간 코인 시세", font=("Arial", 20, "bold"),
                 bg=self.bg_color, fg=self.text_color).pack(pady=20)

        for coin, price in self.coin_prices.items():
            info = f"{coin}: {price:,} KRW"
            tk.Label(self.coin_prices_frame, text=info,
                     bg=self.bg_color, fg=self.text_color, font=("Arial", 14)).pack(pady=5)

        tk.Button(self.coin_prices_frame, text="뒤로 가기", command=self.show_main_screen).pack(pady=20)

    def init_coin_prices_auto_update(self):
        import threading

        def refresh_prices():
            while True:
                self.update_coin_prices()
                time.sleep(30)  # 30초마다 가격 갱신

        thread = threading.Thread(target=refresh_prices)
        thread.daemon = True
        thread.start()

    def show_nft_market(self):
        self.main_frame.destroy()
        self.nft_frame = tk.Frame(self.master)
        self.nft_frame.pack(fill="both", expand=True)

        tk.Label(self.nft_frame, text="NFT 마켓플레이스", font=("Arial", 16)).pack(pady=10)

        self.nft_listbox = tk.Listbox(self.nft_frame)
        self.nft_listbox.pack(pady=10, fill="both", expand=True)

        for nft in self.nft_items:
            self.nft_listbox.insert(tk.END, f"{nft['name']} - {nft['price']} TLK")

        tk.Button(self.nft_frame, text="구매하기", command=self.buy_nft).pack(pady=5)
        tk.Button(self.nft_frame, text="뒤로가기", command=self.show_main_screen).pack(pady=10)

    def buy_nft(self):
        selected = self.nft_listbox.curselection()

        if not selected:
            messagebox.showerror("오류", "구매할 NFT를 선택하세요.")
            return

        index = selected[0]
        nft = self.nft_items[index]

        if self.wallet['balance'] < nft['price']:
            messagebox.showerror("구매 실패", "잔액이 부족합니다.")
            return

        self.wallet['balance'] -= nft['price']
        self.user_data[self.user_id]['wallet']['balance'] = self.wallet['balance']
        self.save_user_data()
        messagebox.showinfo("구매 완료", f"{nft['name']} NFT를 구매했습니다.")
        self.show_nft_market()

    def show_marketplace(self):
        self.main_frame.destroy()
        self.market_frame = tk.Frame(self.master)
        self.market_frame.pack(fill="both", expand=True)

        tk.Label(self.market_frame, text="코인 실시간 시세", font=("Arial", 16)).pack(pady=10)

        self.price_listbox = tk.Listbox(self.market_frame)
        self.price_listbox.pack(pady=10, fill="both", expand=True)

        self.refresh_prices()

        tk.Button(self.market_frame, text="새로고침", command=self.refresh_prices).pack(pady=5)
        tk.Button(self.market_frame, text="뒤로가기", command=self.show_main_screen).pack(pady=10)

    def refresh_prices(self):
        # 샘플 데이터 (나중에 API 연결해서 실제 데이터 가져올 수 있습니다)
        prices = {
            'Bitcoin (BTC)': '₩95,000,000',
            'Ethereum (ETH)': '₩6,500,000',
            'Solana (SOL)': '₩150,000',
            'XRP': '₩900',
            'TRX': '₩150',
            'ZeroTalk TLK': '₩1,000 (고정)'
        }

        self.price_listbox.delete(0, tk.END)

        for coin, price in prices.items():
            self.price_listbox.insert(tk.END, f"{coin}: {price}")

if __name__ == "__main__":
    import tkinter as tk
    root = tk.Tk()
    app = ZeroTalkApp(root)
    root.mainloop()