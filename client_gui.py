import socket
import threading
import queue
import time
import tkinter as tk
from tkinter import scrolledtext, messagebox

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5000


class ChatClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Socket Chat")

        # networking
        self.sock = None
        self.sock_file = None
        self.listener_thread = None
        self.running = False
        self.incoming = queue.Queue()

        self.logged_in = False
        self.username = None

        # conversations: name -> list[str]
        self.conversations = {"Everyone": []}
        self.current_conversation = "Everyone"

        # known contacts (friends)
        self.contacts = set()

        # unread messages: name -> count
        self.unread_counts = {}

        # listbox index -> conversation name
        self.listbox_order = []

        self.build_login_frame()
        self.build_chat_frame()

        self.login_frame.pack(fill="both", expand=True)

        self.root.after(100, self.process_incoming)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    # ---------- UI BUILD ---------- #

    def build_login_frame(self):
        self.login_frame = tk.Frame(self.root, padx=10, pady=10)

        tk.Label(self.login_frame, text="Server Host:").grid(row=0, column=0, sticky="e")
        self.host_entry = tk.Entry(self.login_frame)
        self.host_entry.insert(0, DEFAULT_HOST)
        self.host_entry.grid(row=0, column=1, sticky="we")

        tk.Label(self.login_frame, text="Server Port:").grid(row=1, column=0, sticky="e")
        self.port_entry = tk.Entry(self.login_frame)
        self.port_entry.insert(0, str(DEFAULT_PORT))
        self.port_entry.grid(row=1, column=1, sticky="we")

        tk.Label(self.login_frame, text="Username:").grid(row=2, column=0, sticky="e")
        self.username_entry = tk.Entry(self.login_frame)
        self.username_entry.grid(row=2, column=1, sticky="we")

        tk.Label(self.login_frame, text="Password:").grid(row=3, column=0, sticky="e")
        self.password_entry = tk.Entry(self.login_frame, show="*")
        self.password_entry.grid(row=3, column=1, sticky="we")

        btn_frame = tk.Frame(self.login_frame)
        btn_frame.grid(row=4, column=0, columnspan=2, pady=5)

        self.register_button = tk.Button(btn_frame, text="Register", command=self.on_register)
        self.register_button.pack(side="left", padx=5)

        self.login_button = tk.Button(btn_frame, text="Login", command=self.on_login)
        self.login_button.pack(side="left", padx=5)

        self.quit_button = tk.Button(btn_frame, text="Quit", command=self.on_close)
        self.quit_button.pack(side="left", padx=5)

        self.status_label = tk.Label(self.login_frame, text="", fg="red")
        self.status_label.grid(row=5, column=0, columnspan=2, pady=5)

        self.login_frame.columnconfigure(1, weight=1)

    def build_chat_frame(self):
        self.chat_frame = tk.Frame(self.root, padx=10, pady=10)

        # Top bar
        top_bar = tk.Frame(self.chat_frame)
        top_bar.pack(fill="x")

        self.chat_info_label = tk.Label(top_bar, text="Not logged in")
        self.chat_info_label.pack(side="left")

        logout_button = tk.Button(top_bar, text="Logout", command=self.on_logout)
        logout_button.pack(side="right")

        # Main body
        main_body = tk.Frame(self.chat_frame)
        main_body.pack(fill="both", expand=True, pady=(5, 0))

        # LEFT: contacts + add friend
        left_panel = tk.Frame(main_body)
        left_panel.pack(side="left", fill="y", padx=(0, 5))

        tk.Label(left_panel, text="Add friend (username):").pack(anchor="w")
        self.add_friend_entry = tk.Entry(left_panel)
        self.add_friend_entry.pack(anchor="w", fill="x")
        add_friend_button = tk.Button(left_panel, text="Add", command=self.on_add_friend)
        add_friend_button.pack(anchor="w", pady=(0, 5))

        tk.Label(left_panel, text="Chats").pack(anchor="w", pady=(5, 0))

        self.contacts_listbox = tk.Listbox(left_panel, exportselection=False, height=20)
        self.contacts_listbox.pack(side="left", fill="y")

        contacts_scroll = tk.Scrollbar(left_panel, command=self.contacts_listbox.yview)
        contacts_scroll.pack(side="left", fill="y")
        self.contacts_listbox.config(yscrollcommand=contacts_scroll.set)

        self.contacts_listbox.insert(tk.END, "Everyone")
        self.contacts_listbox.selection_set(0)
        self.listbox_order = ["Everyone"]
        self.contacts_listbox.bind("<<ListboxSelect>>", self.on_contact_selected)

        # RIGHT: chat area
        right_panel = tk.Frame(main_body)
        right_panel.pack(side="left", fill="both", expand=True)

        self.chat_text = scrolledtext.ScrolledText(right_panel, state="disabled", wrap="word", height=20)
        self.chat_text.pack(fill="both", expand=True, pady=(0, 5))

        bottom_bar = tk.Frame(right_panel)
        bottom_bar.pack(fill="x")

        self.msg_entry = tk.Entry(bottom_bar)
        self.msg_entry.pack(side="left", fill="x", expand=True)
        self.msg_entry.bind("<Return>", self.on_send)

        send_button = tk.Button(bottom_bar, text="Send", command=self.on_send)
        send_button.pack(side="left", padx=5)

        clear_button = tk.Button(bottom_bar, text="Clear History", command=self.on_clear_history)
        clear_button.pack(side="left", padx=5)

    # ---------- LOW-LEVEL NETWORK ---------- #

    def parse_host_port(self):
        host = self.host_entry.get().strip()
        port_str = self.port_entry.get().strip()
        try:
            port = int(port_str)
        except ValueError:
            self.set_status("Port must be an integer.")
            return None, None
        return host, port

    def close_socket(self):
        if self.sock_file:
            try:
                self.sock_file.close()
            except OSError:
                pass
            self.sock_file = None
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def send_current(self, text: str) -> bool:
        if not self.sock:
            self.set_status("Not connected to server.")
            return False
        try:
            self.sock.sendall((text + "\n").encode("utf-8"))
            return True
        except OSError as e:
            self.set_status(f"Send failed: {e}")
            self.close_socket()
            self.running = False
            return False

    # ---------- REGISTER / LOGIN / LOGOUT ---------- #

    def on_register(self):
        host, port = self.parse_host_port()
        if host is None:
            return

        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if not username or not password:
            self.set_status("Username and password required.")
            return

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host, port))
            f = s.makefile("r", encoding="utf-8")
            s.sendall(f"REGISTER|{username}|{password}\n".encode("utf-8"))
            line = f.readline()
            if not line:
                self.set_status("No response from server on register.")
            else:
                line = line.strip()
                if line.startswith("OK"):
                    self.set_status("Registered successfully. Now login.")
                else:
                    self.set_status(line)
        except Exception as e:
            self.set_status(f"Register error: {e}")
        finally:
            try:
                f.close()
            except Exception:
                pass
            try:
                s.close()
            except Exception:
                pass

    def on_login(self):
        host, port = self.parse_host_port()
        if host is None:
            return

        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if not username or not password:
            self.set_status("Username and password required.")
            return

        # clean up any existing connection
        self.running = False
        self.close_socket()

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host, port))
            f = s.makefile("r", encoding="utf-8")

            s.sendall(f"LOGIN|{username}|{password}\n".encode("utf-8"))
            self.set_status("Sent login request...")

            resp_line = f.readline()
            if not resp_line:
                self.set_status("No response from server on login.")
                f.close()
                s.close()
                return

            resp_line = resp_line.strip()

            if resp_line.startswith("OK") and "Login successful" in resp_line:
                self.sock = s
                self.sock_file = f
                self.running = True
                self.username = username
                self.logged_in = True
                self.set_status("Login successful.")
                self.show_chat(username)

                self.listener_thread = threading.Thread(target=self.listen_to_server, daemon=True)
                self.listener_thread.start()
            else:
                self.set_status(resp_line)
                f.close()
                s.close()
        except Exception as e:
            self.set_status(f"Login error: {e}")
            self.close_socket()
            self.running = False

    def on_logout(self):
        if self.sock:
            try:
                self.send_current("LOGOUT|")
            except Exception:
                pass
        self.running = False
        self.logged_in = False
        self.username = None

        self.chat_frame.pack_forget()
        self.login_frame.pack(fill="both", expand=True)
        self.chat_info_label.config(text="Not logged in")
        self.set_status("Logged out.")

        self.close_socket()

    def on_close(self):
        try:
            if self.sock:
                try:
                    self.send_current("LOGOUT|")
                except Exception:
                    pass
        finally:
            self.running = False
            self.close_socket()
            self.root.destroy()

    # ---------- LISTENER THREAD & INCOMING LOOP ---------- #

    def listen_to_server(self):
        try:
            while self.running and self.sock_file:
                line = self.sock_file.readline()
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                self.incoming.put(line)
        except Exception:
            pass
        finally:
            self.incoming.put("__DISCONNECTED__")

    def process_incoming(self):
        try:
            while True:
                line = self.incoming.get_nowait()
                if line == "__DISCONNECTED__":
                    if self.logged_in:
                        self.append_chat_message("SYSTEM", "Disconnected from server", "Everyone")
                    else:
                        self.set_status("Disconnected from server")
                    self.close_socket()
                    self.logged_in = False
                    self.running = False
                    break
                self.handle_server_line(line)
        except queue.Empty:
            pass
        except Exception as e:
            self.set_status(f"Internal error: {e}")
        self.root.after(100, self.process_incoming)

    # ---------- SERVER MESSAGE HANDLING ---------- #

    def handle_server_line(self, line: str):
        # HISTORY messages (HISTORY|friend|timestamp|from|text)
        if line.startswith("HISTORY|"):
            parts = line.split("|", 4)
            if len(parts) < 5:
                return
            _, friend, ts_str, from_user, msg = parts
            try:
                ts_val = float(ts_str)
            except ValueError:
                ts_val = time.time()
            self.add_history_message(friend, from_user, msg, ts_val)
            self.add_contact(friend)
            return

        parts = line.split("|", 2)

        if parts[0] == "MSG" and len(parts) == 3:
            _, from_user, msg = parts
            self.append_chat_message(from_user, msg, conversation="Everyone")

        elif parts[0] == "SYSTEM" and len(parts) == 2:
            _, msg = parts
            self.append_chat_message("SYSTEM", msg, conversation="Everyone")

        elif parts[0] == "DM" and len(parts) == 3:
            _, from_user, msg = parts
            self.add_contact(from_user)
            self.append_chat_message(from_user, msg, conversation=from_user)

        elif parts[0] == "USERS" and len(parts) == 2:
            _, user_csv = parts
            online = [u for u in user_csv.split(",") if u]
            self.update_contacts_from_online(online)

        elif parts[0] == "FRIEND_REQUEST" and len(parts) == 2:
            _, from_user = parts
            answer = messagebox.askyesno(
                "Friend request",
                f"{from_user} wants to add you as a friend.\nAccept?"
            )
            if answer:
                self.send_current(f"FRIEND_RESPONSE|{from_user}|ACCEPT")
                self.set_status(f"You accepted friend request from {from_user}")
            else:
                self.send_current(f"FRIEND_RESPONSE|{from_user}|REJECT")
                self.set_status(f"You rejected friend request from {from_user}")

        elif parts[0] == "FRIEND_ACCEPTED" and len(parts) == 2:
            _, other = parts
            self.set_status(f"You are now friends with {other}")
            self.add_contact(other)
            self.append_chat_message("SYSTEM", f"You are now friends with {other}", "Everyone")

        elif parts[0] == "FRIEND_REJECTED" and len(parts) == 2:
            _, other = parts
            self.set_status(f"{other} rejected your friend request")
            self.append_chat_message("SYSTEM", f"{other} rejected your friend request", "Everyone")

        elif parts[0] == "OK":
            # Handle history clear OK specially
            if len(parts) >= 2 and parts[1].startswith("History cleared with "):
                friend = parts[1].replace("History cleared with ", "", 1).strip()
                self.clear_local_history(friend)
                self.set_status(parts[1])
            elif "Logged out" in line:
                self.set_status("Server confirmed logout.")
            else:
                self.set_status(line)

        elif parts[0] == "ERR":
            self.set_status(line)

        else:
            if self.logged_in:
                self.append_chat_message("SYSTEM", line, conversation="Everyone")
            else:
                self.set_status(line)

    # ---------- HISTORY HELPERS ---------- #

    def add_history_message(self, conversation: str, sender: str, message: str, ts_epoch: float):
        """Add a message from history without marking it as unread."""
        ts_str = time.strftime("%H:%M:%S", time.localtime(ts_epoch))
        line = f"{ts_str} {sender}: {message}"

        if conversation not in self.conversations:
            self.conversations[conversation] = []
        self.conversations[conversation].append(line)

        if conversation == self.current_conversation:
            self.refresh_chat_view()

    def clear_local_history(self, friend: str):
        """Clear local messages for this friend (DM conversation)."""
        if friend in self.conversations:
            self.conversations[friend] = []
        self.unread_counts.pop(friend, None)
        if self.current_conversation == friend:
            self.refresh_chat_view()

    # ---------- CHAT UI / FRIENDS ---------- #

    def on_send(self, event=None):
        msg = self.msg_entry.get().strip()
        if not msg:
            return
        if msg.lower() in ("quit", "exit"):
            self.on_logout()
            return

        target = self.current_conversation or "Everyone"
        if target == "Everyone":
            self.send_current("MSG|" + msg)
        else:
            if self.send_current(f"DM|{target}|{msg}"):
                self.append_chat_message("You", msg, conversation=target)

        self.msg_entry.delete(0, tk.END)

    def on_clear_history(self):
        """Ask the server to clear history with the current DM friend."""
        target = self.current_conversation
        if target == "Everyone":
            self.set_status("Cannot clear history for the global chat.")
            return
        if not target:
            self.set_status("No conversation selected.")
            return
        if self.send_current(f"CLEAR_HISTORY|{target}"):
            self.set_status(f"Requested history clear with {target}...")

    def on_add_friend(self):
        target = self.add_friend_entry.get().strip()
        if not target:
            self.set_status("Enter a username to add.")
            return
        if target == self.username:
            self.set_status("You cannot add yourself.")
            return
        if self.send_current(f"FRIEND_REQUEST|{target}"):
            self.set_status(f"Sent friend request to {target}")
            self.add_friend_entry.delete(0, tk.END)

    def on_contact_selected(self, event=None):
        selection = self.contacts_listbox.curselection()
        if not selection:
            return
        idx = selection[0]
        if idx < 0 or idx >= len(self.listbox_order):
            return
        name = self.listbox_order[idx]
        self.current_conversation = name
        if name in self.unread_counts:
            self.unread_counts.pop(name, None)
        self.refresh_chat_view()
        self.rebuild_contacts_listbox()

    def show_chat(self, username: str):
        self.login_frame.pack_forget()
        self.chat_info_label.config(text=f"Logged in as {username}")
        self.chat_frame.pack(fill="both", expand=True)
        self.append_chat_message("SYSTEM", f"Logged in as {username}", conversation="Everyone")

        # reset chat state for new session
        self.conversations = {"Everyone": []}
        self.current_conversation = "Everyone"
        self.contacts = set()
        self.unread_counts = {}
        self.listbox_order = []

        self.contacts_listbox.delete(0, tk.END)
        self.listbox_order.append("Everyone")
        self.contacts_listbox.insert(tk.END, "Everyone")
        self.contacts_listbox.selection_set(0)
        self.refresh_chat_view()

    def set_status(self, text: str):
        self.status_label.config(text=text)

    def append_chat_message(self, sender: str, message: str, conversation: str = "Everyone"):
        ts = time.strftime("%H:%M:%S")
        line = f"{ts} {sender}: {message}"

        if conversation not in self.conversations:
            self.conversations[conversation] = []
        self.conversations[conversation].append(line)

        if conversation != self.current_conversation:
            self.unread_counts[conversation] = self.unread_counts.get(conversation, 0) + 1
            self.rebuild_contacts_listbox()
        else:
            self.chat_text.configure(state="normal")
            self.chat_text.insert(tk.END, line + "\n")
            self.chat_text.see(tk.END)
            self.chat_text.configure(state="disabled")

    def refresh_chat_view(self):
        self.chat_text.configure(state="normal")
        self.chat_text.delete("1.0", tk.END)
        msgs = self.conversations.get(self.current_conversation, [])
        for m in msgs:
            self.chat_text.insert(tk.END, m + "\n")
        self.chat_text.see(tk.END)
        self.chat_text.configure(state="disabled")

    def add_contact(self, username: str):
        if not username or username == self.username:
            return
        if username not in self.contacts:
            self.contacts.add(username)
            self.rebuild_contacts_listbox()

    def update_contacts_from_online(self, online_users):
        for u in online_users:
            if u != self.username:
                self.contacts.add(u)
        self.rebuild_contacts_listbox()

    def rebuild_contacts_listbox(self):
        prev_name = self.current_conversation or "Everyone"

        self.contacts_listbox.delete(0, tk.END)
        self.listbox_order = []

        def add_name(name: str):
            count = self.unread_counts.get(name, 0)
            label = f"{name} ({count})" if count > 0 else name
            self.contacts_listbox.insert(tk.END, label)
            self.listbox_order.append(name)

        add_name("Everyone")
        for name in sorted(self.contacts):
            add_name(name)

        if prev_name in self.listbox_order:
            idx = self.listbox_order.index(prev_name)
        else:
            idx = 0
            prev_name = self.listbox_order[0]
            self.current_conversation = prev_name

        self.contacts_listbox.selection_clear(0, tk.END)
        self.contacts_listbox.selection_set(idx)
        self.contacts_listbox.activate(idx)
        self.refresh_chat_view()


def main():
    root = tk.Tk()
    app = ChatClientGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
