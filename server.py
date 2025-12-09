import socket
import threading
import json
import os
import hashlib
import time

HOST = "0.0.0.0"
PORT = 5000
ACCOUNTS_FILE = "accounts.json"
MESSAGES_FILE = "messages.json"

# Max number of DM messages stored per conversation
MAX_HISTORY_PER_CONV = 100

# Global state (no locks for simplicity – OK for a toy project)
USERS = {}                     # username -> password_hash
FRIENDS = {}                   # username -> set of friend usernames
PENDING_FRIEND_REQUESTS = {}   # to_user -> set(from_user)
CLIENTS = {}                   # username -> socket

# DM history: conv_key (userA|userB sorted) -> list of {ts, from, to, text}
MESSAGES = {}


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def load_data():
    global USERS, FRIENDS
    if not os.path.exists(ACCOUNTS_FILE):
        USERS = {}
        FRIENDS = {}
        return
    try:
        with open(ACCOUNTS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        USERS = {}
        FRIENDS = {}
        return
    USERS = data.get("users", {})
    raw_friends = data.get("friends", {})
    FRIENDS = {u: set(v) for u, v in raw_friends.items()}


def save_data():
    data = {
        "users": USERS,
        "friends": {u: list(v) for u, v in FRIENDS.items()},
    }
    with open(ACCOUNTS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f)


def load_messages():
    global MESSAGES
    if not os.path.exists(MESSAGES_FILE):
        MESSAGES = {}
        return
    try:
        with open(MESSAGES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        MESSAGES = {}
        return
    MESSAGES = data.get("messages", {})


def save_messages():
    data = {"messages": MESSAGES}
    with open(MESSAGES_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f)


def store_dm_message(from_user: str, to_user: str, text: str):
    """Store a DM in the history (keep only last MAX_HISTORY_PER_CONV)."""
    key = "|".join(sorted([from_user, to_user]))
    conv = MESSAGES.setdefault(key, [])
    conv.append({
        "ts": time.time(),
        "from": from_user,
        "to": to_user,
        "text": text,
    })
    # Trim to last N messages
    if len(conv) > MAX_HISTORY_PER_CONV:
        MESSAGES[key] = conv[-MAX_HISTORY_PER_CONV:]
    save_messages()


def clear_history_between(user1: str, user2: str) -> bool:
    """Delete stored history for this pair. Returns True if something was deleted."""
    key = "|".join(sorted([user1, user2]))
    if key in MESSAGES:
        del MESSAGES[key]
        save_messages()
        return True
    return False


def debug(msg: str):
    print(msg, flush=True)


def broadcast(message: str, exclude_username=None):
    """Send a message to all connected users (optionally excluding one)."""
    dead = []
    for uname, conn in CLIENTS.items():
        if uname == exclude_username:
            continue
        try:
            conn.sendall((message + "\n").encode("utf-8"))
        except OSError:
            dead.append(uname)
    for uname in dead:
        CLIENTS.pop(uname, None)


def send_user_list_to(username: str):
    """
    Send USERS|friend1,friend2,... to a single user.
    Only includes friends who are currently online.
    """
    conn = CLIENTS.get(username)
    if not conn:
        return
    my_friends = FRIENDS.get(username, set())
    online_friends = sorted([u for u in my_friends if u in CLIENTS])
    msg = "USERS|" + ",".join(online_friends)
    try:
        conn.sendall((msg + "\n").encode("utf-8"))
    except OSError:
        pass


def send_user_lists_to_all():
    for uname in list(CLIENTS.keys()):
        send_user_list_to(uname)


def send_history_to(username: str):
    """
    Send DM history for this user.
    For each stored DM: HISTORY|friend|timestamp|from|text
    """
    conn = CLIENTS.get(username)
    if not conn:
        return

    for key, msgs in MESSAGES.items():
        users_in_conv = key.split("|", 1)
        if username not in users_in_conv:
            continue
        # friend is the other user in the pair
        if users_in_conv[0] == username:
            friend = users_in_conv[1]
        else:
            friend = users_in_conv[0]

        for m in msgs:
            ts = m.get("ts", time.time())
            from_user = m.get("from", "")
            text = m.get("text", "")
            line = f"HISTORY|{friend}|{ts}|{from_user}|{text}"
            try:
                conn.sendall((line + "\n").encode("utf-8"))
            except OSError:
                return  # if sending fails, just stop


def handle_register(parts):
    if len(parts) != 3:
        return "ERR|Invalid REGISTER format. Use: REGISTER|username|password"
    _, username, password = parts
    username = username.strip()
    password = password.strip()
    if not username or not password:
        return "ERR|Username and password cannot be empty"
    if username in USERS:
        return "ERR|Username already exists"
    USERS[username] = hash_password(password)
    FRIENDS.setdefault(username, set())
    save_data()
    return "OK|Registered successfully"


def handle_login(parts, conn):
    if len(parts) != 3:
        return "ERR|Invalid LOGIN format. Use: LOGIN|username|password", None
    _, username, password = parts
    username = username.strip()
    password = password.strip()

    stored = USERS.get(username)
    if stored is None:
        return "ERR|Unknown username", None
    if stored != hash_password(password):
        return "ERR|Incorrect password", None

    # Kick old session if needed
    old_conn = CLIENTS.get(username)
    if old_conn is not None and old_conn is not conn:
        try:
            old_conn.sendall(b"SYSTEM|You were logged out (login elsewhere)\n")
        except OSError:
            pass
        try:
            old_conn.close()
        except OSError:
            pass

    CLIENTS[username] = conn
    FRIENDS.setdefault(username, set())
    return "OK|Login successful", username


def handle_dm(from_user, parts):
    if len(parts) != 3:
        return "ERR|Invalid DM format. Use: DM|username|message"
    _, to_user, msg = parts
    to_user = to_user.strip()
    msg = msg.strip()
    if not msg:
        return "ERR|Empty message"
    if to_user not in FRIENDS.get(from_user, set()):
        return "ERR|You can only DM friends"
    target_conn = CLIENTS.get(to_user)
    if not target_conn:
        return f"ERR|User '{to_user}' is not online"
    try:
        target_conn.sendall((f"DM|{from_user}|{msg}\n").encode("utf-8"))
    except OSError:
        return f"ERR|Failed to send DM to {to_user}"

    # Store in history after successful send
    store_dm_message(from_user, to_user, msg)
    return None


def handle_friend_request(from_user, parts):
    if len(parts) != 2:
        return "ERR|Invalid FRIEND_REQUEST format. Use: FRIEND_REQUEST|username"
    _, to_user = parts
    to_user = to_user.strip()
    if not to_user:
        return "ERR|Missing target username"
    if to_user not in USERS:
        return "ERR|No such user"
    if to_user == from_user:
        return "ERR|You cannot add yourself"
    if to_user in FRIENDS.get(from_user, set()):
        return "ERR|You are already friends"

    pending_for_to = PENDING_FRIEND_REQUESTS.setdefault(to_user, set())
    if from_user in pending_for_to:
        return "ERR|Friend request already sent"

    target_conn = CLIENTS.get(to_user)
    if not target_conn:
        return "ERR|User is not online"

    pending_for_to.add(from_user)
    try:
        target_conn.sendall((f"FRIEND_REQUEST|{from_user}\n").encode("utf-8"))
    except OSError:
        pending_for_to.discard(from_user)
        return "ERR|Failed to send friend request"
    return "OK|Friend request sent"


def handle_friend_response(from_user, parts):
    if len(parts) != 3:
        return "ERR|Invalid FRIEND_RESPONSE format. Use: FRIEND_RESPONSE|username|ACCEPT/REJECT"
    _, other_user, decision = parts
    other_user = other_user.strip()
    decision = decision.strip().upper()
    if decision not in ("ACCEPT", "REJECT"):
        return "ERR|Decision must be ACCEPT or REJECT"

    pending_from = PENDING_FRIEND_REQUESTS.get(from_user, set())
    if other_user not in pending_from:
        return "ERR|No pending friend request from that user"
    pending_from.remove(other_user)
    if not pending_from:
        PENDING_FRIEND_REQUESTS.pop(from_user, None)

    requester_conn = CLIENTS.get(other_user)
    responder_conn = CLIENTS.get(from_user)

    if decision == "ACCEPT":
        FRIENDS.setdefault(from_user, set()).add(other_user)
        FRIENDS.setdefault(other_user, set()).add(from_user)
        save_data()

        if requester_conn:
            try:
                requester_conn.sendall((f"FRIEND_ACCEPTED|{from_user}\n").encode("utf-8"))
            except OSError:
                pass
        if responder_conn:
            try:
                responder_conn.sendall((f"FRIEND_ACCEPTED|{other_user}\n").encode("utf-8"))
            except OSError:
                pass
        send_user_lists_to_all()
    else:
        if requester_conn:
            try:
                requester_conn.sendall((f"FRIEND_REJECTED|{from_user}\n").encode("utf-8"))
            except OSError:
                pass

    return None


def handle_clear_history(from_user, parts):
    """
    CLEAR_HISTORY|other_user
    Deletes stored DM history between from_user and other_user.
    """
    if len(parts) != 2:
        return "ERR|Invalid CLEAR_HISTORY format. Use: CLEAR_HISTORY|username"
    _, other_user = parts
    other_user = other_user.strip()
    if not other_user:
        return "ERR|Missing target username"

    if other_user not in USERS:
        return "ERR|No such user"

    # Optional: require that they're friends to clear DM history
    if other_user not in FRIENDS.get(from_user, set()):
        return "ERR|You can only clear history with friends"

    if not clear_history_between(from_user, other_user):
        return "ERR|No history with that user"

    # Notify the other user (if online) that history was cleared on the server
    other_conn = CLIENTS.get(other_user)
    if other_conn:
        try:
            other_conn.sendall(
                (f"SYSTEM|History between you and {from_user} was cleared on the server\n").encode("utf-8")
            )
        except OSError:
            pass

    return f"OK|History cleared with {other_user}"


def handle_client(conn, addr):
    debug(f"[+] Connection from {addr}")
    username = None
    try:
        file = conn.makefile("r", encoding="utf-8")
        while True:
            line = file.readline()
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            debug(f"[recv] {addr} user={username!r}: {line}")
            parts = line.split("|", 2)
            cmd = parts[0].upper()

            if username is None:
                # not logged in yet
                if cmd == "REGISTER":
                    response = handle_register(parts)
                    debug(f"[send] to {addr}: {response}")
                    conn.sendall((response + "\n").encode("utf-8"))
                elif cmd == "LOGIN":
                    response, logged_user = handle_login(parts, conn)
                    debug(f"[send] to {addr}: {response}")
                    conn.sendall((response + "\n").encode("utf-8"))
                    if response.startswith("OK"):
                        username = logged_user
                        broadcast(f"SYSTEM|{username} joined the chat", exclude_username=username)
                        send_user_lists_to_all()
                        # After login success, send DM history
                        send_history_to(username)
                else:
                    conn.sendall(b"ERR|Not authenticated. Please LOGIN or REGISTER first\n")
            else:
                # already logged in
                if cmd == "MSG":
                    if len(parts) != 2:
                        conn.sendall(b"ERR|Invalid MSG format. Use: MSG|your text\n")
                        continue
                    _, msg = parts
                    msg = msg.strip()
                    if not msg:
                        continue
                    broadcast(f"MSG|{username}|{msg}")
                elif cmd == "DM":
                    err = handle_dm(username, parts)
                    if err:
                        conn.sendall((err + "\n").encode("utf-8"))
                elif cmd == "FRIEND_REQUEST":
                    response = handle_friend_request(username, parts)
                    conn.sendall((response + "\n").encode("utf-8"))
                elif cmd == "FRIEND_RESPONSE":
                    err = handle_friend_response(username, parts)
                    if err:
                        conn.sendall((err + "\n").encode("utf-8"))
                elif cmd == "CLEAR_HISTORY":
                    response = handle_clear_history(username, parts)
                    conn.sendall((response + "\n").encode("utf-8"))
                elif cmd == "LOGOUT":
                    conn.sendall(b"OK|Logged out\n")
                    debug(f"[i] {username} requested logout, closing connection")
                    return
                else:
                    conn.sendall(b"ERR|Unknown command\n")
    except Exception as e:
        debug(f"[!] Error with {addr}: {e}")
    finally:
        if username:
            if CLIENTS.get(username) is conn:
                CLIENTS.pop(username, None)
            broadcast(f"SYSTEM|{username} left the chat", exclude_username=username)
            send_user_lists_to_all()
        try:
            conn.close()
        except OSError:
            pass
        debug(f"[-] Disconnected {addr}")


def main():
    load_data()
    load_messages()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        print(f"Server listening on {HOST}:{PORT}", flush=True)
        while True:
            conn, addr = s.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()


if __name__ == "__main__":
    main()
