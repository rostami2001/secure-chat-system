import tkinter as tk
from tkinter import messagebox, scrolledtext
from tkinter import simpledialog
import json
import socket


class SecureChatClient:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Chat Client")

        self.server_ip = "localhost"
        self.server_port = 12345

        self.create_widgets()

        self.max_attempts = 3
        self.lockout_duration = 30
        self.failed_attempts = {}
        self.locked_accounts = {}


    def create_widgets(self):
        self.login_frame = tk.Frame(self.root)
        self.login_frame.pack(pady=10)

        tk.Label(self.login_frame, text="Email:").grid(row=0, column=0)
        self.email_entry = tk.Entry(self.login_frame)
        self.email_entry.grid(row=0, column=1)

        tk.Label(self.login_frame, text="Username:").grid(row=1, column=0)
        self.username_entry = tk.Entry(self.login_frame)
        self.username_entry.grid(row=1, column=1)

        tk.Label(self.login_frame, text="Password:").grid(row=2, column=0)
        self.password_entry = tk.Entry(self.login_frame, show='*')
        self.password_entry.grid(row=2, column=1)

        tk.Label(self.login_frame, text="Confirm Password:").grid(row=3, column=0)
        self.confirm_password_entry = tk.Entry(self.login_frame, show='*')
        self.confirm_password_entry.grid(row=3, column=1)

        self.super_admin_var = tk.BooleanVar()
        tk.Checkbutton(self.login_frame, text="Register as Super Admin", variable=self.super_admin_var).grid(row=4,
                                                                                                             columnspan=2)

        tk.Button(self.login_frame, text="Register", command=self.register).grid(row=5, columnspan=2, pady=10)
        tk.Button(self.login_frame, text="Login", command=self.login).grid(row=6, columnspan=2, pady=10)

        self.chat_frame = tk.Frame(self.root)

        tk.Label(self.chat_frame, text="Receiver:").grid(row=0, column=0)
        self.receiver_entry = tk.Entry(self.chat_frame)
        self.receiver_entry.grid(row=0, column=1)

        tk.Label(self.chat_frame, text="Message:").grid(row=1, column=0)
        self.message_entry = tk.Entry(self.chat_frame)
        self.message_entry.grid(row=1, column=1)

        tk.Button(self.chat_frame, text="Send", command=self.send_private_message).grid(row=2, columnspan=2, pady=10)

        self.group_frame = tk.Frame(self.root)

        tk.Label(self.group_frame, text="Group ID:").grid(row=0, column=0)
        self.group_id_entry = tk.Entry(self.group_frame)
        self.group_id_entry.grid(row=0, column=1)

        tk.Button(self.group_frame, text="Create Group", command=self.create_group).grid(row=1, columnspan=2, pady=10)
        tk.Button(self.group_frame, text="Add to Group", command=self.add_to_group).grid(row=2, columnspan=2, pady=10)
        tk.Button(self.group_frame, text="Remove from Group", command=self.remove_from_group).grid(row=3, columnspan=2,
                                                                                                   pady=10)
        tk.Button(self.group_frame, text="Send Group Message", command=self.send_group_message).grid(row=4,
                                                                                                     columnspan=2,
                                                                                                     pady=10)
        self.messages_frame = tk.Frame(self.root)
        self.messages_frame.pack(pady=10)

        tk.Button(self.messages_frame, text="Fetch Messages", command=self.fetch_messages).pack(pady=5)
        self.messages_text = scrolledtext.ScrolledText(self.messages_frame, width=50, height=20)
        self.messages_text.pack(pady=5)

        tk.Button(self.chat_frame, text="Change User Role", command=self.change_user_role).grid(row=3, columnspan=2,
                                                                                                pady=10)

    def register(self):
        email = self.email_entry.get()
        username = self.email_entry.get().split('@')[0]
        password = self.password_entry.get()
        confirm_password = self.confirm_password_entry.get()
        role = 'super admin' if self.super_admin_var.get() else 'user'

        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match.")
            return

        request = {
            'type': 'register',
            'email': email,
            'username': username,
            'password': password,
            'confirm_password': confirm_password,
            'role': role
        }

        response = self.send_request(request)
        if response['status'] == 'success':
            messagebox.showinfo("Success", "Registration successful.")
        else:
            messagebox.showerror("Error", response['message'])

    def change_user_role(self):
        user_email = simpledialog.askstring("Change User Role", "Enter user's email:")
        new_role = simpledialog.askstring("Change User Role", "Enter new role (user, admin, super admin):")

        if user_email and new_role:
            request = {
                'type': 'change_role',
                'email': user_email,
                'role': new_role,
                'requester_email': self.email_entry.get()
            }

            response = self.send_request(request)
            if response['status'] == 'success':
                messagebox.showinfo("Success", "User role changed successfully.")
            else:
                messagebox.showerror("Error", response['message'])

    def lock_account(self, email):
        self.locked_accounts[email] = time.time() + self.lockout_duration
        messagebox.showerror("Error", "Account locked due to too many failed login attempts. Try again later.")


    def login(self):
        email = self.email_entry.get()
        password = self.password_entry.get()

        if email in self.locked_accounts and time.time() < self.locked_accounts[email]:
            remaining_time = int(self.locked_accounts[email] - time.time())
            messagebox.showerror("Error", f"Account is locked. Try again after {remaining_time} seconds.")
            return

        request = {
            'type': 'login',
            'email': email,
            'password': password
        }

        response = self.send_request(request)
        if response['status'] == 'success':
            self.failed_attempts[email] = 0
            self.login_frame.pack_forget()
            self.chat_frame.pack(pady=10)
            self.group_frame.pack(pady=10)
            self.messages_frame.pack(pady=10)
        else:
            self.failed_attempts[email] = self.failed_attempts.get(email, 0) + 1
            if self.failed_attempts[email] >= self.max_attempts:
                self.lock_account(email)
            else:
                remaining_attempts = self.max_attempts - self.failed_attempts[email]
                messagebox.showerror("Error", f"Login failed. {remaining_attempts} attempts remaining.")

    def send_private_message(self):
        receiver = self.receiver_entry.get()
        message = self.message_entry.get()

        request = {
            'type': 'private_chat',
            'sender': self.email_entry.get(),
            'receiver': receiver,
            'message': message
        }

        response = self.send_request(request)
        if response['status'] == 'success':
            messagebox.showinfo("Success", "Message sent securely.")
        else:
            messagebox.showerror("Error", response['message'])

    def create_group(self):
        group_id = self.group_id_entry.get()
        request = {
            'type': 'create_group',
            'group_id': group_id,
            'creator': self.email_entry.get()
        }

        response = self.send_request(request)
        if response['status'] == 'success':
            messagebox.showinfo("Success", "Group created.")
        else:
            messagebox.showerror("Error", response['message'])

    def add_to_group(self):
        group_id = self.group_id_entry.get()
        requester_email = self.email_entry.get()

        def add_user_to_group(user_email):
            request = {
                'type': 'add_to_group',
                'group_id': group_id,
                'user_to_add': user_email,
                'requester_email': requester_email
            }

            response = self.send_request(request)
            if response['status'] == 'success':
                messagebox.showinfo("Success", "User added to group.")
            else:
                messagebox.showerror("Error", response['message'])

        user_email = simpledialog.askstring("Add User to Group", "Enter user's email:")
        if user_email:
            user_email = user_email.strip()

            add_user_to_group(user_email)

    def remove_from_group(self):
        group_id = self.group_id_entry.get()
        requester_email = self.email_entry.get()

        def remove_user_from_group(user_email):
            request = {
                'type': 'remove_from_group',
                'group_id': group_id,
                'user_to_remove': user_email,
                'requester_email': requester_email
            }

            response = self.send_request(request)
            if response['status'] == 'success':
                messagebox.showinfo("Success", "User removed from group.")
            else:
                messagebox.showerror("Error", response['message'])

        user_email = simpledialog.askstring("Remove User from Group", "Enter user's email:")
        if user_email:
            user_email = user_email.strip()

            remove_user_from_group(user_email)

    def send_group_message(self):
        group_id = self.group_id_entry.get()
        message = self.message_entry.get()
        sender = self.email_entry.get()

        request = {
            'type': 'send_group_message',
            'sender': sender,
            'group_id': group_id,
            'message': message
        }

        response = self.send_request(request)
        if response['status'] == 'success':
            messagebox.showinfo("Success", "Group message sent securely.")
        else:
            messagebox.showerror("Error", response['message'])

    def fetch_messages(self):
        email = self.email_entry.get()
        request = {
            'type': 'fetch_messages',
            'email': email
        }

        response = self.send_request(request)
        if response['status'] == 'success':
            self.messages_text.delete(1.0, tk.END)
            for message in response['messages']:
                sender = message['sender']
                decrypted_message = message['message']
                group_name = message.get('group_name', None)
                if group_name:
                    self.messages_text.insert(tk.END,
                                              f"From: {sender}\nGroup: {group_name}\nMessage: {decrypted_message}\n\n")
                else:
                    self.messages_text.insert(tk.END, f"From: {sender}\nMessage: {decrypted_message}\n\n")
        else:
            messagebox.showerror("Error", response['message'])

    def send_request(self, request):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                client_socket.connect((self.server_ip, self.server_port))
                client_socket.send(json.dumps(request).encode('utf-8'))
                response = json.loads(client_socket.recv(4096).decode('utf-8'))
                return response
        except Exception as e:
            messagebox.showerror("Error", f"Could not connect to server: {e}")
            return {}


if __name__ == "__main__":
    root = tk.Tk()
    app = SecureChatClient(root)
    root.mainloop()
