# password_checker_with_report_plus.py
import tkinter as tk
from tkinter import ttk, messagebox
import hashlib
import requests
import string
import math
import pyperclip
import secrets
from datetime import datetime
import os
import csv
import math as _math

# ---------- Utility / Logic ----------

TARGET_ENTROPY_STRONG = 60.0  # bits (approx threshold to be considered "Strong")

def charset_size(password):
    size = 0
    if any(c.islower() for c in password): size += 26
    if any(c.isupper() for c in password): size += 26
    if any(c.isdigit() for c in password): size += 10
    if any(c in string.punctuation for c in password): size += len(string.punctuation)
    return size

def entropy_and_strength(password):
    length = len(password)
    cs = charset_size(password)
    if cs == 0 or length == 0:
        return 0.0, "Very Weak"
    entropy = round(length * math.log2(cs), 2)
    if entropy < 28:
        level = "Very Weak"
    elif entropy < 36:
        level = "Weak"
    elif entropy < 60:
        level = "Moderate"
    elif entropy < 128:
        level = "Strong"
    else:
        level = "Very Strong"
    return entropy, level

def estimate_additional_chars_for_target(password, target_bits=TARGET_ENTROPY_STRONG):
    """Return number of additional characters needed (int) to reach target_bits entropy.
       Returns None if charset size <=1 (can't compute) or already at/above target.
    """
    cs = charset_size(password)
    if cs <= 1:
        return None
    length = len(password)
    current_entropy = length * math.log2(cs)
    if current_entropy >= target_bits:
        return 0
    # needed length L such that L * log2(cs) >= target_bits -> L = ceil(target_bits / log2(cs))
    needed_length = int(_math.ceil(target_bits / math.log2(cs)))
    return max(0, needed_length - length)

def check_pwned_password(password):
    # k-anonymity HIBP check using SHA-1
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        r = requests.get(url, timeout=10)
        if r.status_code != 200:
            return f"Error: API {r.status_code}"
        for line in r.text.splitlines():
            # line format: HASH_SUFFIX:COUNT
            if ":" not in line:
                continue
            h, count = line.split(":")
            if h == suffix:
                return f"Found in {count} breaches"
        return "No breaches found"
    except requests.RequestException:
        return "Network/API error"

def sha1_hex(password):
    return hashlib.sha1(password.encode('utf-8')).hexdigest().upper()

def masked_preview(password):
    if not password:
        return ""
    if len(password) <= 4:
        if len(password) == 1:
            return "*"
        if len(password) == 2:
            return password[0] + "*"
        # 3 or 4
        return password[0] + "*"*(len(password)-2) + password[-1]
    return password[:2] + "*"*(len(password)-4) + password[-2:]

def ensure_reports_dir():
    d = os.path.join(os.getcwd(), "reports")
    os.makedirs(d, exist_ok=True)
    return d

def append_report_txt(entry_text, date_obj=None):
    d = ensure_reports_dir()
    if date_obj is None:
        date_obj = datetime.now()
    fname = f"password_report_{date_obj.strftime('%Y%m%d')}.txt"
    path = os.path.join(d, fname)
    with open(path, "a", encoding="utf-8") as f:
        f.write(entry_text + "\n\n")
    return path

def append_report_csv(row, date_obj=None):
    d = ensure_reports_dir()
    if date_obj is None:
        date_obj = datetime.now()
    fname = f"password_report_{date_obj.strftime('%Y%m%d')}.csv"
    path = os.path.join(d, fname)
    # If file doesn't exist, write header first
    header = ["timestamp", "input_method", "checks_performed", "entropy", "strength", "breach_result",
              "masked_preview", "sha1", "stored_plaintext"]
    file_exists = os.path.exists(path)
    with open(path, "a", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=header)
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)
    return path

def generate_password(length=14, use_upper=True, use_lower=True, use_digits=True, use_symbols=True):
    pool = ""
    if use_upper: pool += string.ascii_uppercase
    if use_lower: pool += string.ascii_lowercase
    if use_digits: pool += string.digits
    if use_symbols: pool += string.punctuation
    if not pool:
        pool = string.ascii_letters + string.digits
    return "".join(secrets.choice(pool) for _ in range(length))

# ---------- GUI ----------

class PasswordCheckerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CyberGuard — Password Analyzer & Reporter")
        self.geometry("640x600")
        self.configure(bg="#0b0f10")
        self.resizable(False, False)

        # Track how password was provided
        self.input_method = "Typed"  # default; updated by Paste/Generate buttons

        # Widgets & state
        self._create_header()
        self._create_body()
        self._create_footer()

    def _create_header(self):
        header = tk.Frame(self, bg="#071011", height=90)
        header.pack(fill="x")
        title = tk.Label(header, text="🔐 CyberGuard — Password Analyzer", bg="#071011", fg="#00FFD5",
                         font=("Segoe UI", 16, "bold"))
        title.place(relx=0.5, rely=0.55, anchor="center")

    def _create_body(self):
        p = {"padx": 16}
        body = tk.Frame(self, bg="#0b0f10")
        body.pack(fill="both", expand=True, pady=(10,0))

        # Entry label & entry
        lbl = tk.Label(body, text="Enter password:", bg="#0b0f10", fg="#DDD", font=("Segoe UI", 12))
        lbl.pack(anchor="w", **p)

        entry_frame = tk.Frame(body, bg="#0b0f10")
        entry_frame.pack(fill="x", padx=16, pady=(6,0))

        self.pw_var = tk.StringVar()
        self.entry = ttk.Entry(entry_frame, textvariable=self.pw_var, show="*", font=("Segoe UI", 13))
        self.entry.pack(side="left", fill="x", expand=True, ipady=6)

        # Show checkbox
        self.show_var = tk.BooleanVar(value=False)
        show_cb = ttk.Checkbutton(entry_frame, text="Show", variable=self.show_var, command=self._toggle_show)
        show_cb.pack(side="left", padx=(8,0))

        # Buttons: Paste, Copy, Generate
        btn_frame = tk.Frame(body, bg="#0b0f10")
        btn_frame.pack(fill="x", padx=16, pady=(8,0))

        paste_btn = ttk.Button(btn_frame, text="Paste", command=self._paste_password)
        paste_btn.pack(side="left")

        copy_btn = ttk.Button(btn_frame, text="Copy", command=self._copy_password)
        copy_btn.pack(side="left", padx=(8,0))

        gen_btn = ttk.Button(btn_frame, text="Generate", command=self._generate_password)
        gen_btn.pack(side="left", padx=(8,0))

        # Generator length slider and label
        self.gen_len = tk.IntVar(value=14)
        gen_len_lbl = tk.Label(btn_frame, text="Length:", bg="#0b0f10", fg="#CCC")
        gen_len_lbl.pack(side="left", padx=(16,4))
        gen_len_scale = ttk.Scale(btn_frame, from_=6, to=32, variable=self.gen_len, orient="horizontal", length=140, command=self._update_gen_len_label)
        gen_len_scale.pack(side="left")
        self.gen_len_display = tk.Label(btn_frame, text=f"{self.gen_len.get()} chars", bg="#0b0f10", fg="#EEE")
        self.gen_len_display.pack(side="left", padx=(6,0))

        # Check button
        check_btn = ttk.Button(self, text="Check & Save", command=self._on_check_and_save)
        check_btn.pack(pady=(14,8))

        # Results frame
        res_frame = tk.LabelFrame(self, text="Results", bg="#0b0f10", fg="#DDD", font=("Segoe UI", 11))
        res_frame.pack(fill="both", expand=True, padx=16, pady=(6,12))

        self.score_label = tk.Label(res_frame, text="Entropy: —", bg="#0b0f10", fg="#FFF", font=("Segoe UI", 12, "bold"))
        self.score_label.pack(anchor="w", pady=(8,2), padx=8)

        self.level_label = tk.Label(res_frame, text="Strength: —", bg="#0b0f10", fg="#FFF", font=("Segoe UI", 12))
        self.level_label.pack(anchor="w", pady=(2,2), padx=8)

        self.breach_label = tk.Label(res_frame, text="Breach: —", bg="#0b0f10", fg="#FFF", font=("Segoe UI", 12))
        self.breach_label.pack(anchor="w", pady=(2,2), padx=8)

        self.features_label = tk.Label(res_frame, text="Checks used: Entropy, HIBP breach", bg="#0b0f10", fg="#AAA",
                                       font=("Segoe UI", 10))
        self.features_label.pack(anchor="w", pady=(8,2), padx=8)

        ttk.Separator(res_frame, orient="horizontal").pack(fill="x", padx=8, pady=(6,6))

        suggestions_lbl = tk.Label(res_frame, text="Suggestions:", bg="#0b0f10", fg="#DDD", font=("Segoe UI", 11, "underline"))
        suggestions_lbl.pack(anchor="w", padx=8)

        self.suggestions_text = tk.Text(res_frame, height=6, wrap="word", state="disabled", bg="#071011", fg="#EEE", font=("Segoe UI", 10))
        self.suggestions_text.pack(fill="both", expand=True, padx=8, pady=(6,8))

        # Save options row (checkboxes)
        save_frame = tk.Frame(self, bg="#0b0f10")
        save_frame.pack(fill="x", padx=16, pady=(0,10))
        self.store_plain_var = tk.BooleanVar(value=False)
        store_cb = ttk.Checkbutton(save_frame, text="Store plaintext in report (not recommended)", variable=self.store_plain_var)
        store_cb.pack(side="left")

        self.include_sha1_var = tk.BooleanVar(value=True)
        sha1_cb = ttk.Checkbutton(save_frame, text="Include SHA1 in report", variable=self.include_sha1_var)
        sha1_cb.pack(side="left", padx=(12,0))

    def _create_footer(self):
        footer = tk.Frame(self, bg="#0b0f10")
        footer.pack(fill="x", side="bottom")
        self.status_label = tk.Label(footer, text="Ready", bg="#0b0f10", fg="#666", font=("Segoe UI", 9))
        self.status_label.pack(anchor="e", padx=12, pady=8)

    # ---------- Actions ----------
    def _toggle_show(self):
        self.entry.config(show="" if self.show_var.get() else "*")

    def _paste_password(self):
        try:
            txt = pyperclip.paste()
            if txt:
                self.pw_var.set(txt)
                self.input_method = "Pasted"
                self.status_label.config(text="Password pasted from clipboard")
            else:
                self.status_label.config(text="Clipboard empty")
        except Exception:
            messagebox.showwarning("Paste failed", "pyperclip not installed or clipboard not accessible.")
            self.status_label.config(text="Paste failed")

    def _copy_password(self):
        pw = self.pw_var.get()
        if not pw:
            self.status_label.config(text="Nothing to copy")
            return
        try:
            pyperclip.copy(pw)
            self.status_label.config(text="Password copied to clipboard")
        except Exception:
            messagebox.showwarning("Copy failed", "pyperclip not installed or copy failed.")

    def _generate_password(self):
        length = max(6, int(self.gen_len.get()))
        pw = generate_password(length=length)
        self.pw_var.set(pw)
        self.input_method = "Generated"
        self.status_label.config(text=f"Generated password (len={length})")
        self.gen_len_display.config(text=f"{length} chars")
        # update UI immediately with strength/breach preview if you want (optional)
        # We'll leave it to the user to press "Check & Save"

    def _update_gen_len_label(self, _=None):
        self.gen_len_display.config(text=f"{int(self.gen_len.get())} chars")

    def _on_check_and_save(self):
        pw = self.pw_var.get()
        if not pw:
            messagebox.showwarning("Missing", "Please enter or generate a password first.")
            return

        # If user wants to store plaintext, show explicit warning
        store_plain = self.store_plain_var.get()
        if store_plain:
            ok = messagebox.askyesno("Warning - storing plaintext",
                                     "Storing plaintext passwords in a report is dangerous.\n\n"
                                     "Do you still want to store the plaintext in the report?")
            if not ok:
                self.store_plain_var.set(False)
                store_plain = False

        # If user didn't interact with Paste or Generate, assume Typed
        if not hasattr(self, "input_method") or not self.input_method:
            self.input_method = "Typed"

        # Perform checks
        entropy, level = entropy_and_strength(pw)
        breach = check_pwned_password(pw)

        # Update UI (color-coded)
        color_map = {
            "Very Weak": "#FF4C4C",
            "Weak": "#FF884C",
            "Moderate": "#FFD24C",
            "Strong": "#66E08B",
            "Very Strong": "#00D6A7"
        }
        clr = color_map.get(level, "#FFF")
        self.score_label.config(text=f"Entropy: {entropy} bits", fg=clr)
        self.level_label.config(text=f"Strength: {level}", fg=clr)
        self.breach_label.config(text=f"Breach: {breach}", fg="#9FEFFF")

        # Suggestions (enhanced)
        suggestions = []
        if len(pw) < 8:
            suggestions.append("Make it at least 8 characters long (12+ recommended).")
        if not any(c.islower() for c in pw): suggestions.append("Add lowercase letters (a-z).")
        if not any(c.isupper() for c in pw): suggestions.append("Add uppercase letters (A-Z).")
        if not any(c.isdigit() for c in pw): suggestions.append("Add digits (0-9).")
        if not any(c in string.punctuation for c in pw): suggestions.append("Add symbols (e.g., !@#$%).")
        if any(s in pw.lower() for s in ["password", "1234", "qwerty", "admin"]):
            suggestions.append("Avoid common words or sequences (e.g., 'password', '1234').")

        # Computed actionable suggestion: extra characters to reach strong
        extra = estimate_additional_chars_for_target(pw, TARGET_ENTROPY_STRONG)
        if extra is None:
            suggestions.append("Unable to estimate additional length — include mixed character types to allow estimation.")
        elif extra > 0:
            suggestions.append(f"Add ~{extra} more character(s) (with current character set) to reach ~{TARGET_ENTROPY_STRONG} bits (Strong).")
        else:
            suggestions.append("Entropy meets Strong threshold — good job!")

        self.suggestions_text.config(state="normal")
        self.suggestions_text.delete("1.0", "end")
        if suggestions:
            for s in suggestions:
                self.suggestions_text.insert("end", f"• {s}\n")
        else:
            self.suggestions_text.insert("end", "No suggestions — good job!")
        self.suggestions_text.config(state="disabled")

        # Prepare report entry
        now = datetime.now()
        sha1 = sha1_hex(pw) if self.include_sha1_var.get() else ""
        preview = masked_preview(pw)
        features_used = ["Entropy check", "HIBP breach check"]
        entry_lines = [
            f"Timestamp: {now.isoformat()}",
            f"Input method: {self.input_method}",
            f"Checks performed: {', '.join(features_used)}",
            f"Entropy: {entropy}",
            f"Strength level: {level}",
            f"Breach result: {breach}",
        ]
        if store_plain:
            entry_lines.insert(3, f"Plaintext password: {pw}")
            stored_plain = pw
        else:
            entry_lines.insert(3, f"Masked preview: {preview}")
            stored_plain = ""
            if sha1:
                entry_lines.insert(4, f"SHA1: {sha1}")

        entry_text = "\n".join(entry_lines)

        # Save to text file
        txt_path = append_report_txt(entry_text, now)

        # Save to CSV row
        csv_row = {
            "timestamp": now.isoformat(),
            "input_method": self.input_method,
            "checks_performed": ", ".join(features_used),
            "entropy": entropy,
            "strength": level,
            "breach_result": breach,
            "masked_preview": preview,
            "sha1": sha1,
            "stored_plaintext": stored_plain
        }
        csv_path = append_report_csv(csv_row, now)

        self.status_label.config(text=f"Saved report to {os.path.basename(txt_path)} and {os.path.basename(csv_path)}")
        # Reset input method to default for next action
        self.input_method = "Typed"

# ---------- Run ----------
if __name__ == "__main__":
    app = PasswordCheckerApp()
    app.mainloop()
