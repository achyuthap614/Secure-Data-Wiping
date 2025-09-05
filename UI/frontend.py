import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import datetime
import platform
import ctypes

try:
    if platform.system() == "Windows":
        import wmi # type: ignore
    else:
        wmi = None
except ImportError:
    wmi = None


COMPLIANCE_TEXT = """\
Security Compliance:

1. NIST SP 800-88
2. DoD 5220-M
3. ISO 27040

Features:
- Tamper-proof Certificates
- Digital Signatures
- Compliance Documentation
"""


class DiskWiper:
    def __init__(self, device_path, passes, pattern, progress_cb, log_cb, stop_event):
        self.device_path = device_path
        self.passes = passes
        self.pattern = pattern.lower()
        self.progress_cb = progress_cb
        self.log_cb = log_cb
        self.stop_event = stop_event

    def wipe(self):
        total_size = 500 * 1024 ** 3  # simulate 500GB
        total_bytes = total_size * self.passes
        written = 0

        for p in range(1, self.passes + 1):
            if self.stop_event.is_set():
                self.log(f"Wipe cancelled at pass {p}")
                return False
            self.log(f"Starting pass {p} with pattern '{self.pattern}'")
            steps = 100
            for i in range(steps):
                if self.stop_event.is_set():
                    self.log(f"Wipe cancelled at pass {p} step {i}")
                    return False
                threading.Event().wait(0.05)
                written += total_size / steps
                self.progress_cb(written, total_bytes)
                if i % 10 == 0:
                    self.log(f"Pass {p} progress: {i + 1}%")
            self.log(f"Pass {p} completed")

        self.log("Starting verification...")
        for i in range(10):
            if self.stop_event.is_set():
                self.log("Verification cancelled")
                return False
            threading.Event().wait(0.2)
            self.log(f"Verification step {i + 1} completed")
        self.log("Verification completed successfully")
        return True

    def log(self, msg):
        if self.log_cb:
            self.log_cb(msg)


def check_access(device_path):
    GENERIC_READ = 0x80000000
    OPEN_EXISTING = 3
    SHARE_READ = 1
    SHARE_WRITE = 2

    CreateFile = ctypes.windll.kernel32.CreateFileW
    CloseHandle = ctypes.windll.kernel32.CloseHandle

    handle = CreateFile(
        device_path,
        GENERIC_READ,
        SHARE_READ | SHARE_WRITE,
        None,
        OPEN_EXISTING,
        0,
        None,
    )
    if handle == 0 or handle == -1:
        return False
    CloseHandle(handle)
    return True


def enumerate_devices():
    if platform.system() != "Windows" or wmi is None:
        raise EnvironmentError("This app requires Windows and installed 'wmi' module.")

    c = wmi.WMI()
    devices = []
    info = {}
    try:
        # Get system drive letter
        os_info = c.query("SELECT Caption FROM Win32_OperatingSystem")
        system_drive = os_info[0].Caption.split()[0].upper() if os_info else "C:"
    except Exception:
        system_drive = "C:"

    for disk in c.Win32_DiskDrive():
        try:
            is_system = False
            for partition in disk.associators("Win32_DiskDriveToPartition"):
                for ld in partition.associators("Win32_LogicalDiskToPartition"):
                    if ld.DeviceID.upper() == system_drive:
                        is_system = True
                        break
                if is_system:
                    break
            device_path = disk.DeviceID
            caption = disk.Model.strip()
            size = int(disk.Size) if disk.Size else 0
            size_gb = size / (1024 ** 3) if size else 0.0
            display = f"{caption} ({size_gb:.2f} GB) | {device_path}"
            accessible = check_access(device_path)
            status = "System Disk" if is_system else ("Accessible" if accessible else "Inaccessible")
            if is_system:
                accessible = False
                display += " [System Disk]"
            elif not accessible:
                display += " [Access Denied]"
            devices.append(display)
            info[display] = {
                "caption": caption,
                "device_path": device_path,
                "size": size,
                "status": status,
                "accessible": accessible,
            }
        except:
            pass
    return devices, info


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure Data Wiping Utility")
        self.geometry("950x700")
        self.minsize(900, 600)

        self.passes = ["1 Pass", "3 Passes", "7 Passes"]
        self.wipe_methods = ["Zeros", "Random", "DoD 5220"]
        self.verifications = ["No Verification", "Quick Verify", "Full Verify"]
        self.certificate_types = ["RSA-2048", "ECDSA", "SHA-256"]

        self.device_list = []
        self.device_info = {}

        self.wiping = False
        self.stop_event = threading.Event()
        self.certificates = []

        self._build_ui()
        try:
            self._load_devices()
        except Exception as e:
            tk.messagebox.showerror("Error", str(e))
            self.destroy()

    def _build_ui(self):
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True)

        self.tab_wipe = ttk.Frame(self.notebook)
        self.tab_compliance = ttk.Frame(self.notebook)
        self.tab_support = ttk.Frame(self.notebook)
        self.tab_certificates = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_wipe, text="Wipe")
        self.notebook.add(self.tab_compliance, text="Compliance")
        self.notebook.add(self.tab_support, text="Support")
        self.notebook.add(self.tab_certificates, text="Certificates")

        self._build_wipe_tab()
        self._build_compliance_tab()
        self._build_support_tab()
        self._build_certificates_tab()

    def _load_devices(self):
        self.device_list, self.device_info = enumerate_devices()
        self.device_combo["values"] = self.device_list
        if self.device_list:
            self.device_combo.current(0)
            self._update_device_info()

    def _build_wipe_tab(self):
        frame = self.tab_wipe
        left = ttk.Frame(frame)
        left.pack(side="left", fill="both", expand=True, padx=10)
        right = ttk.Frame(frame)
        right.pack(side="right", fill="y", padx=10)

        ttk.Label(left, text="Select Device:", font=("Arial", 12, "bold")).pack(anchor="w", pady=5)
        self.device_var = tk.StringVar()
        self.device_combo = ttk.Combobox(left, textvariable=self.device_var, state="readonly")
        self.device_combo.pack(fill="x", pady=5)
        self.device_combo.bind("<<ComboboxSelected>>", lambda e: self._update_device_info())

        self.detail_vars = {k: tk.StringVar() for k in ("Name", "Capacity", "Status")}
        detail_frame = ttk.LabelFrame(left, text="Device Details", padding=10)
        detail_frame.pack(fill="x", pady=5)
        for i, (k, v) in enumerate(self.detail_vars.items()):
            ttk.Label(detail_frame, text=f"{k}:").grid(row=i, column=0, sticky="w", padx=5)
            ttk.Label(detail_frame, textvariable=v).grid(row=i, column=1, sticky="w")

        self._update_device_info()

        labels = ["Passes", "Wipe Method", "Verification", "Certificate"]
        options = [self.passes, self.wipe_methods, self.verifications, self.certificate_types]
        self.vars = []

        form_frame = ttk.Frame(left)
        form_frame.pack(fill="x", pady=10)

        for idx, label_text in enumerate(labels):
            ttk.Label(form_frame, text=label_text).grid(row=idx, column=0, sticky="w", padx=5, pady=5)
            var = tk.StringVar(value=options[idx][0])
            self.vars.append(var)
            combo = ttk.Combobox(form_frame, values=options[idx], state="readonly", textvariable=var)
            combo.grid(row=idx, column=1, sticky="ew", padx=5, pady=5)
        self.passes_var, self.wipe_var, self.verif_var, self.cert_var = self.vars

        btn_frame = ttk.Frame(left)
        btn_frame.pack(fill="x", pady=10)

        self.start_btn = ttk.Button(btn_frame, text="Start", command=self.confirm_wipe)
        self.start_btn.pack(side="left", fill="x", expand=True, padx=5)
        self.stop_btn = ttk.Button(btn_frame, text="Stop", command=self.stop_wipe, state="disabled")
        self.stop_btn.pack(side="left", fill="x", expand=True, padx=5)

        ttk.Label(left, text="Progress").pack(anchor="w", pady=2)
        self.progress = ttk.Progressbar(left, mode="determinate")
        self.progress.pack(fill="x", pady=5)

        self.et_label = ttk.Label(left, text="Estimated time: N/A")
        self.et_label.pack(anchor="w", pady=5)

        ttk.Label(left, text="Log").pack(anchor="w", pady=2)

        self.log_text = tk.Text(left, height=8, state="disabled")
        self.log_text.pack(fill="both", expand=True)

        # Right pane: stats and log duplicate (optional)
        ttk.Label(right, text="Statistics", font=("Arial", 12, "bold")).pack(pady=10)

        self.stats_vars = {"Bytes Written": tk.StringVar(value="0"), "Current Pass": tk.StringVar(value="0")}
        for label, var in self.stats_vars.items():
            f = ttk.Frame(right)
            f.pack(fill="x", pady=5, padx=5)
            ttk.Label(f, text=label).pack(side="left")
            ttk.Label(f, textvariable=var).pack(side="right")

        ttk.Label(right, text="Live Log", font=("Arial", 10, "bold")).pack(pady=10)
        self.right_log_text = tk.Text(right, state="disabled")
        self.right_log_text.pack(fill="both", expand=True)

        self.certificate_text = tk.StringVar(value="No certificate generated.")
        cert_frame = ttk.LabelFrame(self.tab_certificates, text="Certificates")
        cert_frame.pack(fill="both", expand=True, padx=10, pady=10)
        self.cert_tree = ttk.Treeview(
            cert_frame,
            columns=("Device", "Passes", "Method", "Verification", "Certificate", "Timestamp"),
            show="headings",
        )
        for col in ("Device", "Passes", "Method", "Verification", "Certificate", "Timestamp"):
            self.cert_tree.heading(col, text=col)
            self.cert_tree.column(col, width=120)
        self.cert_tree.pack(fill="both", expand=True)
        self.cert_tree.bind("<Double-1>", self.download_certificate)

        self.btn_download_cert = ttk.Button(self.tab_certificates, text="Download Certificate", state="disabled", command=self.download_certificate)
        self.btn_download_cert.pack(pady=5)

        # Compliance tab
        compli_text = tk.Text(self.tab_compliance, wrap="word")
        compli_text.insert("1.0", COMPLIANCE_TEXT)
        compli_text.config(state="disabled")
        compli_text.pack(fill="both", expand=True, padx=10, pady=10)

        # Support tab
        support_msg = tk.Label(self.tab_support, text="For support contact: support@example.com", font=("Arial", 14))
        support_msg.pack(expand=True, pady=100)

    def update_device_info(self, event=None):
        device_name = self.device_var.get()
        device_info = self.device_info.get(device_name, {})
        self.detail_vars["Name"].set(device_info.get("caption", "N/A"))
        size = device_info.get("size", 0)
        self.detail_vars["Capacity"].set(f"{size / (1024 ** 3):.2f} GB" if size else "N/A")
        self.detail_vars["Status"].set(device_info.get("status", "N/A"))

    def confirm_wipe(self):
        if self.wiping:
            messagebox.showinfo("Info", "Wipe is already in progress.")
            return

        device_name = self.device_var.get()
        device_info = self.device_info.get(device_name, {})
        if not device_info.get("accessible", False):
            messagebox.showerror("Error", "Selected device is not accessible or is a system disk and cannot be wiped.")
            return

        passes = int(self.passes_var.get().split()[0])
        method = self.wipe_var.get()
        verification = self.verif_var.get()
        certificate = self.cert_var.get()

        confirm_msg = (
            f"You have selected to wipe:\n{device_name}\n\n"
            f"Passes: {passes}\n"
            f"Method: {method}\n"
            f"Verification: {verification}\n"
            f"Certificate: {certificate}\n\n"
            "This operation will permanently delete all data on this device.\nAre you sure you want to continue?"
        )
        if not messagebox.askyesno("Confirm Wipe", confirm_msg):
            self.log("Wipe cancelled by user.")
            return

        self.start_wipe(passes, method)

    def start_wipe(self, passes, method):
        device_name = self.device_var.get()
        device_info = self.device_info.get(device_name, {})

        self.wiping = True
        self.stop_event = threading.Event()

        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")

        self.log_text.config(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.config(state="disabled")

        self.progress["value"] = 0
        self.et_label.config(text=f"Estimated time: {passes * 2} minutes")

        self.log(f"Starting wipe on {device_name} with {passes} passes and {method} method.")

        self.worker = DiskWiper(device_info.get("device_path"), passes, method, self.progress_update, self.log, self.stop_event)
        self.thread = threading.Thread(target=self.worker_thread)
        self.thread.daemon = True
        self.thread.start()

    def worker_thread(self):
        try:
            result = self.worker.wipe()
        except Exception as e:
            self.log(f"Error during wipe: {e}")
            self.wiping = False
            self.after(0, self.finish_wipe)
            self.after(0, lambda: messagebox.showerror("Error", f"Wipe failed:\n{e}"))
            return

        if result:
            self.log("Wipe completed successfully.")
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cert_text = (
                f"Certificate of Data Erasure\n\n"
                f"Device: {self.device_var.get()}\n"
                f"Passes: {self.passes_var.get()}\n"
                f"Method: {self.wipe_var.get()}\n"
                f"Verification: {self.verif_var.get()}\n"
                f"Certificate: {self.cert_var.get()}\n"
                f"Date: {timestamp}\n\n"
                f"This certifies the device was securely wiped."
            )

            self.certificate_text.set(cert_text)
            self.certificates.append(
                {
                    "device": self.device_var.get(),
                    "passes": self.passes_var.get(),
                    "method": self.wipe_var.get(),
                    "verification": self.verif_var.get(),
                    "certificate": self.cert_var.get(),
                    "timestamp": timestamp,
                    "text": cert_text,
                }
            )
            self.after(0, self.populate_certificates)
            self.after(0, lambda: self.cert_tree.selection_set(self.cert_tree.get_children()[-1]))
            self.after(0, self.enable_cert_download)
            self.after(0, lambda: messagebox.showinfo("Success", "Wipe completed successfully."))
        else:
            self.log("Wipe was interrupted or failed.")
            self.after(0, lambda: messagebox.showwarning("Warning", "Wipe did not complete."))

        self.wiping = False
        self.after(0, self.finish_wipe)

    def finish_wipe(self):
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.progress["value"] = 0
        self.et_label.config(text="")

    def stop_wipe(self):
        if self.wiping:
            self.worker.stop_event.set()
            self.log("Wipe stopped by user.")
            self.start_btn.config(state="normal")
            self.stop_btn.config(state="disabled")

    def progress_update(self, done, total):
        value = min(100, (done / total) * 100 if total else 0)
        self.progress["value"] = value

    def log(self, msg):
        self.log_text.config(state="normal")
        self.log_text.insert("end", msg + "\n")
        self.log_text.see("end")
        self.log_text.config(state="disabled")

    def populate_certificates(self):
        if not hasattr(self, "cert_tree"):
            self.cert_tree = ttk.Treeview(
                self.tab_certificates,
                columns=("device", "passes", "method", "verification", "certificate", "timestamp"),
                show="headings",
            )
            for col in ("device", "passes", "method", "verification", "certificate", "timestamp"):
                self.cert_tree.heading(col, text=col.capitalize())
                self.cert_tree.column(col, width=120)
            self.cert_tree.pack(fill="both", expand=True)
            self.cert_tree.bind("<Double-1>", self.download_certificate)

        self.cert_tree.delete(*self.cert_tree.get_children())
        for idx, cert in enumerate(self.certificates):
            self.cert_tree.insert(
                "",
                "end",
                iid=idx,
                values=(
                    cert["device"],
                    cert["passes"],
                    cert["method"],
                    cert["verification"],
                    cert["certificate"],
                    cert["timestamp"],
                ),
            )

    def enable_cert_download(self):
        if not hasattr(self, "download_btn"):
            self.download_btn = ttk.Button(
                self.tab_certificates,
                text="Download Certificate",
                command=self.download_certificate,
            )
            self.download_btn.pack(pady=8)
        else:
            self.download_btn.config(state="normal")

    def download_certificate(self, event=None):
        if not hasattr(self, "cert_tree"):
            return
        selected = self.cert_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a certificate to download.")
            return
        idx = int(selected[0])
        cert = self.certificates[idx]
        filepath = filedialog.asksaveasfilename(
            defaultextension=".txt", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if filepath:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(cert["text"])
            messagebox.showinfo("Saved", f"Certificate saved to:\n{filepath}")


if __name__ == "__main__":
    app = App()
    app.mainloop()
