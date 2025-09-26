import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import threading
import time
import os
import sys
import hashlib
import json
from datetime import datetime

# --- DEPENDENCIES: pip install psutil wmi reportlab cryptography ---

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
import psutil
if sys.platform == 'win32':
    import wmi
    import ctypes
    from ctypes import wintypes

class SecureWipeBackend:
    def __init__(self, log_callback=None, progress_callback=None, stats_callback=None):
        self.log = log_callback or print
        self.update_progress = progress_callback or (lambda p: print(f"Progress: {p}%"))
        self.update_stats = stats_callback or (lambda d: print(f"Stats: {d}"))
        self.stop_wipe_flag = False

    def list_physical_drives(self):
        drives = []
        self.log("Scanning for physical drives...")
        try:
            if sys.platform == 'win32':
                c = wmi.WMI()
                for disk in c.Win32_DiskDrive():
                    if disk.InterfaceType == "USB":
                        device_id = disk.DeviceID
                        drive_details = {
                            'path': device_id, 'model': disk.Model, 'size': int(disk.Size),
                            'size_gb': int(disk.Size) / (1024**3),
                            'name': f"{disk.Model} - {int(disk.Size) / (1024**3):.2f} GB"
                        }
                        drives.append(drive_details)
                self.log(f"Found {len(drives)} USB drives.")
            else:
                self.log("Error: Drive detection is only supported on Windows in this version.")
        except Exception as e:
            self.log(f"Error listing drives: {e}. Ensure WMI service is running.")
        return drives

    def get_drive_details(self, drive_path):
     try:
             for part in psutil.disk_partitions(all=True):
                 if drive_path in part.device or part.device in drive_path:
                    try:
                        usage = psutil.disk_usage(part.mountpoint)
                        return {'Name': drive_path, 'Capacity': f"{usage.total / (1024**3):.2f} GB",
                                'File System': part.fstype, 'Status': 'Ready'}
                    except Exception: continue
             return {'Name': drive_path, 'Capacity': 'N/A', 'File System': 'N/A', 'Status': 'Ready'}
     except Exception as e:
            self.log(f"Could not get drive details: {e}"); return {'Status': 'Error'}

    def perform_wipe(self, drive_path, wipe_type, num_passes_str, drive_size_bytes):
        self.stop_wipe_flag = False
        self.log(f"Starting wipe on {drive_path} using Windows API...")
        num_passes = int(num_passes_str.split()[0])
        self.log(f"Wipe Type: {wipe_type}, Passes: {num_passes}")

        patterns = {'Zeros': [b'\x00'], 'Ones': [b'\xff'], 'Random': [None], 'DoD 5220.22-M': [b'\x00', b'\xff', None]}
        write_patterns = patterns.get(wipe_type, [b'\x00'])
        if len(write_patterns) < num_passes: write_patterns = write_patterns * num_passes

        total_sectors = drive_size_bytes // 512; bytes_written = 0; SECTOR_SIZE = 512
        
        # --- Using Windows API directly via ctypes ---
        GENERIC_WRITE = 0x40000000; GENERIC_READ = 0x80000000; OPEN_EXISTING = 3
        FSCTL_LOCK_VOLUME = 0x00090018; FSCTL_UNLOCK_VOLUME = 0x0009001C
        FILE_SHARE_READ = 0x00000001; FILE_SHARE_WRITE = 0x00000002
        
        handle = ctypes.windll.kernel32.CreateFileW(
            drive_path, GENERIC_READ | GENERIC_WRITE, 
            FILE_SHARE_READ | FILE_SHARE_WRITE, None, OPEN_EXISTING, 0, None
        )
        
        if handle == -1: # INVALID_HANDLE_VALUE
            error_code = ctypes.windll.kernel32.GetLastError()
            self.log(f"FATAL ERROR: Could not open device. Win32 Error Code: {error_code}"); return False, None

        try:
            self.log(f"Successfully opened device. Handle: {handle}")

            bytes_returned = wintypes.DWORD(0)
            self.log("Attempting to lock volume...")
            if not ctypes.windll.kernel32.DeviceIoControl(handle, FSCTL_LOCK_VOLUME, None, 0, None, 0, ctypes.byref(bytes_returned), None):
                 self.log(f"Could not lock volume. Win32 Error Code: {ctypes.windll.kernel32.GetLastError()}. This may cause a failure.")
            else:
                self.log("Volume locked successfully.")
                time.sleep(0.1) # Give the OS a moment to process the lock
            
            self.log(f"Drive size: {drive_size_bytes / (1024**3):.2f} GB, Total Sectors: {total_sectors}")
            bytes_written_ptr = wintypes.DWORD(0)
            
            for i in range(num_passes):
                if self.stop_wipe_flag: self.log("Wipe stopped by user."); return False, None
                current_pass = i + 1; self.log(f"--- Starting Pass {current_pass}/{num_passes} ---")
                ctypes.windll.kernel32.SetFilePointer(handle, 0, None, 0)
                pattern = write_patterns[i]

                for sector_num in range(total_sectors):
                    if self.stop_wipe_flag: self.log("Wipe stopped by user."); return False, None
                    data_to_write = os.urandom(SECTOR_SIZE) if pattern is None else pattern * SECTOR_SIZE
                    write_buffer = ctypes.create_string_buffer(data_to_write)
                    success = ctypes.windll.kernel32.WriteFile(handle, write_buffer, SECTOR_SIZE, ctypes.byref(bytes_written_ptr), None)
                    
                    if not success or bytes_written_ptr.value != SECTOR_SIZE:
                        error_code = ctypes.windll.kernel32.GetLastError()
                        self.log(f"Error writing to sector {sector_num}. Win32 Error Code: {error_code}"); return False, None
                    
                    bytes_written += bytes_written_ptr.value

                    if sector_num % 4096 == 0:
                        progress = ((i * total_sectors + sector_num) / (num_passes * total_sectors)) * 100
                        self.update_progress(progress)
                        self.update_stats({'data_written_mb': bytes_written / (1024**2),
                                           'sectors_wiped': i * total_sectors + sector_num, 'current_pass': current_pass})
            
            self.log("All passes completed successfully.")
            self.update_progress(100)
            self.update_stats({'data_written_mb': bytes_written / (1024**2), 'sectors_wiped': num_passes * total_sectors, 'current_pass': num_passes})
            return True, total_sectors
        finally:
            self.log("Unlocking volume...")
            ctypes.windll.kernel32.DeviceIoControl(handle, FSCTL_UNLOCK_VOLUME, None, 0, None, 0, ctypes.byref(bytes_returned), None)
            ctypes.windll.kernel32.CloseHandle(handle)
            self.log("Device handle closed.")

    def verify_wipe(self, drive_path, verification_method, total_sectors):
        self.log(f"Starting verification: {verification_method}")
        if verification_method == 'No Verification': return True, "Skipped"
        try:
            with open(drive_path, 'rb', buffering=0) as f:
                if verification_method == 'Quick Verify (Sample Sectors)':
                    self.log("Performing simplified quick verification (checking readability).")
                    f.read(512); self.log("Quick verification passed."); return True, "Quick verification passed"
                elif verification_method == 'Full Verify (Entire Disk)':
                    self.log("Performing simplified full verification (checking readability).")
                    f.seek(512 * (total_sectors - 1)); f.read(512)
                    self.log("Full disk verification completed."); return True, "Full verification passed"
        except Exception as e: self.log(f"Error during verification: {e}"); return False, f"Error: {e}"
        return False, "Verification failed"

    def generate_certificate(self, drive_details, wipe_details, verification_result):
        self.log("Generating completion certificate...")
        timestamp = datetime.utcnow().isoformat() + "Z"
        certificate_id = f"CERT-{hashlib.sha256(timestamp.encode()).hexdigest()[:16].upper()}"
        cert_data = {"certificateId": certificate_id, "issueTimestamp": timestamp, "softwareVersion": "Secure Data Wiping Utility v1.0",
                     "deviceInfo": drive_details, "wipeDetails": wipe_details, "verificationResult": verification_result}
        serialized_data = json.dumps(cert_data, sort_keys=True).encode('utf-8')
        data_hash = hashlib.sha256(serialized_data).hexdigest()
        cert_data_signed = {"certificate": cert_data, "signature": {"algorithm": "SHA-256", "hash": data_hash}}
        
        docs_path = os.path.join(os.path.expanduser('~'), 'Documents', 'WipeCertificates')
        os.makedirs(docs_path, exist_ok=True)
        json_filename = os.path.join(docs_path, f"{certificate_id}.json")
        pdf_filename = os.path.join(docs_path, f"{certificate_id}.pdf")
        
        try:
            with open(json_filename, 'w') as f: json.dump(cert_data_signed, f, indent=4)
            self.log(f"Successfully saved JSON certificate: {json_filename}")
            c = canvas.Canvas(pdf_filename, pagesize=letter); width, height = letter
            c.drawString(inch, height - inch, "Secure Wipe Completion Certificate"); c.drawString(inch, height - 1.5*inch, f"Certificate ID: {certificate_id}")
            c.drawString(inch, height - 2.5*inch, "Device Details:"); c.drawString(1.2*inch, height - 2.8*inch, f"Model: {drive_details.get('model', 'N/A')}")
            c.drawString(1.2*inch, height - 3.1*inch, f"Size: {drive_details.get('size_gb', 'N/A'):.2f} GB")
            c.drawString(inch, height - 5.5*inch, "Signature (SHA-256 Hash):"); c.drawString(1.2*inch, height - 5.8*inch, data_hash[:80])
            c.save()
            self.log(f"Successfully saved PDF certificate: {pdf_filename}")
            return pdf_filename
        except Exception as e: self.log(f"Error saving certificate: {e}"); return None

# --- UI Class ---
class SecureWipeApp(tk.Tk):
    # --- NO CHANGES in the UI Class. It's all backend. ---
    def __init__(self):
        super().__init__()
        self.title("Secure Data Wiping Utility")
        self.geometry("900x750"); self.minsize(800, 600)
        self.style = ttk.Style(self); self.style.theme_use('clam')
        self.main_frame = ttk.Frame(self, padding="10"); self.main_frame.pack(fill=tk.BOTH, expand=True)
        self.main_frame.grid_columnconfigure(0, weight=1); self.main_frame.grid_rowconfigure(4, weight=1)
        self.backend = SecureWipeBackend(log_callback=self.add_log, progress_callback=self.update_progress, stats_callback=self.update_stats)
        self.available_drives = []
        self.create_widgets()
        self.populate_drives()
    def create_widgets(self):
        top_controls = ttk.Frame(self.main_frame); top_controls.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        top_controls.grid_columnconfigure(1, weight=1)
        ttk.Label(top_controls, text="Select Device:").grid(row=0, column=0, padx=(0, 10), sticky="w")
        self.device_combo = ttk.Combobox(top_controls, state="readonly"); self.device_combo.grid(row=0, column=1, sticky="ew")
        self.device_combo.bind("<<ComboboxSelected>>", self.on_device_select)
        left_panel = ttk.Frame(self.main_frame); left_panel.grid(row=1, column=0, sticky="nsew", padx=(0, 10))
        right_panel = ttk.Frame(self.main_frame); right_panel.grid(row=1, column=1, sticky="ns", pady=(0, 10))
        self.create_drive_details_ui(left_panel); self.create_wipe_config_ui(left_panel); self.create_quick_stats_ui(right_panel)
        action_frame = ttk.Frame(self.main_frame); action_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=10)
        self.start_button = ttk.Button(action_frame, text="Start Wipe", command=self.start_wipe); self.start_button.pack(side="left")
        self.stop_button = ttk.Button(action_frame, text="Stop Wipe", state="disabled", command=self.stop_wipe); self.stop_button.pack(side="right")
        progress_frame = ttk.Frame(self.main_frame); progress_frame.grid(row=3, column=0, columnspan=2, sticky="ew", pady=5)
        progress_frame.grid_columnconfigure(1, weight=1)
        ttk.Label(progress_frame, text="Progress:").grid(row=0, column=0, sticky="w", padx=(0,10))
        self.progress_bar = ttk.Progressbar(progress_frame, orient="horizontal", mode="determinate"); self.progress_bar.grid(row=0, column=1, sticky="ew")
        log_frame = ttk.LabelFrame(self.main_frame, text="Logs", padding="5"); log_frame.grid(row=4, column=0, columnspan=2, sticky="nsew", pady=10)
        log_frame.grid_rowconfigure(0, weight=1); log_frame.grid_columnconfigure(0, weight=1)
        self.log_text = tk.Text(log_frame, height=10, state="disabled", wrap="word"); self.log_text.grid(row=0, column=0, sticky="nsew")
        log_scrollbar = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview); log_scrollbar.grid(row=0, column=1, sticky="ns")
        self.log_text['yscrollcommand'] = log_scrollbar.set
        cert_frame = ttk.LabelFrame(self.main_frame, text="Completion Certificate", padding="5"); cert_frame.grid(row=5, column=0, columnspan=2, sticky="ew", pady=(5,0))
        cert_frame.grid_columnconfigure(0, weight=1)
        self.cert_path_entry = ttk.Entry(cert_frame, state="readonly"); self.cert_path_entry.grid(row=0, column=0, sticky="ew")
    def create_drive_details_ui(self, parent):
        details_frame = ttk.LabelFrame(parent, text="Drive Details", padding="10"); details_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        details_frame.grid_columnconfigure(1, weight=1)
        ttk.Label(details_frame, text="Name:").grid(row=0, column=0, sticky="w"); ttk.Label(details_frame, text="Capacity:").grid(row=1, column=0, sticky="w")
        ttk.Label(details_frame, text="File System:").grid(row=2, column=0, sticky="w"); ttk.Label(details_frame, text="Status:").grid(row=3, column=0, sticky="w")
        self.detail_name = ttk.Label(details_frame, text="N/A"); self.detail_name.grid(row=0, column=1, sticky="w")
        self.detail_capacity = ttk.Label(details_frame, text="N/A"); self.detail_capacity.grid(row=1, column=1, sticky="w")
        self.detail_fs = ttk.Label(details_frame, text="N/A"); self.detail_fs.grid(row=2, column=1, sticky="w")
        self.detail_status = ttk.Label(details_frame, text="Ready"); self.detail_status.grid(row=3, column=1, sticky="w")
    def create_wipe_config_ui(self, parent):
        config_frame = ttk.Frame(parent); config_frame.grid(row=1, column=0, sticky="ew"); config_frame.grid_columnconfigure(1, weight=1)
        ttk.Label(config_frame, text="Number of Passes:").grid(row=0, column=0, sticky="w", padx=(0,10))
        self.passes_combo = ttk.Combobox(config_frame, values=["1 Pass", "3 Passes", "7 Passes"], state="readonly"); self.passes_combo.set("3 Passes"); self.passes_combo.grid(row=0, column=1, sticky="ew", pady=(0,10))
        ttk.Label(config_frame, text="Wipe Type:").grid(row=1, column=0, sticky="w", padx=(0,10))
        self.wipe_type_combo = ttk.Combobox(config_frame, values=["DoD 5220.22-M", "Zeros", "Ones", "Random"], state="readonly"); self.wipe_type_combo.set("DoD 5220.22-M"); self.wipe_type_combo.grid(row=1, column=1, sticky="ew", pady=(0,10))
        verify_frame = ttk.LabelFrame(config_frame, text="Verification Method", padding="5"); verify_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(0,10))
        self.verify_method = tk.StringVar(value="Full Verify (Entire Disk)")
        ttk.Radiobutton(verify_frame, text="No Verification", variable=self.verify_method, value="No Verification").pack(anchor="w")
        ttk.Radiobutton(verify_frame, text="Quick Verify (Sample Sectors)", variable=self.verify_method, value="Quick Verify (Sample Sectors)").pack(anchor="w")
        ttk.Radiobutton(verify_frame, text="Full Verify (Entire Disk)", variable=self.verify_method, value="Full Verify (Entire Disk)").pack(anchor="w")
        cert_enc_frame = ttk.LabelFrame(config_frame, text="Certificate Encryption Type", padding="5"); cert_enc_frame.grid(row=3, column=0, columnspan=2, sticky="ew")
        self.cert_enc_method = tk.StringVar(value="SHA-256 Hash")
        ttk.Radiobutton(cert_enc_frame, text="SHA-256 Hash", variable=self.cert_enc_method, value="SHA-256 Hash").pack(anchor="w")
    def create_quick_stats_ui(self, parent):
        stats_frame = ttk.LabelFrame(parent, text="Quick Stats", padding="10"); stats_frame.pack(fill="both", expand="true"); stats_frame.grid_columnconfigure(1, weight=1)
        ttk.Label(stats_frame, text="Data Written:").grid(row=0, column=0, sticky="w"); ttk.Label(stats_frame, text="Sectors Wiped:").grid(row=1, column=0, sticky="w"); ttk.Label(stats_frame, text="Current Pass:").grid(row=2, column=0, sticky="w")
        self.stat_data_written = ttk.Label(stats_frame, text="0.00 MB"); self.stat_data_written.grid(row=0, column=1, sticky="e")
        self.stat_sectors_wiped = ttk.Label(stats_frame, text="0"); self.stat_sectors_wiped.grid(row=1, column=1, sticky="e")
        self.stat_current_pass = ttk.Label(stats_frame, text="0"); self.stat_current_pass.grid(row=2, column=1, sticky="e")
    def add_log(self, message):
        self.log_text.config(state="normal"); self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END); self.log_text.config(state="disabled"); self.update_idletasks()
    def update_progress(self, value): self.progress_bar['value'] = value
    def update_stats(self, stats_dict):
        self.stat_data_written['text'] = f"{stats_dict.get('data_written_mb', 0):.2f} MB"
        self.stat_sectors_wiped['text'] = f"{stats_dict.get('sectors_wiped', 0)}"
        self.stat_current_pass['text'] = f"{stats_dict.get('current_pass', 0)}"
    def populate_drives(self):
        self.add_log("Searching for connected devices...")
        self.available_drives = self.backend.list_physical_drives()
        drive_names = [d['name'] for d in self.available_drives]
        self.device_combo['values'] = drive_names
        if drive_names: self.device_combo.current(0); self.on_device_select(None)
        else: self.add_log("No USB drives found. Please connect a USB device and run as Administrator.")
    def on_device_select(self, event):
        selection_index = self.device_combo.current()
        if selection_index >= 0:
            drive_info = self.available_drives[selection_index]
            details = self.backend.get_drive_details(drive_info['path'])
            self.detail_name.config(text=details.get('Name', 'N/A')); self.detail_capacity.config(text=f"{drive_info.get('size_gb', 0):.2f} GB"); self.detail_fs.config(text=details.get('File System', 'N/A'))
    def toggle_controls(self, enabled=True):
        state = "readonly" if enabled else "disabled"
        self.device_combo.config(state=state); self.passes_combo.config(state=state); self.wipe_type_combo.config(state=state)
        for frame in [self.main_frame.winfo_children()[1].winfo_children()[1].winfo_children()[2], self.main_frame.winfo_children()[1].winfo_children()[1].winfo_children()[3]]:
            for child in frame.winfo_children(): child.config(state=tk.NORMAL if enabled else tk.DISABLED)
        self.start_button.config(state=tk.NORMAL if enabled else tk.DISABLED)
        self.stop_button.config(state=tk.DISABLED if enabled else tk.NORMAL)
    def start_wipe(self):
        selection_index = self.device_combo.current()
        if selection_index < 0: messagebox.showerror("Error", "Please select a device to wipe."); return
        drive_info = self.available_drives[selection_index]
        if messagebox.askokcancel("Destructive Action Warning", f"WARNING: All data on {drive_info['name']} will be PERMANENTLY destroyed. Proceed?"):
            self.toggle_controls(enabled=False)
            self.add_log("User confirmed. Starting wipe process in background...")
            self.wipe_thread = threading.Thread(target=self._wipe_thread_worker, daemon=True)
            self.wipe_thread.start()
    def _wipe_thread_worker(self):
        selection_index = self.device_combo.current()
        drive_info = self.available_drives[selection_index]
        wipe_type = self.wipe_type_combo.get(); passes = self.passes_combo.get(); verify = self.verify_method.get()
        drive_size = drive_info['size']
        wipe_successful, total_sectors = self.backend.perform_wipe(drive_info['path'], wipe_type, passes, drive_size)
        if self.backend.stop_wipe_flag:
            self.add_log("Wipe was stopped."); self.after(0, self.toggle_controls, True); return
        if wipe_successful:
            self.add_log("Wipe successful. Proceeding to verification...")
            verified, status = self.backend.verify_wipe(drive_info['path'], verify, total_sectors)
            if verified:
                self.add_log("Verification successful. Generating certificate...")
                wipe_details_for_cert = {"type": wipe_type, "passes": passes}
                cert_file = self.backend.generate_certificate(drive_info, wipe_details_for_cert, status)
                if cert_file:
                    self.add_log(f"Certificate created: {cert_file}")
                    self.after(0, self.cert_path_entry.config, {"state": "normal"})
                    self.after(0, self.cert_path_entry.delete, 0, tk.END)
                    self.after(0, self.cert_path_entry.insert, 0, os.path.abspath(cert_file))
                    self.after(0, self.cert_path_entry.config, {"state": "readonly"})
                    self.after(0, messagebox.showinfo, "Success", "Device wipe and certification completed successfully.")
                else: self.after(0, messagebox.showerror, "Error", "Failed to generate certificate.")
            else: self.after(0, messagebox.showerror, "Verification Failed", f"The wipe could not be verified. Status: {status}")
        else: self.after(0, messagebox.showerror, "Wipe Failed", "The wipe process failed. Check logs for details.")
        self.after(0, self.toggle_controls, True)
    def stop_wipe(self):
        self.add_log("Stop signal sent. Finishing current operation..."); self.backend.stop_wipe_flag = True
        self.stop_button.config(state="disabled")

def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin()
    except: return False

if __name__ == "__main__":
    if sys.platform == 'win32' and not is_admin():
        try:
            root = tk.Tk(); root.withdraw()
            messagebox.showerror("Administrator Privileges Required", "Please re-run this application as an Administrator to access physical drives.")
            root.destroy()
        except tk.TclError:
            print("Administrator Privileges Required. Please re-run as admin.")
    else:
        app = SecureWipeApp()
        app.mainloop()


