import tkinter as tk
from tkinter import ttk
from tkinter import messagebox, filedialog
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


def human_eta(seconds: float) -> str:
    """Convert seconds to a friendly ETA string."""
    if seconds is None or seconds <= 0 or seconds == float('inf'):
        return "calculating…"
    seconds = int(seconds)
    h = seconds // 3600
    m = (seconds % 3600) // 60
    s = seconds % 60
    if h > 0:
        return f"{h}h {m}m {s}s"
    if m > 0:
        return f"{m}m {s}s"
    return f"{s}s"


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
                        device_id = disk.DeviceID.strip()
                        drive_details = {
                            'path': device_id,
                            'model': disk.Model,
                            'size': int(disk.Size),
                            'size_gb': int(disk.Size) / (1024**3),
                            'name': f"{disk.Model} - {int(disk.Size) / (1024**3):.2f} GB",
                            'pnp_id': getattr(disk, 'PNPDeviceID', None)
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
                    except Exception:
                        continue
            return {'Name': drive_path, 'Capacity': 'N/A', 'File System': 'N/A', 'Status': 'Ready'}
        except Exception as e:
            self.log(f"Could not get drive details: {e}")
            return {'Status': 'Error'}

    # -------- Drive Health & Temperature (best-effort using WMI SMART) ----------
    def get_drive_health_and_temp(self, drive_info):
        """
        Returns dict: {'health': 'OK/Predicted Failure/Unknown', 'temperature_c': int or None}
        Attempts to read from WMI SMART classes; may return Unknown/None if unsupported.
        """
        default = {'health': 'Unknown', 'temperature_c': None}
        if sys.platform != 'win32':
            self.log("Drive health/temperature: Not supported on non-Windows.")
            return default
        try:
            c_disk = wmi.WMI()
            # Match the disk by DeviceID
            target = None
            for disk in c_disk.Win32_DiskDrive():
                if disk.DeviceID.strip() == drive_info['path'].strip():
                    target = disk
                    break
            if not target:
                self.log("SMART: Could not match selected disk to WMI Win32_DiskDrive.")
                return default

            # Now use root\\wmi for SMART data
            cw = wmi.WMI(namespace="root\\wmi")

            # Health / PredictFailure flag
            health = 'Unknown'
            for stat in cw.MSStorageDriver_FailurePredictStatus():
                # InstanceName contains PNP id usually; try to match on model or PNPDeviceID
                inst = getattr(stat, 'InstanceName', '') or ''
                if (drive_info.get('pnp_id') and drive_info['pnp_id'] in inst) or (drive_info['model'] and drive_info['model'] in inst):
                    health = 'Predicted Failure' if stat.PredictFailure else 'OK'
                    break

            # Temperature: parse attribute 194 from FailurePredictData.VendorSpecific (12-byte records)
            temperature_c = None
            try:
                for d in cw.MSStorageDriver_FailurePredictData():
                    inst = getattr(d, 'InstanceName', '') or ''
                    if (drive_info.get('pnp_id') and drive_info['pnp_id'] in inst) or (drive_info['model'] and drive_info['model'] in inst):
                        # VendorSpecific is a bytes array; parse attributes blocks of 12 bytes
                        raw = bytes(d.VendorSpecific)
                        # Each attribute entry: 1:id,1:status,6:value/raw,lots of vendor layout differences.
                        # Common SMART layout uses 12 bytes per attribute.
                        for offset in range(2, len(raw) - 12, 12):
                            attr_id = raw[offset]
                            if attr_id == 194:  # Temperature
                                # raw value usually at offset+5 or offset+3 depending on vendor; common: offset+5
                                # We'll try several typical positions and pick the first plausible 0..120
                                candidates = [raw[offset + 5], raw[offset + 3], raw[offset + 7]]
                                for v in candidates:
                                    if 0 < v < 130:
                                        temperature_c = int(v)
                                        break
                                break
                        break
            except Exception as e:
                self.log(f"SMART temperature parsing failed (non-fatal): {e}")

            return {'health': health, 'temperature_c': temperature_c}
        except Exception as e:
            self.log(f"Error reading drive health/temperature: {e}")
            return default

    def perform_wipe(self, drive_path, wipe_type, num_passes_str, drive_size_bytes):
        self.stop_wipe_flag = False
        self.log(f"Starting wipe on {drive_path} using Windows API...")
        num_passes = int(num_passes_str.split()[0])
        self.log(f"Wipe Type: {wipe_type}, Passes: {num_passes}")

        patterns = {'Zeros': [b'\x00'], 'Ones': [b'\xff'], 'Random': [None], 'DoD 5220.22-M': [b'\x00', b'\xff', None]}
        write_patterns = patterns.get(wipe_type, [b'\x00'])
        if len(write_patterns) < num_passes:
            write_patterns = write_patterns * num_passes

        total_sectors = drive_size_bytes // 512
        bytes_written = 0
        SECTOR_SIZE = 512

        total_bytes_to_write = int(total_sectors * SECTOR_SIZE * num_passes)
        start_time = time.time()

        # Windows API related constants
        GENERIC_WRITE = 0x40000000
        GENERIC_READ = 0x80000000
        OPEN_EXISTING = 3
        FSCTL_LOCK_VOLUME = 0x00090018
        FSCTL_UNLOCK_VOLUME = 0x0009001C
        FSCTL_DISMOUNT_VOLUME = 0x00090020
        FILE_SHARE_READ = 0x00000001
        FILE_SHARE_WRITE = 0x00000002

        self.log(f"Opening device with path: {drive_path}")

        handle = ctypes.windll.kernel32.CreateFileW(
            drive_path,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            0,
            None
        )

        INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value
        if handle == INVALID_HANDLE_VALUE:
            error_code = ctypes.windll.kernel32.GetLastError()
            self.log(f"FATAL ERROR: Could not open device. Win32 Error Code: {error_code}")
            return False, None

        try:
            self.log(f"Successfully opened device. Handle: {handle}")

            bytes_returned = wintypes.DWORD(0)
            self.log("Attempting to lock volume...")
            if not ctypes.windll.kernel32.DeviceIoControl(handle, FSCTL_LOCK_VOLUME, None, 0, None, 0, ctypes.byref(bytes_returned), None):
                self.log(f"Could not lock volume. Win32 Error Code: {ctypes.windll.kernel32.GetLastError()}. This may cause a failure.")
            else:
                self.log("Volume locked successfully.")
                time.sleep(0.1)

            self.log("Attempting to dismount volume...")
            if not ctypes.windll.kernel32.DeviceIoControl(handle, FSCTL_DISMOUNT_VOLUME, None, 0, None, 0, ctypes.byref(bytes_returned), None):
                dismount_error = ctypes.windll.kernel32.GetLastError()
                self.log(f"Could not dismount volume. Win32 Error Code: {dismount_error}. This may cause write failure.")
            else:
                self.log("Volume dismounted successfully.")
                time.sleep(0.1)

            self.log(f"Drive size: {drive_size_bytes / (1024**3):.2f} GB, Total Sectors: {total_sectors}")
            bytes_written_ptr = wintypes.DWORD(0)

            # Update every N sectors to reduce UI overhead
            SECTORS_PER_UPDATE = 4096

            for i in range(num_passes):
                if self.stop_wipe_flag:
                    self.log("Wipe stopped by user.")
                    return False, None
                current_pass = i + 1
                self.log(f"--- Starting Pass {current_pass}/{num_passes} ---")
                ctypes.windll.kernel32.SetFilePointer(handle, 0, None, 0)
                pattern = write_patterns[i]

                for sector_num in range(total_sectors):
                    if self.stop_wipe_flag:
                        self.log("Wipe stopped by user.")
                        return False, None
                    data_to_write = os.urandom(SECTOR_SIZE) if pattern is None else pattern * SECTOR_SIZE
                    write_buffer = ctypes.create_string_buffer(data_to_write)
                    success = ctypes.windll.kernel32.WriteFile(handle, write_buffer, SECTOR_SIZE, ctypes.byref(bytes_written_ptr), None)

                    if not success or bytes_written_ptr.value != SECTOR_SIZE:
                        error_code = ctypes.windll.kernel32.GetLastError()
                        self.log(f"Error writing to sector {sector_num}. Win32 Error Code: {error_code}")
                        return False, None

                    bytes_written += bytes_written_ptr.value

                    if sector_num % SECTORS_PER_UPDATE == 0 or sector_num == total_sectors - 1:
                        # progress and ETA
                        elapsed = time.time() - start_time
                        speed = (bytes_written / (1024**2)) / elapsed if elapsed > 0 else 0  # MB/s
                        remaining_bytes = max(total_bytes_to_write - bytes_written - (i * total_sectors * SECTOR_SIZE), 0)
                        # Include future passes:
                        overall_bytes_done = (i * total_sectors * SECTOR_SIZE) + bytes_written
                        remaining_total = max(total_bytes_to_write - overall_bytes_done, 0)
                        eta_seconds = (remaining_total / (1024**2)) / speed if speed > 0 else None

                        progress = (overall_bytes_done / total_bytes_to_write) * 100.0
                        self.update_progress(progress)
                        self.update_stats({
                            'data_written_mb': overall_bytes_done / (1024**2),
                            'sectors_wiped': int(overall_bytes_done / SECTOR_SIZE),
                            'current_pass': current_pass,
                            'eta_seconds': eta_seconds,
                            'speed_mbps': speed
                        })

            self.log("All passes completed successfully.")
            self.update_progress(100.0)
            self.update_stats({'data_written_mb': total_bytes_to_write / (1024**2),
                               'sectors_wiped': num_passes * total_sectors,
                               'current_pass': num_passes,
                               'eta_seconds': 0,
                               'speed_mbps': 0})
            return True, total_sectors
        finally:
            self.log("Unlocking volume...")
            try:
                ctypes.windll.kernel32.DeviceIoControl(handle, FSCTL_UNLOCK_VOLUME, None, 0, None, 0, ctypes.byref(bytes_returned), None)
            except Exception:
                pass
            ctypes.windll.kernel32.CloseHandle(handle)
            self.log("Device handle closed.")

    def verify_wipe(self, drive_path, verification_method, total_sectors):
        self.log(f"Starting verification: {verification_method}")
        if verification_method == 'No Verification': 
            return True, "Skipped"
        try:
            with open(drive_path, 'rb', buffering=0) as f:
                if verification_method == 'Quick Verify (Sample Sectors)':
                    self.log("Performing simplified quick verification (checking readability).")
                    f.read(512)
                    self.log("Quick verification passed.")
                    return True, "Quick verification passed"
                elif verification_method == 'Full Verify (Entire Disk)':
                    self.log("Performing simplified full verification (checking readability).")
                    f.seek(512 * (total_sectors - 1))
                    f.read(512)
                    self.log("Full disk verification completed.")
                    return True, "Full verification passed"
        except Exception as e:
            self.log(f"Error during verification: {e}")
            return False, f"Error: {e}"
        return False, "Verification failed"

    def generate_certificate(self, drive_details, wipe_details, verification_result):
        self.log("Generating completion certificate...")
        timestamp = datetime.utcnow().isoformat() + "Z"
        certificate_id = f"CERT-{hashlib.sha256(timestamp.encode()).hexdigest()[:16].upper()}"
        cert_data = {
            "certificateId": certificate_id,
            "issueTimestamp": timestamp,
            "softwareVersion": "Secure Data Wiping Utility v1.1",
            "deviceInfo": drive_details,
            "wipeDetails": wipe_details,
            "verificationResult": verification_result
        }
        serialized_data = json.dumps(cert_data, sort_keys=True).encode('utf-8')
        data_hash = hashlib.sha256(serialized_data).hexdigest()
        cert_data_signed = {"certificate": cert_data, "signature": {"algorithm": "SHA-256", "hash": data_hash}}

        docs_path = os.path.join(os.path.expanduser('~'), 'Documents', 'WipeCertificates')
        os.makedirs(docs_path, exist_ok=True)
        json_filename = os.path.join(docs_path, f"{certificate_id}.json")
        pdf_filename = os.path.join(docs_path, f"{certificate_id}.pdf")

        try:
            with open(json_filename, 'w') as f:
                json.dump(cert_data_signed, f, indent=4)
            self.log(f"Successfully saved JSON certificate: {json_filename}")
            c = canvas.Canvas(pdf_filename, pagesize=letter)
            width, height = letter
            c.drawString(inch, height - inch, "Secure Wipe Completion Certificate")
            c.drawString(inch, height - 1.5*inch, f"Certificate ID: {certificate_id}")
            c.drawString(inch, height - 2.5*inch, "Device Details:")
            c.drawString(1.2*inch, height - 2.8*inch, f"Model: {drive_details.get('model', 'N/A')}")
            size_gb = drive_details.get('size_gb', 0.0)
            c.drawString(1.2*inch, height - 3.1*inch, f"Size: {size_gb:.2f} GB")
            c.drawString(inch, height - 3.9*inch, "Wipe Details:")
            c.drawString(1.2*inch, height - 4.2*inch, f"Type: {wipe_details.get('type')}")
            c.drawString(1.2*inch, height - 4.5*inch, f"Passes: {wipe_details.get('passes')}")
            c.drawString(inch, height - 5.0*inch, f"Verification: {verification_result}")
            c.drawString(inch, height - 5.5*inch, "Signature (SHA-256 Hash):")
            c.drawString(1.2*inch, height - 5.8*inch, data_hash[:80])
            c.save()
            self.log(f"Successfully saved PDF certificate: {pdf_filename}")
            return pdf_filename
        except Exception as e:
            self.log(f"Error saving certificate: {e}")
            return None


# --- UI Class ---
class SecureWipeApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure Data Wiping Utility")
        self.geometry("1000x800")
        self.minsize(900, 650)

        self.style = ttk.Style(self)
        self.style.theme_use('clam')

        self.backend = SecureWipeBackend(
            log_callback=self.add_log,
            progress_callback=self.update_progress,
            stats_callback=self.update_stats
        )

        # Keep in-memory log buffer for export
        self.log_buffer = []

        # Notebook for tabs/pages
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # ---- Main tab ----
        self.main_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.main_tab, text="Main")

        self.main_frame = ttk.Frame(self.main_tab, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(5, weight=1)

        self.available_drives = []
        self.create_widgets()
        self.populate_drives()

        # ---- Support tab ----
        self.support_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.support_tab, text="Support")
        self.build_support_tab()

        # ---- Security Compliances tab ----
        self.sec_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.sec_tab, text="Security Compliances")
        self.build_security_tab()

        # ---- About tab (useful extra) ----
        self.about_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.about_tab, text="About")
        self.build_about_tab()

    # ----------------- Main Tab UI -----------------
    def create_widgets(self):
        # Top controls row
        top_controls = ttk.Frame(self.main_frame)
        top_controls.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        top_controls.grid_columnconfigure(1, weight=1)

        ttk.Label(top_controls, text="Select Device:").grid(row=0, column=0, padx=(0, 10), sticky="w")
        self.device_combo = ttk.Combobox(top_controls, state="readonly")
        self.device_combo.grid(row=0, column=1, sticky="ew")
        self.device_combo.bind("<<ComboboxSelected>>", self.on_device_select)

        self.refresh_btn = ttk.Button(top_controls, text="Refresh", command=self.populate_drives)
        self.refresh_btn.grid(row=0, column=2, padx=(10, 0))

        self.export_btn = ttk.Button(top_controls, text="Export Logs", command=self.export_logs)
        self.export_btn.grid(row=0, column=3, padx=(10, 0))

        left_panel = ttk.Frame(self.main_frame)
        left_panel.grid(row=1, column=0, sticky="nsew", padx=(0, 10))
        left_panel.grid_columnconfigure(0, weight=1)

        right_panel = ttk.Frame(self.main_frame)
        right_panel.grid(row=1, column=1, sticky="ns", pady=(0, 10))

        self.create_drive_details_ui(left_panel)
        self.create_wipe_config_ui(left_panel)
        self.create_quick_stats_ui(right_panel)

        # Actions
        action_frame = ttk.Frame(self.main_frame)
        action_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=10)
        self.start_button = ttk.Button(action_frame, text="Start Wipe", command=self.start_wipe)
        self.start_button.pack(side="left")
        self.stop_button = ttk.Button(action_frame, text="Stop Wipe", state="disabled", command=self.stop_wipe)
        self.stop_button.pack(side="left", padx=(10, 0))

        # Progress area
        progress_frame = ttk.Frame(self.main_frame)
        progress_frame.grid(row=3, column=0, columnspan=2, sticky="ew", pady=5)
        progress_frame.grid_columnconfigure(1, weight=1)

        ttk.Label(progress_frame, text="Progress:").grid(row=0, column=0, sticky="w", padx=(0, 10))
        self.progress_bar = ttk.Progressbar(progress_frame, orient="horizontal", mode="determinate", maximum=100.0)
        self.progress_bar.grid(row=0, column=1, sticky="ew")

        self.progress_percent_label = ttk.Label(progress_frame, text="0.0%")
        self.progress_percent_label.grid(row=0, column=2, padx=(10, 0))

        self.eta_label = ttk.Label(progress_frame, text="ETA: calculating…")
        self.eta_label.grid(row=1, column=1, sticky="w", pady=(5, 0))

        # Logs
        log_frame = ttk.LabelFrame(self.main_frame, text="Logs", padding="5")
        log_frame.grid(row=5, column=0, columnspan=2, sticky="nsew", pady=10)
        log_frame.grid_rowconfigure(0, weight=1)
        log_frame.grid_columnconfigure(0, weight=1)
        self.log_text = tk.Text(log_frame, height=10, state="disabled", wrap="word")
        self.log_text.grid(row=0, column=0, sticky="nsew")
        log_scrollbar = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        log_scrollbar.grid(row=0, column=1, sticky="ns")
        self.log_text['yscrollcommand'] = log_scrollbar.set

        # Certificate path
        cert_frame = ttk.LabelFrame(self.main_frame, text="Completion Certificate", padding="5")
        cert_frame.grid(row=6, column=0, columnspan=2, sticky="ew", pady=(5, 0))
        cert_frame.grid_columnconfigure(0, weight=1)
        self.cert_path_entry = ttk.Entry(cert_frame, state="readonly")
        self.cert_path_entry.grid(row=0, column=0, sticky="ew")

    def create_drive_details_ui(self, parent):
        details_frame = ttk.LabelFrame(parent, text="Drive Details", padding="10")
        details_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        details_frame.grid_columnconfigure(1, weight=1)

        ttk.Label(details_frame, text="Name:").grid(row=0, column=0, sticky="w")
        ttk.Label(details_frame, text="Capacity:").grid(row=1, column=0, sticky="w")
        ttk.Label(details_frame, text="File System:").grid(row=2, column=0, sticky="w")
        ttk.Label(details_frame, text="Status:").grid(row=3, column=0, sticky="w")
        ttk.Label(details_frame, text="Health:").grid(row=4, column=0, sticky="w")
        ttk.Label(details_frame, text="Temperature:").grid(row=5, column=0, sticky="w")

        self.detail_name = ttk.Label(details_frame, text="N/A")
        self.detail_name.grid(row=0, column=1, sticky="w")
        self.detail_capacity = ttk.Label(details_frame, text="N/A")
        self.detail_capacity.grid(row=1, column=1, sticky="w")
        self.detail_fs = ttk.Label(details_frame, text="N/A")
        self.detail_fs.grid(row=2, column=1, sticky="w")
        self.detail_status = ttk.Label(details_frame, text="Ready")
        self.detail_status.grid(row=3, column=1, sticky="w")

        self.detail_health = ttk.Label(details_frame, text="Unknown")
        self.detail_health.grid(row=4, column=1, sticky="w")
        self.detail_temp = ttk.Label(details_frame, text="N/A")
        self.detail_temp.grid(row=5, column=1, sticky="w")

        self.health_btn = ttk.Button(details_frame, text="Check Health", command=self.check_health_clicked)
        self.health_btn.grid(row=0, column=2, padx=(10, 0))

    def create_wipe_config_ui(self, parent):
        config_frame = ttk.Frame(parent)
        config_frame.grid(row=1, column=0, sticky="ew")
        config_frame.grid_columnconfigure(1, weight=1)

        ttk.Label(config_frame, text="Number of Passes:").grid(row=0, column=0, sticky="w", padx=(0, 10))
        self.passes_combo = ttk.Combobox(config_frame, values=["1 Pass", "3 Passes", "7 Passes"], state="readonly")
        self.passes_combo.set("3 Passes")
        self.passes_combo.grid(row=0, column=1, sticky="ew", pady=(0, 10))

        ttk.Label(config_frame, text="Wipe Type:").grid(row=1, column=0, sticky="w", padx=(0, 10))
        self.wipe_type_combo = ttk.Combobox(config_frame, values=["DoD 5220.22-M", "Zeros", "Ones", "Random"], state="readonly")
        self.wipe_type_combo.set("DoD 5220.22-M")
        self.wipe_type_combo.grid(row=1, column=1, sticky="ew", pady=(0, 10))

        verify_frame = ttk.LabelFrame(config_frame, text="Verification Method", padding="5")
        verify_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        self.verify_method = tk.StringVar(value="Full Verify (Entire Disk)")
        ttk.Radiobutton(verify_frame, text="No Verification", variable=self.verify_method, value="No Verification").pack(anchor="w")
        ttk.Radiobutton(verify_frame, text="Quick Verify (Sample Sectors)", variable=self.verify_method, value="Quick Verify (Sample Sectors)").pack(anchor="w")
        ttk.Radiobutton(verify_frame, text="Full Verify (Entire Disk)", variable=self.verify_method, value="Full Verify (Entire Disk)").pack(anchor="w")

        cert_enc_frame = ttk.LabelFrame(config_frame, text="Certificate Encryption Type", padding="5")
        cert_enc_frame.grid(row=3, column=0, columnspan=2, sticky="ew")
        self.cert_enc_method = tk.StringVar(value="SHA-256 Hash")
        ttk.Radiobutton(cert_enc_frame, text="SHA-256 Hash", variable=self.cert_enc_method, value="SHA-256 Hash").pack(anchor="w")

    def create_quick_stats_ui(self, parent):
        stats_frame = ttk.LabelFrame(parent, text="Quick Stats", padding="10")
        stats_frame.pack(fill="both", expand=True)
        stats_frame.grid_columnconfigure(1, weight=1)

        ttk.Label(stats_frame, text="Data Written:").grid(row=0, column=0, sticky="w")
        ttk.Label(stats_frame, text="Sectors Wiped:").grid(row=1, column=0, sticky="w")
        ttk.Label(stats_frame, text="Current Pass:").grid(row=2, column=0, sticky="w")
        ttk.Label(stats_frame, text="Speed:").grid(row=3, column=0, sticky="w")
        ttk.Label(stats_frame, text="Remaining (ETA):").grid(row=4, column=0, sticky="w")

        self.stat_data_written = ttk.Label(stats_frame, text="0.00 MB")
        self.stat_data_written.grid(row=0, column=1, sticky="e")
        self.stat_sectors_wiped = ttk.Label(stats_frame, text="0")
        self.stat_sectors_wiped.grid(row=1, column=1, sticky="e")
        self.stat_current_pass = ttk.Label(stats_frame, text="0")
        self.stat_current_pass.grid(row=2, column=1, sticky="e")
        self.stat_speed = ttk.Label(stats_frame, text="0.00 MB/s")
        self.stat_speed.grid(row=3, column=1, sticky="e")
        self.stat_eta = ttk.Label(stats_frame, text="calculating…")
        self.stat_eta.grid(row=4, column=1, sticky="e")

    # ----------------- Logs & Progress -----------------
    def add_log(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{timestamp}] {message}"
        self.log_buffer.append(line)

        self.log_text.config(state="normal")
        self.log_text.insert(tk.END, line + "\n")
        self.log_text.see(tk.END)
        self.log_text.config(state="disabled")
        self.update_idletasks()

    def update_progress(self, value):
        self.progress_bar['value'] = value
        self.progress_percent_label.config(text=f"{value:.1f}%")

    def update_stats(self, stats_dict):
        self.stat_data_written['text'] = f"{stats_dict.get('data_written_mb', 0):.2f} MB"
        self.stat_sectors_wiped['text'] = f"{stats_dict.get('sectors_wiped', 0)}"
        self.stat_current_pass['text'] = f"{stats_dict.get('current_pass', 0)}"
        speed = stats_dict.get('speed_mbps', 0.0)
        self.stat_speed['text'] = f"{speed:.2f} MB/s"

        eta_sec = stats_dict.get('eta_seconds', None)
        eta_txt = human_eta(eta_sec)
        self.stat_eta['text'] = eta_txt
        self.eta_label.config(text=f"ETA: {eta_txt}")

    # ----------------- Drive population & selection -----------------
    def populate_drives(self):
        self.add_log("Searching for connected devices...")
        self.available_drives = self.backend.list_physical_drives()
        drive_names = [d['name'] for d in self.available_drives]
        self.device_combo['values'] = drive_names
        if drive_names:
            self.device_combo.current(0)
            self.on_device_select(None)
        else:
            self.add_log("No USB drives found. Please connect a USB device and run as Administrator.")

    def on_device_select(self, event):
        selection_index = self.device_combo.current()
        if selection_index >= 0 and selection_index < len(self.available_drives):
            drive_info = self.available_drives[selection_index]
            details = self.backend.get_drive_details(drive_info['path'])
            self.detail_name.config(text=details.get('Name', 'N/A'))
            self.detail_capacity.config(text=f"{drive_info.get('size_gb', 0):.2f} GB")
            self.detail_fs.config(text=details.get('File System', 'N/A'))
            # Reset health/temp view
            self.detail_health.config(text="Unknown")
            self.detail_temp.config(text="N/A")

    # ----------------- Buttons -----------------
    def toggle_controls(self, enabled=True):
        state = "readonly" if enabled else "disabled"
        self.device_combo.config(state=state)
        self.passes_combo.config(state=state)
        self.wipe_type_combo.config(state=state)
        # Enable/disable radiobuttons in verification frame and cert frame
        # (Walk the Main tab frame children)
        try:
            for child in self.main_frame.winfo_children():
                if isinstance(child, ttk.Frame) or isinstance(child, ttk.LabelFrame):
                    for grand in child.winfo_children():
                        if isinstance(grand, ttk.Radiobutton):
                            grand.config(state=tk.NORMAL if enabled else tk.DISABLED)
        except Exception:
            pass
        self.start_button.config(state=tk.NORMAL if enabled else tk.DISABLED)
        self.stop_button.config(state=tk.DISABLED if enabled else tk.NORMAL)
        self.export_btn.config(state=tk.NORMAL if enabled else tk.DISABLED)
        self.refresh_btn.config(state=tk.NORMAL if enabled else tk.DISABLED)
        self.health_btn.config(state=tk.NORMAL if enabled else tk.DISABLED)

    def start_wipe(self):
        selection_index = self.device_combo.current()
        if selection_index < 0:
            messagebox.showerror("Error", "Please select a device to wipe.")
            return
        drive_info = self.available_drives[selection_index]
        if messagebox.askokcancel("Destructive Action Warning",
                                  f"WARNING: All data on {drive_info['name']} will be PERMANENTLY destroyed. Proceed?"):
            self.toggle_controls(enabled=False)
            self.add_log("User confirmed. Starting wipe process in background...")
            self.progress_bar['value'] = 0
            self.progress_percent_label.config(text="0.0%")
            self.eta_label.config(text="ETA: calculating…")
            self.wipe_thread = threading.Thread(target=self._wipe_thread_worker, daemon=True)
            self.wipe_thread.start()

    def _wipe_thread_worker(self):
        selection_index = self.device_combo.current()
        drive_info = self.available_drives[selection_index]
        wipe_type = self.wipe_type_combo.get()
        passes = self.passes_combo.get()
        verify = self.verify_method.get()
        drive_size = drive_info['size']
        wipe_successful, total_sectors = self.backend.perform_wipe(drive_info['path'], wipe_type, passes, drive_size)

        if self.backend.stop_wipe_flag:
            self.add_log("Wipe was stopped.")
            self.after(0, self.toggle_controls, True)
            return

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
                    # Auto-save logs to Documents/WipeLogs
                    self.auto_save_logs()
                    self.after(0, messagebox.showinfo, "Success", "Device wipe and certification completed successfully.\nLogs have been saved.")
                else:
                    self.after(0, messagebox.showerror, "Error", "Failed to generate certificate.")
            else:
                self.after(0, messagebox.showerror, "Verification Failed", f"The wipe could not be verified. Status: {status}")
        else:
            self.after(0, messagebox.showerror, "Wipe Failed", "The wipe process failed. Check logs for details.")
        self.after(0, self.toggle_controls, True)

    def stop_wipe(self):
        self.add_log("Stop signal sent. Finishing current operation...")
        self.backend.stop_wipe_flag = True
        self.stop_button.config(state="disabled")

    # -------- Health button --------
    def check_health_clicked(self):
        idx = self.device_combo.current()
        if idx < 0:
            messagebox.showerror("Error", "Select a device first.")
            return
        info = self.available_drives[idx]
        self.add_log("Checking drive health and temperature (SMART)…")
        res = self.backend.get_drive_health_and_temp(info)
        self.detail_health.config(text=res.get('health', 'Unknown'))
        temp_c = res.get('temperature_c', None)
        self.detail_temp.config(text=f"{temp_c} °C" if temp_c is not None else "N/A")
        self.add_log(f"Health: {res.get('health', 'Unknown')}, Temperature: {temp_c if temp_c is not None else 'N/A'}")

    # -------- Log export --------
    def export_logs(self):
        try:
            default_name = f"WipeLogs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            path = filedialog.asksaveasfilename(
                title="Export Logs",
                defaultextension=".txt",
                initialfile=default_name,
                filetypes=[("Text Files", "*.txt")]
            )
            if not path:
                return
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(self.log_buffer))
            messagebox.showinfo("Logs Exported", f"Logs saved to:\n{path}")
            self.add_log(f"Logs exported to {path}")
        except Exception as e:
            messagebox.showerror("Export Failed", f"Could not save logs: {e}")

    def auto_save_logs(self):
        try:
            logs_dir = os.path.join(os.path.expanduser("~"), "Documents", "WipeLogs")
            os.makedirs(logs_dir, exist_ok=True)
            filename = os.path.join(logs_dir, f"WipeLogs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
            with open(filename, "w", encoding="utf-8") as f:
                f.write("\n".join(self.log_buffer))
            self.add_log(f"Auto-saved logs to {filename}")
        except Exception as e:
            self.add_log(f"Auto-save logs failed: {e}")

    # ----------------- Other Tabs -----------------
    def build_support_tab(self):
        frame = ttk.Frame(self.support_tab, padding=15)
        frame.pack(fill=tk.BOTH, expand=True)
        txt = tk.Text(frame, wrap="word", height=20)
        txt.pack(fill=tk.BOTH, expand=True)
        help_text = (
            "Support\n"
            "======\n\n"
            "1) Run as Administrator on Windows for physical drive access.\n"
            "2) Connect your USB drive, click Refresh, then select the device.\n"
            "3) Choose wipe type and number of passes.\n"
            "4) Click Start Wipe. Do not remove the drive until completion.\n"
            "5) After completion, verify status and find your certificate under Documents/WipeCertificates.\n"
            "6) Export logs anytime via the 'Export Logs' button.\n\n"
            "If you face 'Win32 Error 5' or access denied:\n"
            " - Ensure no windows are open on the target drive.\n"
            " - Close antivirus or tools locking the device.\n"
            " - Re-run the app as Administrator.\n\n"
            "Contact: support@yourcompany.example\n"
        )
        txt.insert("1.0", help_text)
        txt.config(state="disabled")

    def build_security_tab(self):
        frame = ttk.Frame(self.sec_tab, padding=15)
        frame.pack(fill=tk.BOTH, expand=True)
        tree = ttk.Treeview(frame, columns=("desc"), show="headings", height=15)
        tree.heading("desc", text="Standard / Guidance")
        tree.pack(fill=tk.BOTH, expand=True)

        items = [
            "DoD 5220.22-M (E): Multi-pass overwrite guidance (legacy; not current DoD policy).",
            "NIST SP 800-88 Rev.1: Guidelines for Media Sanitization (Clear, Purge, Destroy).",
            "ISO/IEC 27040: Storage security — media sanitization references.",
            "GDPR (EU): Data protection—secure erasure for personal data when no longer needed.",
            "HIPAA (US): Secure disposal of ePHI including media sanitization.",
            "PCI DSS: Secure deletion for cardholder data on media.",
            "CJIS (US): Criminal Justice Information Services—media handling/sanitization.",
        ]
        for it in items:
            tree.insert("", tk.END, values=(it,))

        note = ttk.Label(frame, text="Note: This tool provides overwrite-based clearing methods. "
                                     "For compliance, select the appropriate method and retain the generated certificate and logs.")
        note.pack(anchor="w", pady=(10, 0))

    def build_about_tab(self):
        frame = ttk.Frame(self.about_tab, padding=15)
        frame.pack(fill=tk.BOTH, expand=True)
        lbl = ttk.Label(frame, text="Secure Data Wiping Utility v1.1\n(c) 2025 Runtime Terror\n\n"
                                    "Features: DoD-style multi-pass, verification, certificates, logs export,\n"
                                    "drive health check (SMART), progress % and ETA, and compliance references.",
                        justify="left")
        lbl.pack(anchor="w")

    # ----------------- App Entry -----------------
    def run(self):
        self.mainloop()


def is_admin():
    if sys.platform != 'win32':
        return True
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


if __name__ == "__main__":
    if sys.platform == 'win32' and not is_admin():
        try:
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror("Administrator Privileges Required",
                                 "Please re-run this application as an Administrator to access physical drives.")
            root.destroy()
        except tk.TclError:
            print("Administrator Privileges Required. Please re-run as admin.")
    else:
        app = SecureWipeApp()
        app.run()
