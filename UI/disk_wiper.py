import os
import threading
import ctypes
import datetime

class DiskWiper:
    def __init__(self, device_path, passes, pattern, progress_callback, log_callback, stop_event):
        self.device_path = device_path
        self.passes = passes
        self.pattern = pattern.lower()
        self.progress_callback = progress_callback
        self.log_callback = log_callback
        self.stop_event = stop_event

    def wipe(self):
        try:
            size = self._get_device_size()
            if size == 0:
                self._log("Device size reported as zero. Aborting wipe.")
                return False
        except Exception as e:
            self._log(f"Failed to determine device size: {e}")
            return False

        chunk_size = 1024 * 1024  # 1 MB per write

        try:
            with open(self.device_path, 'rb+') as disk:
                for pass_num in range(1, self.passes + 1):
                    if self.stop_event.is_set():
                        self._log("Wipe cancelled by user.")
                        return False
                    self._log(f"Pass {pass_num} started")
                    disk.seek(0)
                    total_written = 0
                    while total_written < size:
                        if self.stop_event.is_set():
                            self._log("Wipe cancelled by user.")
                            return False
                        write_len = min(chunk_size, size - total_written)
                        data = self._generate_pattern(write_len, pass_num)
                        disk.write(data)
                        disk.flush()
                        os.fsync(disk.fileno())
                        total_written += write_len
                        self._progress(total_written, size)
                        if total_written % (50 * chunk_size) == 0:
                            self._log(f"Pass {pass_num}: {total_written/(1024**3):.2f} GB written")
                    self._log(f"Pass {pass_num} completed")
            self._log("Wipe operation completed successfully.")
            return True
        except Exception as e:
            self._log(f"Error during wiping: {e}")
            return False

    def _get_device_size(self):
        if os.name == 'nt':
            GENERIC_READ = 0x80000000
            OPEN_EXISTING = 3
            FILE_SHARE_READ = 1
            FILE_SHARE_WRITE = 2

            CreateFile = ctypes.windll.kernel32.CreateFileW
            GetFileSizeEx = ctypes.windll.kernel32.GetFileSizeEx
            CloseHandle = ctypes.windll.kernel32.CloseHandle

            handle = CreateFile(
                self.device_path,
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                0,
                None
            )
            if handle == -1:
                raise PermissionError("Cannot open device, try running as Administrator.")

            size = ctypes.c_longlong()
            if not GetFileSizeEx(handle, ctypes.byref(size)):
                CloseHandle(handle)
                raise OSError("Failed to get device size.")
            CloseHandle(handle)
            return size.value
        else:
            with open(self.device_path, 'rb') as f:
                f.seek(0, os.SEEK_END)
                return f.tell()

    def _generate_pattern(self, length, pass_num):
        if self.pattern == 'zeros only' or self.pattern == 'zeros':
            return b'\x00' * length
        elif self.pattern == 'random data' or self.pattern == 'random':
            return os.urandom(length)
        elif self.pattern == 'dod 5220.22-m' or self.pattern == 'dod':
            patterns = [b'\xF6', b'\x00', b'\xFF']
            pattern_byte = patterns[(pass_num - 1) % len(patterns)]
            return pattern_byte * length
        else:
            return b'\x00' * length

    def _log(self, message):
        if self.log_callback:
            self.log_callback(message)

    def _progress(self, done, total):
        if self.progress_callback:
            self.progress_callback(done, total)
