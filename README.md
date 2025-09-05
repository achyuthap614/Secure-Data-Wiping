Secure Data Wiping Utility
A secure, user-friendly data wiping utility built with Python and Tkinter. This tool is designed to securely and permanently erase all data from storage devices like USB drives, HDDs, and SSDs. It provides verifiable proof of erasure by generating a digitally signed certificate, giving you peace of mind when selling, donating, or disposing of your old hardware.

Screenshots
(Here you can add the screenshots you sent me. In GitHub, you can drag and drop them into this README file.)

Features
Physical Drive Detection: Automatically scans for and lists all connected physical storage devices.

Multiple Wiping Algorithms: Choose from various industry-standard sanitization methods:

DoD 5220.22-M (3 passes)

Fill with Zeros (1 pass)

Fill with Ones (1 pass)

Random Data (1 pass)

Configurable Passes: Customize the number of overwrite passes for added security.

Wipe Verification: Optional verification steps to ensure the data has been successfully overwritten:

Full Verify: Checks the entire disk.

Quick Verify: Checks a random sample of sectors for speed.

Tamper-Proof Certificates: Generates a detailed completion certificate in both human-readable PDF and machine-readable JSON formats.

Secure Hashing: The certificate includes a SHA-256 hash of its contents to ensure its integrity.

Real-time Progress: A detailed live log, progress bar, and statistics panel keep you informed throughout the process.

Technology Stack
UI Framework: Python Tkinter

Backend Logic: Python

Core Libraries:

psutil & wmi: For detecting physical drives on Windows.

reportlab: For generating PDF certificates.

cryptography: For cryptographic operations and future digital signature enhancements.

Prerequisites
Python 3.9 or higher

Windows Operating System (the current drive detection logic is Windows-specific)

Installation & Usage
Clone the repository:

git clone [https://github.com/your-username/secure-wiping-utility.git](https://github.com/your-username/secure-wiping-utility.git)
cd secure-wiping-utility

Install the required libraries:

pip install psutil wmi reportlab cryptography

Run the application:

⚠️ IMPORTANT: You MUST run the script with Administrator privileges to allow low-level access to the physical drives. Right-click your terminal (Command Prompt, PowerShell, etc.) and select "Run as administrator" before running the command below.

python your_main_ui_script.py

Using the tool:

Select the target device from the dropdown menu.

Choose your desired Wipe Type, Number of Passes, and Verification Method.

Click Start Wipe.

Acknowledge the warning prompt.

Upon completion, a PDF and JSON certificate will be saved in the application's directory.

⚠️ DESTRUCTIVE ACTION WARNING ⚠️
This is a powerful tool that will PERMANENTLY and IRREVERSIBLY delete all data on the selected drive. There is NO UNDO option.

Double-check the selected drive before starting the wipe.

The author is not responsible for any data loss. Use this software at your own risk.

It is highly recommended to test the application on a spare, non-critical USB drive first.

License
This project is licensed under the MIT License. See the LICENSE file for details.****
