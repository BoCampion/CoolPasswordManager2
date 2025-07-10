# CoolThing Password Manager

CoolThing is a local, secure, and minimalist password manager built with Flask. It encrypts your credentials, detects breaches, and includes a Chrome extension for quick access.


# Features

- 🔒 AES encryption using Fernet
- 🔐 Password breach check (via HaveIBeenPwned API)
- 🌙 Light/Dark theme toggle
- ⭐ Favorite logins
- ⏳ Auto-logout option
- 📩 Breach notification toggle
- 🧩 Chrome extension integration


## Setup Instructions

# 1. Clone the repository
git clone https://github.com/yourusername/coolthing-password-manager.git
cd coolthing-password-manager

# 2. Install Python dependencies
pip3 install flask flask-cors cryptography pwnedapi

# 3. Start the server
cd python\ flask/
python app.py
Add Chrome Extension
Open Chrome and go to chrome://extensions

# Google Extention
Enable Developer Mode (top-right)

Click Load unpacked

Select the extension folder (e.g., chrome_extension/)

Done! The extension connects to your running Flask server.
