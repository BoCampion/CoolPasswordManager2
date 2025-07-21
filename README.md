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

Before installing make sure you have 'git' installed so you can clone the repository fine (when you run git clone... it should show a pop up to install it and then try again after)
# 1. Clone the repository
git clone (https://github.com/BoCampion/CoolPasswordManager2.git)
cd coolthingpasswordmanager2

# 2. Install Python dependencies
pip3 install flask flask-cors cryptography pwnedapi

# 3. Create secret Key
cd python\ flask/ 
python3 makekey.py
(or navigate to makekey.py in side bar and run it ONLY ONCE and make sure the seceret key inst in the python flask folder)
# 3. Start the server
python3 app.py


# Google Extention
Open Chrome and go to chrome://extensions
Enable Developer Mode (top-right)

Click Load unpacked

Select the extension folder (e.g., chrome_extension/)

Done! The extension connects to your running Flask server.
