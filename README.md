# 497-full-stack-messaging-application
# Secure Messenger (Python GUI)

This project is a secure full-stack messaging application built using Python.

## Security Features
- RSA key exchange
- AES-GCM encryption
- HMAC-SHA256 integrity validation
- Base64 transport
- REST API
- GUI client (Tkinter)

## How to Run
-In the terminal, to run the server enter these copy these commands:
py -m venv .venv
.\.venv\Scripts\Activate.ps1

-This will put you into the virtual environment, after enter the commands in the server section
-Then, create another terminal and run the commands for the client to open up the GUI

### Server
cd secure-messenger/server
pip install -r requirements.txt
uvicorn app:app --reload

### Client
cd secure-messenger/client
pip install -r requirements.txt
py gui_client.py

### Youtube Link
https://youtu.be/LxXW-xcP3IY
