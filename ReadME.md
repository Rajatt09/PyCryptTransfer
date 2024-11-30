# PyCryptTransfer

**PyCryptTransfer** is a secure file transfer system that uses **Python (Flask)** for backend processing, **Socket.IO** for real-time communication, and **encryption** to protect file contents during transfer. The project is designed for seamless file transfer between users with strong encryption standards.

---

## **Features**

- Real-time file transfer with **Socket.IO**
- **AES encryption** for secure file sharing
- User-friendly interface for sending and receiving files

---

## **Setup Guide**

###Create a virtual environment to isolate your Python dependencies.

```bash
python -m venv venv
```

-Activate the virtual environment:

-On Windows:

```bash
venv\Scripts\activate
```

###Navigate to the frontend folder

```bash
cd frontend
```

-Install the necessary frontend packages, such as Socket.IO client.

```bash
npm install socket.io-client
```

###Navigate to Backend Folder

```bash
cd ../backend
```
-Install required Python packages for Flask, Socket.IO, and encryption.

```bash
pip install flask flask-socketio cryptography
```

-Start the Flask server.

```bash
python app.py
```






