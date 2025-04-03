# CryptographyCommunicationSystem

## Description
CryptographyCommunicationSystem is a secure, terminal-based chat application built in Python. It uses RSA for key exchange and AES for message encryption to provide a private communication channel between a client and server over sockets. This project highlights the power of cryptography in securing network communication.

## Features
- **RSA Key Exchange**: Ensures secure sharing of encryption keys.
- **AES Encryption**: Protects message content.
- **Terminal-Based**: Lightweight and easy to use.
- **Socket Communication**: Real-time messaging via TCP.

## Requirements
- Python 3.x
- `cryptography` library (`pip install cryptography`)

## How to Run
1. **Install dependencies**:
   ```bash
   pip install cryptography


## Screenshot
Here’s a snapshot of the one-way communication in action between the server and client:

![One-Way Communication Screenshot]
![image](https://github.com/user-attachments/assets/85910625-7347-46d3-b817-7d075ee74057)
**Server**: Listens for incoming messages and responds.
- **Client**: Sends a message to the server and receives the reply.

This demonstrates the secure exchange of encrypted messages using RSA and AES over a socket connection.

![Two-Way Communication Screenshot]
![image](https://github.com/user-attachments/assets/4ae789fd-92a8-44de-ab27-341bc7f0d334)
