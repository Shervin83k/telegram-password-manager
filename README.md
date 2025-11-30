# 🔒 Secure Password Manager Bot

A secure, encrypted password management Telegram bot built with Python and aiogram. Features end-to-end encryption, secure session management, and comprehensive security measures to protect your sensitive data.

## 🚀 Features

### 🔐 Security & Encryption
- **End-to-End Encryption**: All passwords encrypted with Fernet (AES-128)
- **Secure Hashing**: bcrypt for password hashing with salt
- **Session Management**: Encrypted sessions with automatic timeout
- **Input Validation**: Comprehensive validation against SQL injection and malicious input
- **Rate Limiting**: Global rate limiting to prevent abuse

### 💼 Password Management
- **Secure Storage**: Encrypted password entries in SQLite database
- **Easy Retrieval**: Decrypt entries with your encryption key
- **Entry Management**: Add, view, edit, and delete password entries
- **Data Isolation**: Users can only access their own entries

### 🛡️ Security Features
- **Automatic Session Expiry**: 3-minute inactivity timeout
- **Login Attempt Limits**: Maximum 5 attempts per 5 minutes
- **Input Sanitization**: Protection against injection attacks
- **Encrypted Memory**: Session data encrypted in memory
- **Admin Controls**: User management and monitoring

## 📋 Prerequisites

- Python 3.8+
- Telegram Bot Token from [@BotFather](https://t.me/BotFather)

## 🛠️ Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd password-saver-bot