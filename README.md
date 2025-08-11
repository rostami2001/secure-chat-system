# secure-chat-system

This repository contains my implementation of a secure chat application, developed as part of the "Fundamentals of Information Security" course at Ferdowsi University of Mashhad at spring 2024.

## Project Overview

The Secure Chat System is a Python-based application that provides:
- User registration and authentication with password hashing
- End-to-end encrypted private messaging
- Secure group chats with access control
- Digital signatures for message authenticity
- Role-based access control (admin/user roles)

## Technical Features

- **Cryptography**: Uses RSA for asymmetric encryption and PBKDF2 for password hashing
- **Network Communication**: Socket-based client-server architecture
- **Data Storage**: JSON files for user data, groups, and messages
- **Security Measures**:
  - Salted password hashing
  - Public/private key pairs for each user
  - Message encryption and digital signatures
  - Access control for group management

## Files Included

- `server.py` - Main server application
- `secure-chat.py` - Client GUI application
- `user_data.json` - Sample user database (contains test data)
- `group_data.json` - Sample group information
- `messages_data.json` - Sample message history
- `project_report.pdf` - Documentation (in Persian)

## Course Context

This was my first information security project, implementing core security concepts:
- Confidentiality (encryption)
- Integrity (digital signatures)
- Authentication
- Access control
- Non-repudiation
