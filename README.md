# 🔐 Java Password-Manager
A secure, offline password manager built with java. This application allows users to store, retrieve, and manage their login credentials safely using string encryption and a master password authentication system.
# Features
- Master password authentication system
- Secure local storage of credentials
- AES encryption for passwords
- Search credentials by service/ website
- Password generator
- Password strength indicator
- Clipboard auto-clear
- Encrypted export/import of data
- Auto-lock after inactivity
# Tech Stack
- Language: Java 8+
- Encryption: Java Crytography Architecture
- Data Storage: Local file system
- UI: CLI (Console-based), extendable to JavaFX or Swing for GUI
- Build Tool: Maven
# How It Works
1. User Authentication
   - First time users create a master password, which is hashed and stored.
   - On launch, the user must enter the correct master password to unlock the vault.
2. Password Storage
   - Credentials (website, username, password) are encrypted and saved to a local file.
   - The file is unreadable without the correct master key.
3. Password Encryption
   - Uses AES symmetric encryption with a securely generated key derived from the master password
   - Stored passwords are decrypted only after successful authentication
4. Password Generator
   - User can generate strong, random password based on customized rules.
5. Auto Clear Clipboard
   - Passwords copied to clipboard are automatically cleared after a short duration to reduce risk
# Prerequisites
- Java JDK 8 or higher
- Git
- Maven
# Planned Features
- GUI with JavaFX
- Cloud backup with encryption
- Two-Factor-Authentication
- Browser extension integration
- Password change reminder system
# Contributing
Contributions are welcome! You can: 
- Suggest new features
- Report bugs
- Submit pull requests
# Disclaimer
This application is for educational use only. Do not use it to store real passwords without performing proper security audits
