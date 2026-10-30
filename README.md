# 🔐 Password Strength Checker

A fast, private password strength checker with a secure password generator and a dark/light theme. Everything runs in your browser, so the password you type is never sent anywhere.

## ✨ Features

- **Real-time strength analysis**: five levels (Weak, Fair, Good, Strong, Very Strong) that update as you type
- **Smart weakness detection**: catches common passwords even when they're disguised (`P@ssw0rd123!`, `Summer2024!`), plus sequences (`abc`, `123`, `qwerty`), repeated characters and years
- **Crack time estimate**: based on effective entropy against a fast offline attack (10 billion guesses/second)
- **Secure password generator**: 16-character passwords made with the browser's cryptographic random number generator (`crypto.getRandomValues`), always including uppercase, lowercase, numbers and symbols
- **Copy to clipboard**: one click, with a fallback for older browsers
- **Dark/light theme**: follows your system setting by default and remembers your choice
- **Accessible**: keyboard friendly, screen-reader announcements, reduced-motion support, and a layout that works on phones

## 🚀 Usage

No installation or build step needed. Open `index.html` in any modern browser.

```bash
git clone https://github.com/YOUR_USERNAME/password-strength-checker.git
cd password-strength-checker
start index.html   # Windows  (macOS: open index.html)
```

## 🛠️ Built with

- HTML5
- CSS3 (custom properties, glassmorphism, responsive layout)
- Vanilla JavaScript (no frameworks or dependencies)

## 🧠 How the score works

1. **Character pool**: lowercase (26), uppercase (26), digits (10), symbols (33), non-Latin characters (100)
2. **Effective length**: repeated characters, sequences and years count for less
3. **Entropy** = effective length × log₂(pool size)
4. **Level**: entropy thresholds, with caps: under 8 characters can't go above *Fair*, and *Very Strong* needs 12+ characters and 3+ character types
5. **Common passwords** are always rated *Too Common* with an instant crack time

This is an educational estimate. For critical accounts, use a password manager and enable two-factor authentication.

## 📝 License

MIT
