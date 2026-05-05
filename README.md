# Zero-Knowledge Vault API (E2EE)

A production-grade, high-security vault system where the server never has access to user data or master passwords. Built with **Zero-Knowledge Architecture** and **End-to-End Encryption (E2EE)**.

## 🛡️ Security Architecture

### 1. Key Derivation (Argon2id)
When a user enters their password, it never leaves the browser. We use **Argon2id** (the winner of the Password Hashing Competition) to derive a `Master Key`.
- **Memory Cost**: 64MB
- **Iterations**: 3
- **Parallelism**: 4

### 2. Key Separation (HKDF)
From the `Master Key`, we derive two distinct keys using **HKDF (SHA-256)**:
- **Auth Key**: Sent to the server for authentication. The server hashes this with Bcrypt before storage. Even if the server is compromised, the Auth Key doesn't reveal the Master Key.
- **Encryption Key**: Used for AES-GCM. **This key never leaves the client.**

### 3. Authenticated Encryption (AES-256-GCM)
All vault data (titles, secrets) is encrypted using **AES-256-GCM**.
- **Symmetric Key**: 256-bit.
- **Nonce/IV**: 96-bit random value per item.
- **Integrity**: GCM provides built-in authentication (MAC), ensuring data hasn't been tampered with.

### 4. Server-Side Protection
- **No Plaintext**: The server only sees encrypted blobs and base64 nonces.
- **Secure Authentication**: Uses JWT for sessions, but the underlying proof is the `Auth Key` derived on the client.

## 🚀 Technologies
- **Backend**: Node.js, Express, TypeScript, Prisma, SQLite/PostgreSQL.
- **Frontend**: Vite, TypeScript, Vanilla CSS (Premium "Antigravity" Aesthetic).
- **Crypto**: Web Crypto API, Argon2-browser (WASM).

## 🛠️ Installation

### Backend
```bash
cd server
npm install
npx prisma db push
npm run dev
```

### Frontend
```bash
cd client
npm install
npm run dev
```

## 🔒 Security Disclaimer
This project is intended for educational and portfolio purposes. While it follows industry-best practices (Argon2, AES-GCM, HKDF), a full production deployment would require:
1. Mandatory HTTPS/HSTS.
2. Content Security Policy (CSP) to prevent XSS (which could steal keys from memory).
3. Professional Security Audit.

---
Created by ruok
