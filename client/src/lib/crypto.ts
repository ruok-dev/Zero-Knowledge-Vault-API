import argon2 from 'argon2-browser';

export interface Keys {
  authKey: string;
  encryptionKey: CryptoKey;
}

/**
 * Derives Auth Key and Encryption Key from a password and salt.
 * Uses Argon2id for the main derivation, then HKDF/HMAC for separation.
 */
export async function deriveKeys(password: string, salt: string): Promise<Keys> {
  // 1. Argon2id to get Master Key
  // Parameters: 64MB memory, 3 iterations, 4 parallelism (standard for modern hardware)
  const result = await argon2.hash({
    pass: password,
    salt: salt,
    time: 3,
    mem: 64 * 1024,
    hashLen: 32,
    parallelism: 4,
    type: argon2.Argon2Type.Argon2id,
  });

  const masterKeyBytes = result.hash;

  // 2. Import Master Key for Web Crypto
  const baseKey = await window.crypto.subtle.importKey(
    'raw',
    masterKeyBytes,
    { name: 'HKDF' },
    false,
    ['deriveKey', 'deriveBits']
  );

  // 3. Derive Auth Key (for server login)
  const authKeyBits = await window.crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new TextEncoder().encode('auth-salt'),
      info: new TextEncoder().encode('auth-key'),
    },
    baseKey,
    256
  );
  const authKey = Array.from(new Uint8Array(authKeyBits))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');

  // 4. Derive Encryption Key (AES-GCM)
  const encryptionKey = await window.crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new TextEncoder().encode('enc-salt'),
      info: new TextEncoder().encode('enc-key'),
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );

  return { authKey, encryptionKey };
}

/**
 * Encrypts data using AES-256-GCM
 */
export async function encrypt(data: string, key: CryptoKey): Promise<{ ciphertext: string; nonce: string }> {
  const encoder = new TextEncoder();
  const nonce = window.crypto.getRandomValues(new Uint8Array(12));
  const encodedData = encoder.encode(data);

  const encrypted = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce },
    key,
    encodedData
  );

  return {
    ciphertext: btoa(String.fromCharCode(...new Uint8Array(encrypted))),
    nonce: btoa(String.fromCharCode(...nonce)),
  };
}

/**
 * Decrypts data using AES-256-GCM
 */
export async function decrypt(ciphertext: string, nonce: string, key: CryptoKey): Promise<string> {
  const decoder = new TextDecoder();
  const nonceBytes = Uint8Array.from(atob(nonce), c => c.charCodeAt(0));
  const encryptedBytes = Uint8Array.from(atob(ciphertext), c => c.charCodeAt(0));

  const decrypted = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonceBytes },
    key,
    encryptedBytes
  );

  return decoder.decode(decrypted);
}
