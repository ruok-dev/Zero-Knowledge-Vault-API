export interface UserRegistrationResponse {
  userId: string;
  username: string;
  salt: string;
}

export interface UserLoginChallenge {
  salt: string;
}

export interface VaultItem {
  id: string;
  title: string; // Encrypted
  data: string;  // Encrypted (AES-GCM base64/hex)
  nonce: string; // IV for AES-GCM
  createdAt: Date;
  updatedAt: Date;
}

export interface EncryptedPayload {
  ciphertext: string;
  nonce: string;
  tag?: string; // If using a separate tag, though often included in ciphertext in Web Crypto
}
