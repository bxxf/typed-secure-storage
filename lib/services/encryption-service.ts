import type { EncryptionService } from "../interfaces/encryption-service";

export class AESGCMEncryptionService implements EncryptionService {
  constructor(private encryptionKey: CryptoKey) {}

  /**
   * Encrypts a given string data.
   * @param {string} data - The data to encrypt.
   * @returns {Promise<string>} A promise that resolves with the encrypted data in a string format.
   * @private
   */
  async encrypt(data: string): Promise<string> {
    if (!this.encryptionKey)
      throw new Error("Encryption key has not been initialized.");

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoder = new TextEncoder();
    const encryptedData = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      this.encryptionKey,
      encoder.encode(data)
    );

    // Convert ArrayBuffer to Base64 string
    const buffer = new Uint8Array(encryptedData);
    const base64Data = btoa(String.fromCharCode(...buffer));

    return JSON.stringify({ iv: Array.from(iv), data: base64Data });
  }

  /**
   * Decrypts a given string data.
   * @param {string} encrypted - The encrypted data in a string format.
   * @returns {Promise<string>} A promise that resolves with the decrypted data as a string.
   * @private
   */
  async decrypt(encrypted: string): Promise<string> {
    if (!this.encryptionKey)
      throw new Error("Encryption key has not been initialized.");

    const { iv, data } = JSON.parse(encrypted);
    const ivArray = new Uint8Array(iv);
    const dataArray = Uint8Array.from(atob(data), (c) => c.charCodeAt(0));

    const decryptedData = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: ivArray },
      this.encryptionKey,
      dataArray
    );

    const decoder = new TextDecoder();
    return decoder.decode(decryptedData);
  }
}
