/**
 * A class to provide encrypted local storage functionality, with data being
 * securely stored using AES-GCM encryption.
 *
 * @template S - Schema type for the storage. It should be an interface where the keys are table names and the values are the data types stored within those tables.
 */

import type { EncryptionService } from "./interfaces/encryption-service";
import { AESGCMEncryptionService } from "./services/encryption-service";

interface RequireSchemaDefinition {
  _defineSchemaInConstructorFirst: never;
}

/**
 * Factory function to create an instance of EncryptedStorage with a defined schema.
 *
 * @param {string} secret - The secret used to generate the encryption key.
 * @param {string} salt - The salt used to generate the encryption key.
 * @param {string} prefix - The prefix used for storage keys.
 * @returns An instance of EncryptedStorage with the provided schema.
 */
export async function createTypedSecureStorage<
  S extends Record<string, any> = RequireSchemaDefinition
>(
  secret: string,
  salt: string,
  prefix?: string | undefined
): Promise<EncryptedStorage<S>> {
  const encryptionService = new AESGCMEncryptionService(
    await generateKeyFromSecret(secret, new TextEncoder().encode(salt))
  );
  return new EncryptedStorage<S>(encryptionService, prefix);
}

class EncryptedStorage<
  S extends Record<string, any> = RequireSchemaDefinition
> {
  private prefix: string;
  private encryptionService: EncryptionService;

  /**
   * Constructs an instance of EncryptedStorage with a specified prefix for keys in local storage.
   *
   * @param {string} prefix - A prefix to prepend to all keys stored in local storage to avoid key collisions.
   */
  constructor(
    encryptionService: EncryptionService,
    prefix?: string | undefined
  ) {
    if (typeof window === "undefined")
      throw new Error("This library works only on client side.");
    if (!window.crypto.subtle)
      throw new Error("SubtleCrypto API is not supported in this environment.");
    if (!window.localStorage)
      throw new Error("LocalStorage API is not supported in this environment.");

    this.prefix = prefix ?? "@edb";
    this.encryptionService = encryptionService;
  }

  /**
   * Stores multiple values in the encrypted storage.
   * @param tableName
   * @param values
   * @returns {Promise<Array<S[T] & { key: string }>} A promise that resolves with an array of values, each with its key.
   */
  async setMultiple<T extends keyof S>(
    tableName: T,
    values: Array<S[T]>
  ): Promise<Array<S[T] & { key: string }>> {
    const res = await Promise.all(
      values.map((value) => this.set(tableName, value))
    );
    return res;
  }

  /**
   * Stores a value in the encrypted storage, with an optional key to use - if not provided, a random key will be generated.
   * @param tableName
   * @param value
   * @param key
   * @returns {Promise<S[T] & { key: string }>} A promise that resolves with the value and its key.
   */
  async set<T extends keyof S>(
    tableName: T,
    value: S[T],
    key?: string
  ): Promise<S[T] & { key: string }> {
    const finalKey = key || crypto.randomUUID();
    if ((await this.exists(tableName, finalKey)) && key == undefined) {
      return this.set(tableName, value);
    }
    const encryptedValue =
      (await this.encryptionService?.encrypt(JSON.stringify(value))) ?? "";
    localStorage.setItem(
      `${this.prefix}_${String(tableName)}_${finalKey}`,
      encryptedValue
    );
    return { ...value, key: finalKey };
  }

  /**
   * Checks if a specific key exists in the encrypted storage.
   * @param {keyof S} tableName - The name of the table.
   * @param {string} key - The key to check for existence.
   * @returns {Promise<boolean>} A promise that resolves with a boolean indicating whether the key exists.
   */
  async exists<T extends keyof S>(tableName: T, key: string): Promise<boolean> {
    return !!localStorage.getItem(`${this.prefix}_${String(tableName)}_${key}`);
  }

  /**
   * Retrieves a value for a specific key from the encrypted storage.
   * @param {keyof S} tableName - The name of the table.
   * @param {string} key - The key for the value to retrieve.
   * @returns {Promise<S[keyof S] | null>} A promise that resolves with the value, or null if not found.
   */
  async get<T extends keyof S>(
    tableName: T,
    key: string
  ): Promise<S[T] | null> {
    const item = localStorage.getItem(
      `${this.prefix}_${String(tableName)}_${key}`
    );
    if (!item) return null;
    const decryptedValue = (await this.encryptionService?.decrypt(item)) ?? "";
    return JSON.parse(decryptedValue);
  }

  /**
   * Retrieves all values from a specific table in the encrypted storage.
   * @param {keyof S} tableName - The name of the table to retrieve values from.
   * @returns {Promise<Array<S[keyof S] & { key: string }>>} A promise that resolves with an array of values, each with its key.
   */
  async getAll<T extends keyof S>(
    tableName: T
  ): Promise<Array<S[T] & { key: string }>> {
    const results: Array<S[T]> = [];
    const keys = Object.keys(localStorage).filter((key) =>
      key.startsWith(`${this.prefix}_${String(tableName)}_`)
    );

    for (const key of keys) {
      const item = localStorage.getItem(key);
      if (item) {
        const decryptedValue =
          (await this.encryptionService?.decrypt(item)) ?? "";
        results.push({
          ...JSON.parse(decryptedValue),
          key: key.replace(`${this.prefix}_${String(tableName)}_`, ""),
        });
      }
    }

    return results;
  }

  /**
   * Retrieves all keys from a specific table in the encrypted storage.
   * @param {keyof S} tableName - The name of the table to retrieve keys from.
   * @param predicate - A function that takes an item and returns a boolean indicating whether to include the item in the results.
   * @returns {Promise<Array<string>>} A promise that resolves with an array of keys.
   * */

  async filter<T extends keyof S>(
    tableName: T,
    predicate: (item: S[T] & { key: string }) => boolean
  ): Promise<Array<S[T] & { key: string }>> {
    const allItems = await this.getAll(tableName);
    return allItems.filter(predicate);
  }

  async remove<T extends keyof S>(tableName: T, key: string): Promise<void> {
    localStorage.removeItem(`${this.prefix}_${String(tableName)}_${key}`);
  }
}

/**
 * Generates an encryption key from a secret and a salt.
 *
 * @param {string} secret - The secret used to generate the key.
 * @param {Uint8Array} salt - The salt used in key generation.
 * @returns {Promise<CryptoKey>} A promise that resolves with the generated CryptoKey.
 * @private
 */
async function generateKeyFromSecret(
  secret: string,
  salt: Uint8Array
): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const keyMaterial = await window.crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 100000,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}
