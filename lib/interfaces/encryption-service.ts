export interface EncryptionService {
  encrypt(data: string): Promise<string>;
  decrypt(data: string): Promise<string>;
}
