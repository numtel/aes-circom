/**
 * tinyAes.ts
 * 
 * Single-block AES (ECB-like) encryption/decryption using 
 * the Web Crypto API (AES-CBC + zero IV) for 128/192/256 bits.
 * 99% by ChatGPT o1
 */

/** A 4×4 matrix of bytes: [4][4]. */
export type Block4x4 = number[][];

/**
 * Flatten a 4×4 matrix of bytes into a 16-byte Uint8Array
 */
function flattenBlock(block: Block4x4): Uint8Array {
  const out = new Uint8Array(16);
  let idx = 0;
  for (let row = 0; row < 4; row++) {
    for (let col = 0; col < 4; col++) {
      out[idx++] = block[col][row] & 0xff;
    }
  }
  return out;
}

/**
 * Un-flatten a 16-byte Uint8Array into a 4×4 matrix of bytes
 */
function unflattenBlock(bytes: Uint8Array): Block4x4 {
  const out: Block4x4 = [
    [0, 0, 0, 0],
    [0, 0, 0, 0],
    [0, 0, 0, 0],
    [0, 0, 0, 0],
  ];
  let idx = 0;
  for (let row = 0; row < 4; row++) {
    for (let col = 0; col < 4; col++) {
      out[col][row] = bytes[idx++];
    }
  }
  return out;
}

/**
 * Single-block AES class that mimics ECB for exactly one block
 * by using AES-CBC with a zero IV.
 *
 * Supports 16-, 24-, and 32-byte keys (AES-128, AES-192, AES-256).
 */
export class TinyAES {
  private cryptoKey!: CryptoKey;

  /**
   * @param key A 16-, 24-, or 32-byte key.
   */
  constructor(private readonly key: Uint8Array) {
    if (![16, 24, 32].includes(key.length)) {
      throw new Error('Key must be 16, 24, or 32 bytes.');
    }
  }

  /**
   * Imports the raw key into the SubtleCrypto API. Must be awaited
   * before calling encryptBlock/decryptBlock.
   */
  public async init() {
    // length is auto-detected from the raw key size (16, 24, or 32)
    this.cryptoKey = await crypto.subtle.importKey(
      'raw',
      this.key,
      { name: 'AES-CBC' }, // We'll use CBC mode with zero IV
      false,               // not extractable
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Encrypt exactly one 16-byte block (4×4) with AES.
   * Internally uses CBC with IV = 0, effectively giving ECB for one block.
   *
   * @param block 4×4 matrix of bytes
   * @returns 4×4 matrix of ciphertext bytes
   */
  public async encryptBlock(block: Block4x4): Promise<Block4x4> {
    const plaintext = flattenBlock(block);
    if (plaintext.length !== 16) {
      throw new Error('Block must be exactly 16 bytes (4×4).');
    }
    const zeroIv = new Uint8Array(16);

    const result = await crypto.subtle.encrypt(
      { name: 'AES-CBC', iv: zeroIv },
      this.cryptoKey,
      plaintext
    );
    const ciphertext = new Uint8Array(result);

    if (ciphertext.length !== 32) {
      throw new Error('Unexpected ciphertext size (not 32 bytes, block + unused padding).');
    }
    return unflattenBlock(ciphertext);
  }

  /**
   * Decrypt exactly one 16-byte block (4×4).
   *
   * @param block 4×4 matrix of ciphertext bytes
   * @returns 4×4 matrix of decrypted (plaintext) bytes
   */
  public async decryptBlock(block: Block4x4): Promise<Block4x4> {
    const ciphertext = flattenBlock(block);
    if (ciphertext.length !== 16) {
      throw new Error('Block must be exactly 16 bytes (4×4).');
    }
    const zeroIv = new Uint8Array(16);

    const result = await crypto.subtle.decrypt(
      { name: 'AES-CBC', iv: zeroIv },
      this.cryptoKey,
      ciphertext
    );
    const plaintext = new Uint8Array(result);

    if (plaintext.length !== 32) {
      throw new Error('Unexpected plaintext size (not 32 bytes, block + unused padding).');
    }
    return unflattenBlock(plaintext);
  }
}

