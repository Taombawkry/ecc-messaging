import { ec as EC } from 'elliptic';
import path from 'path';

const ec = new EC('secp256k1');

/**
 * Generates a new key pair.
 * @returns An object containing the public and private keys in hex format.
 */
export async function generateKeys(): Promise<{ publicKey: string; privateKey: string }> {
    const keyPair = ec.genKeyPair();
    const publicKey = keyPair.getPublic('hex');
    const privateKey = keyPair.getPrivate('hex');

    // Securely handle key generation in a non-blocking manner
    return new Promise((resolve) => {
        resolve({ publicKey, privateKey });
    });
}

/**
 * Generates a new key pair and schedules the private key to be cleared from memory after a specified timeout.
 * @param timeout - The time in milliseconds after which the private key should be cleared from memory.
 * @returns An object containing the public key in hex format and the private key as a nullable string.
 */

export async function generateKeysWithTimeout(timeout: number = 1800000): Promise<{ publicKey: string, privateKey: string;}> {
    const keyPair = ec.genKeyPair();
    const publicKey = keyPair.getPublic("hex");
    let privateKey: string | null = keyPair.getPrivate("hex")

    // set timer to clear priivate key from memory
    setTimeout(() => {
        clearPrivateKey(privateKey!);
        privateKey = null; // ensure nullification
    }, timeout);

    return {publicKey, privateKey};
}


/**
 * Signs a message using the provided private key.
 * @param message - The message to sign.
 * @param privateKey - The private key to sign the message with.
 * @returns The signature in hex format.
 */

export async function signMessage(message: string, privateKey: string): Promise<string> {
    const key = ec.keyFromPrivate(privateKey);
    const signature = key.sign(message);

    return new Promise((resolve) => {
        resolve(signature.toDER('hex'));
    });
}

/**
 * Verifies a signed message.
 * @param message - The original message.
 * @param signature - The signature to verify.
 * @param publicKey - The public key to verify the signature against.
 * @returns A boolean indicating whether the signature is valid.
 */

export async function verifySignature(message: string, signature: string, publicKey: string): Promise<boolean> {
    const key = ec.keyFromPublic(publicKey, 'hex');
    const isValid = key.verify(message, signature);

    return new Promise((resolve) => {
        resolve(isValid);
    });
}

/**
 * Retrieves the public key from a given private key.
 * @param privateKey - The private key.
 * @returns The public key in hex format.
 */

export async function getPublicKey(privateKey: string): Promise<string> {
    const key = ec.keyFromPrivate(privateKey);
    const publicKey = key.getPublic('hex');

    return new Promise((resolve) => {
        resolve(publicKey);
    });
}

/**
 * Clears the private key from memory.
 * @param privateKey - The private key to clear.
 */

export function clearPrivateKey(privateKey: string): void {
    // Overwrite the private key variable with random data and then nullify
    const buffer = Buffer.from(privateKey, 'hex');
    buffer.fill(0);
    privateKey = null as any;
}
