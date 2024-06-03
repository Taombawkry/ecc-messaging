// Hooks and methods for generator

// Hooks and methods for generator
import { ec as EC } from 'elliptic';

// Create a new elliptic curve instance using the preset curve 'secp256k1'
const ec = new EC('secp256k1');

export function generateKeys() {
    const key = ec.genKeyPair();
    const publicKey = key.getPublic('hex');
    const privateKey = key.getPrivate('hex');

    return { publicKey, privateKey };
}
