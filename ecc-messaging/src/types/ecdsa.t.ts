// types/ecdsa.d.ts
declare module 'ecdsa' {
    export function sign(message: string, key: string): string;
    export function verify(message: string, signature: string, key: string): boolean;
    // Add other functions you use from the ecdsa module, following the above pattern.
}
