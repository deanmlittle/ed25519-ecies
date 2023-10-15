import { scalarMult, box, sign } from 'tweetnacl';
import { convertPublicKey, convertSecretKey } from 'ed2curve';
import { sha512, createSHA256, createHMAC } from "hash-wasm";
import { ModeOfOperation, padding } from "aes-js";

export interface ivkEkM {
  iv: Uint8Array,
  kE: Uint8Array,
  kM: Uint8Array
}

export class Ed25519Ecies {
  static AESCBCEncrypt = (message: Uint8Array, kE: Uint8Array, iV:Uint8Array): Uint8Array => {
    message = padding.pkcs7.pad(message)
    const aesCbc = new ModeOfOperation.cbc(kE, iV)
    return aesCbc.encrypt(message)
  }

  static AESCBCDecrypt = (message: Uint8Array, kE: Uint8Array, iV:Uint8Array): Uint8Array => {
    const aesCbc = new ModeOfOperation.cbc(kE, iV)
    const decrypted = aesCbc.decrypt(message)
    return Buffer.from(padding.pkcs7.strip(decrypted))
  }

  static sharedSecretFromEd25519Keys = (secretKey: Uint8Array, publicKey: Uint8Array): Uint8Array => {
    const X25519Secret = convertSecretKey(secretKey);
    const X25519Pubkey = convertPublicKey(publicKey)!;
    return scalarMult(X25519Secret, X25519Pubkey)
  }

  static ivkEkMFromEd25519Keys = async (secretKey: Uint8Array, publicKey: Uint8Array): Promise<ivkEkM> => {
    const P = this.sharedSecretFromEd25519Keys(secretKey, publicKey);
    const S = box.keyPair.fromSecretKey(P).publicKey;
    const hash = await sha512(S);
    const hashBuffer = Buffer.from(hash, "hex");

    return {
      iv: hashBuffer.subarray(0,16),
      kE: hashBuffer.subarray(16, 32),
      kM: hashBuffer.subarray(32, 64)
    } as ivkEkM
  }

  static encrypt = async (message: Uint8Array, to: Uint8Array, from?: Uint8Array) => {
    // If we don't specify a sender, we make one from a random new keypair
    const fromKeypair = from ? sign.keyPair.fromSecretKey(from) : sign.keyPair()
    const Rbuf = fromKeypair.publicKey
    const { iv, kE, kM } = await this.ivkEkMFromEd25519Keys(fromKeypair.secretKey, to)
    const ciphertext = Ed25519Ecies.AESCBCEncrypt(message, kE, iv)
    const encoded = Buffer.concat([Buffer.from('SIE1'), Rbuf, ciphertext])

    const hmac = await createHMAC(createSHA256(), kM);
    hmac.init();
    hmac.update(encoded);
    const digest = hmac.digest("binary");
    return Buffer.concat([encoded, digest])
  }

  // Takes in an encrypted message and a secret key to decrypt an encrypted message
  static decrypt = async (message: Uint8Array, to: Uint8Array): Promise<Uint8Array> => {
    // If we don't specify a sender, we make one from a random new keypair
    if(Buffer.from(message.subarray(0,4)).toString() !== "SIE1") {
      throw new Error("Invalid Magic")
    }
    const from = message.subarray(4, 36);
    const { iv, kE, kM } = await Ed25519Ecies.ivkEkMFromEd25519Keys(to, from)
    const ciphertext = message.subarray(36, message.length - 32)
    const checksum = message.subarray(message.length-32, message.length)

    const hmac = await createHMAC(createSHA256(), kM);
    hmac.init();
    hmac.update(message.subarray(0, message.length - 32));
    const checksum2 = hmac.digest("binary");
    if(!Buffer.from(checksum).equals(checksum2)) {
      throw new Error("Invalid checksum")
    }
    return Ed25519Ecies.AESCBCDecrypt(ciphertext, kE, iv);
  }
}