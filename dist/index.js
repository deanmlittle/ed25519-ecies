"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var _a;
Object.defineProperty(exports, "__esModule", { value: true });
exports.Ed25519Ecies = void 0;
const tweetnacl_1 = require("tweetnacl");
const ed2curve_1 = require("ed2curve");
const hash_wasm_1 = require("hash-wasm");
const aes_js_1 = require("aes-js");
class Ed25519Ecies {
}
exports.Ed25519Ecies = Ed25519Ecies;
_a = Ed25519Ecies;
Ed25519Ecies.AESCBCEncrypt = (message, kE, iV) => {
    message = aes_js_1.padding.pkcs7.pad(message);
    const aesCbc = new aes_js_1.ModeOfOperation.cbc(kE, iV);
    return aesCbc.encrypt(message);
};
Ed25519Ecies.AESCBCDecrypt = (message, kE, iV) => {
    const aesCbc = new aes_js_1.ModeOfOperation.cbc(kE, iV);
    const decrypted = aesCbc.decrypt(message);
    return Buffer.from(aes_js_1.padding.pkcs7.strip(decrypted));
};
Ed25519Ecies.sharedSecretFromEd25519Keys = (secretKey, publicKey) => {
    const X25519Secret = (0, ed2curve_1.convertSecretKey)(secretKey);
    const X25519Pubkey = (0, ed2curve_1.convertPublicKey)(publicKey);
    return (0, tweetnacl_1.scalarMult)(X25519Secret, X25519Pubkey);
};
Ed25519Ecies.ivkEkMFromEd25519Keys = (secretKey, publicKey) => __awaiter(void 0, void 0, void 0, function* () {
    const P = _a.sharedSecretFromEd25519Keys(secretKey, publicKey);
    const S = tweetnacl_1.box.keyPair.fromSecretKey(P).publicKey;
    const hash = yield (0, hash_wasm_1.sha512)(S);
    const hashBuffer = Buffer.from(hash, "hex");
    return {
        iv: hashBuffer.subarray(0, 16),
        kE: hashBuffer.subarray(16, 32),
        kM: hashBuffer.subarray(32, 64)
    };
});
Ed25519Ecies.encrypt = (message, to, from) => __awaiter(void 0, void 0, void 0, function* () {
    // If we don't specify a sender, we make one from a random new keypair
    const fromKeypair = from ? tweetnacl_1.sign.keyPair.fromSecretKey(from) : tweetnacl_1.sign.keyPair();
    const Rbuf = fromKeypair.publicKey;
    const { iv, kE, kM } = yield _a.ivkEkMFromEd25519Keys(fromKeypair.secretKey, to);
    const ciphertext = _a.AESCBCEncrypt(message, kE, iv);
    const encoded = Buffer.concat([Buffer.from('SIE1'), Rbuf, ciphertext]);
    const hmac = yield (0, hash_wasm_1.createHMAC)((0, hash_wasm_1.createSHA256)(), kM);
    hmac.init();
    hmac.update(encoded);
    const digest = hmac.digest("binary");
    return Buffer.concat([encoded, digest]);
});
// Takes in an encrypted message and a secret key to decrypt an encrypted message
Ed25519Ecies.decrypt = (message, to) => __awaiter(void 0, void 0, void 0, function* () {
    // If we don't specify a sender, we make one from a random new keypair
    if (Buffer.from(message.subarray(0, 4)).toString() !== "SIE1") {
        throw new Error("Invalid Magic");
    }
    const from = message.subarray(4, 36);
    const { iv, kE, kM } = yield _a.ivkEkMFromEd25519Keys(to, from);
    const ciphertext = message.subarray(36, message.length - 32);
    const checksum = message.subarray(message.length - 32, message.length);
    const hmac = yield (0, hash_wasm_1.createHMAC)((0, hash_wasm_1.createSHA256)(), kM);
    hmac.init();
    hmac.update(message.subarray(0, message.length - 32));
    const checksum2 = hmac.digest("binary");
    if (!Buffer.from(checksum).equals(checksum2)) {
        throw new Error("Invalid checksum");
    }
    return _a.AESCBCDecrypt(ciphertext, kE, iv);
});
