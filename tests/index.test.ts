import { Ed25519Ecies } from "../src"
import { sign } from 'tweetnacl';
import { assert } from "chai";

describe("My Test Suite", () => {
  it("E2E checks for encrypt/descrypt", async () => {
    // Set some Ed25519 key pairs for Alice and Bob
    const aliceSecret = Buffer.from("8099218df05be91769679587124cfb3c1f6b0602805ffda193f26790c531e1eb", "hex");
    const bobSecret = Buffer.from("8ed0ce08849ef03657e0f137f15b73afbfc4ecbfcc76505e5fb5f63c998bb8a0", "hex");

    // Create keypairs
    const aliceEd25519KeyPair = sign.keyPair.fromSeed(aliceSecret);
    const bobEd25519KeyPair = sign.keyPair.fromSeed(bobSecret);

    // Encrypt and decrypt message
    const messageEncrypted = await Ed25519Ecies.encrypt(Buffer.from("Hello!"), aliceEd25519KeyPair.publicKey, bobEd25519KeyPair.secretKey);
    const messageEncrypted2 = await Ed25519Ecies.encrypt(Buffer.from("Hello!"), bobEd25519KeyPair.publicKey, aliceEd25519KeyPair.secretKey);
    // Make sure they achieve the same encrypted result
    assert(Buffer.from(messageEncrypted.subarray(36, messageEncrypted.length-32)).equals(messageEncrypted2.subarray(36, messageEncrypted2.length-32)));
    // Make sure they do not equal the unencrypted string
    assert(Buffer.from(messageEncrypted.subarray(36, messageEncrypted.length-32)).toString() !== "Hello!")
    const messageDecrypted = await Ed25519Ecies.decrypt(messageEncrypted, aliceEd25519KeyPair.secretKey);
    assert(Buffer.from(messageDecrypted).toString() === "Hello!")
  });
});