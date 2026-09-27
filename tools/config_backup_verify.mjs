#!/usr/bin/env node

import { createDecipheriv, pbkdf2Sync } from "node:crypto";
import { isUtf8 } from "node:buffer";
import { closeSync, constants, fstatSync, openSync, readFileSync, readSync, writeSync } from "node:fs";

const ENVELOPE_HEADER_BYTES = 44;
const TAG_BYTES = 16;
const MAX_ENCRYPTED_BYTES = 32828;
const CFG2_HEADER_BYTES = 20;
const ENVELOPE_MAGIC = Buffer.from("SMSCFG01");
const CFG2_MAGIC = Buffer.from("CFG2");

function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
    }
  }
  return (~crc) >>> 0;
}

function readEncrypted(path) {
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const info = fstatSync(descriptor);
    if (!info.isFile() || info.size < 80 || info.size > MAX_ENCRYPTED_BYTES) {
      throw new Error("invalid artifact");
    }
    const encrypted = readFileSync(descriptor);
    if (encrypted.length !== info.size) throw new Error("artifact changed");
    return encrypted;
  } finally {
    closeSync(descriptor);
  }
}

function readPassphrase() {
  const input = Buffer.alloc(129);
  let length = 0;
  try {
    while (length < input.length) {
      const count = readSync(0, input, length, input.length - length, null);
      if (count === 0) break;
      length += count;
    }
    if (length < 12 || length > 128 || !isUtf8(input.subarray(0, length)) ||
        input.subarray(0, length).includes(0x0a) || input.subarray(0, length).includes(0x0d)) {
      throw new Error("invalid passphrase");
    }
    return Buffer.from(input.subarray(0, length));
  } finally {
    input.fill(0);
  }
}

function verify(encrypted, passphrase) {
  if (encrypted.length < ENVELOPE_HEADER_BYTES + TAG_BYTES + CFG2_HEADER_BYTES ||
      encrypted.length > MAX_ENCRYPTED_BYTES ||
      !encrypted.subarray(0, 8).equals(ENVELOPE_MAGIC) ||
      encrypted.readUInt16LE(8) !== 1 || encrypted[10] !== 1 || encrypted[11] !== 1 ||
      encrypted.readUInt32LE(12) !== 210000) {
    throw new Error("invalid envelope");
  }

  const header = encrypted.subarray(0, ENVELOPE_HEADER_BYTES);
  const tagOffset = encrypted.length - TAG_BYTES;
  const key = pbkdf2Sync(passphrase, encrypted.subarray(16, 32), 210000, 32, "sha256");
  let plaintext;
  let updateChunk;
  let finalChunk;
  try {
    const decipher = createDecipheriv(
      "aes-256-gcm", key, encrypted.subarray(32, 44), { authTagLength: TAG_BYTES },
    );
    decipher.setAAD(header);
    decipher.setAuthTag(encrypted.subarray(tagOffset));
    updateChunk = decipher.update(encrypted.subarray(ENVELOPE_HEADER_BYTES, tagOffset));
    finalChunk = decipher.final();
    plaintext = Buffer.concat([updateChunk, finalChunk]);
    if (plaintext.length < CFG2_HEADER_BYTES || plaintext.length > 32768) {
      throw new Error("invalid CFG2");
    }
    const schema = plaintext.readUInt16LE(4);
    const generation = plaintext.readUInt32LE(8);
    const payloadLength = plaintext.readUInt32LE(12);
    if (
        !plaintext.subarray(0, 4).equals(CFG2_MAGIC) ||
        (schema !== 6 && schema !== 7) || plaintext.readUInt16LE(6) !== 0 || generation !== 0 ||
        payloadLength !== plaintext.length - CFG2_HEADER_BYTES ||
        plaintext.readUInt32LE(16) !== crc32(plaintext.subarray(CFG2_HEADER_BYTES))
    ) {
      throw new Error("invalid CFG2");
    }
    return {
      bytes: encrypted.length,
      envelopeVersion: 1,
      generation,
      schema,
    };
  } finally {
    key.fill(0);
    plaintext?.fill(0);
    updateChunk?.fill(0);
    finalChunk?.fill(0);
  }
}

try {
  if (process.argv.length !== 3) throw new Error("one artifact path is required");
  const passphrase = readPassphrase();
  try {
    writeSync(1, `${JSON.stringify(verify(readEncrypted(process.argv[2]), passphrase))}\n`);
  } finally {
    passphrase.fill(0);
  }
} catch {
  writeSync(2, "configuration backup verification failed\n");
  process.exitCode = 1;
}
