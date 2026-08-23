import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createCipheriv, pbkdf2Sync } from "node:crypto";
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import test from "node:test";

const SCRIPT = fileURLToPath(new URL("./config_backup_verify.mjs", import.meta.url));
const FIXTURE = JSON.parse(readFileSync(
  fileURLToPath(new URL("../mock_server/test/fixtures/config-envelope-v6.json", import.meta.url)),
  "utf8",
));
const PASSPHRASE = FIXTURE.passphrase;
const PLAINTEXT = Buffer.from(FIXTURE.plaintextHex, "hex");
const ENCRYPTED = Buffer.from(FIXTURE.smscfgHex, "hex");

function encryptedBackup({ plaintext = PLAINTEXT, authenticateHeader = true, changeHeader } = {}) {
  const header = Buffer.alloc(44);
  header.write("SMSCFG01", 0, 8, "ascii");
  header.writeUInt16LE(1, 8);
  header[10] = 1;
  header[11] = 1;
  header.writeUInt32LE(210000, 12);
  Buffer.from(Array.from({ length: 16 }, (_, index) => index)).copy(header, 16);
  Buffer.from(Array.from({ length: 12 }, (_, index) => index + 16)).copy(header, 32);
  changeHeader?.(header);
  const key = pbkdf2Sync(PASSPHRASE, header.subarray(16, 32), 210000, 32, "sha256");
  const cipher = createCipheriv("aes-256-gcm", key, header.subarray(32, 44));
  if (authenticateHeader) cipher.setAAD(header);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([header, ciphertext, cipher.getAuthTag()]);
}

function invoke(artifact, passphrase = PASSPHRASE) {
  const directory = mkdtempSync(join(tmpdir(), "config-backup-verify-"));
  const path = join(directory, "backup.smscfg");
  writeFileSync(path, artifact, { mode: 0o600 });
  const before = readdirSync(directory);
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [SCRIPT, path], { cwd: directory });
    const stdout = [];
    const stderr = [];
    child.stdout.on("data", (chunk) => stdout.push(chunk));
    child.stderr.on("data", (chunk) => stderr.push(chunk));
    child.on("error", reject);
    const timeout = setTimeout(() => child.kill(), 5000);
    child.on("close", (status) => {
      clearTimeout(timeout);
      const result = {
        filesUnchanged: JSON.stringify(readdirSync(directory)) === JSON.stringify(before),
        status,
        stderr: Buffer.concat(stderr).toString("utf8"),
        stdout: Buffer.concat(stdout).toString("utf8"),
      };
      rmSync(directory, { recursive: true });
      resolve(result);
    });
    child.stdin.end(Buffer.isBuffer(passphrase) ? passphrase : Buffer.from(passphrase));
  });
}

test("accepts the existing v6 portable backup fixture and emits only sanitized metadata", async () => {
  const result = await invoke(ENCRYPTED);

  assert.equal(result.status, 0, result.stderr);
  assert.ok(result.stdout, JSON.stringify(result));
  assert.deepEqual(JSON.parse(result.stdout), {
    bytes: 860,
    envelopeVersion: 1,
    generation: 0,
    schema: 6,
  });
  assert.equal(result.filesUnchanged, true);
  assert.doesNotMatch(result.stdout + result.stderr, /correct horse battery staple|smtp-secret/);
});

test("rejects authentication and CFG2 boundary failures", async (t) => {
  const changedPlaintext = (change) => {
    const value = Buffer.from(PLAINTEXT);
    change(value);
    return encryptedBackup({ plaintext: value });
  };
  const cases = [
    ["wrong passphrase", ENCRYPTED, "wrong passphrase"],
    ["ciphertext tamper", (() => { const value = Buffer.from(ENCRYPTED); value[44] ^= 1; return value; })()],
    ["salt tamper", (() => { const value = Buffer.from(ENCRYPTED); value[16] ^= 1; return value; })()],
    ["IV tamper", (() => { const value = Buffer.from(ENCRYPTED); value[32] ^= 1; return value; })()],
    ["envelope magic", encryptedBackup({ changeHeader: (value) => { value[0] ^= 1; } })],
    ["high-bit envelope magic alias", encryptedBackup({ changeHeader: (value) => { value[0] = 0xd3; } })],
    ["envelope version", (() => { const value = Buffer.from(ENCRYPTED); value[8] = 2; return value; })()],
    ["KDF identifier", (() => { const value = Buffer.from(ENCRYPTED); value[10] = 2; return value; })()],
    ["cipher identifier", (() => { const value = Buffer.from(ENCRYPTED); value[11] = 2; return value; })()],
    ["iteration count", (() => { const value = Buffer.from(ENCRYPTED); value[12] ^= 1; return value; })()],
    ["header not used as AAD", encryptedBackup({ authenticateHeader: false })],
    ["authentication tag", (() => { const value = Buffer.from(ENCRYPTED); value[value.length - 1] ^= 1; return value; })()],
    ["truncated tag", ENCRYPTED.subarray(0, ENCRYPTED.length - 1)],
    ["envelope too short", Buffer.alloc(79)],
    ["envelope too large", Buffer.alloc(32829)],
    ["CFG2 magic", changedPlaintext((value) => { value[0] ^= 1; })],
    ["high-bit CFG2 magic alias", changedPlaintext((value) => { value[0] = 0xc3; })],
    ["CFG2 schema", changedPlaintext((value) => value.writeUInt16LE(5, 4))],
    ["CFG2 flags", changedPlaintext((value) => value.writeUInt16LE(1, 6))],
    ["CFG2 generation", changedPlaintext((value) => value.writeUInt32LE(1, 8))],
    ["CFG2 payload length", changedPlaintext((value) => value.writeUInt32LE(781, 12))],
    ["CFG2 payload CRC", changedPlaintext((value) => { value[16] ^= 1; })],
    ["passphrase newline", ENCRYPTED, `${PASSPHRASE}\n`],
    ["invalid UTF-8 passphrase", ENCRYPTED, Buffer.from([0xc3, 0x28, ...Buffer.alloc(12)])],
    ["oversized passphrase", ENCRYPTED, Buffer.alloc(129, 0x78)],
  ];

  for (const [name, artifact, passphrase = PASSPHRASE] of cases) {
    await t.test(name, async () => {
      const result = await invoke(artifact, passphrase);
      assert.notEqual(result.status, 0);
      assert.equal(result.stdout, "");
      assert.equal(result.stderr, "configuration backup verification failed\n");
      assert.equal(result.filesUnchanged, true);
    });
  }
});
