# OTTO Crypt for .NET (C#)


Implements the **OTTO-256-GCM-HKDF-SIV** construction, header, and streaming format. You can encrypt in Laravel and decrypt in C#, or the other way around.

> ⚠️ This is a custom composition built on standard primitives. Obtain an independent **cryptographic review** before production.

## Install

Add dependency for libsodium bindings (used for Argon2id + X25519):

```bash
dotnet add package Sodium.Core
```

Then add the project or source files to your solution.

## Quick start

```csharp
using IvanSostarko.OttoCrypt;

var otto = new OttoCrypt();

// Strings (single-shot)
var (cipher, header) = otto.EncryptString(System.Text.Encoding.UTF8.GetBytes("Hello"), new Options { Password = "P@ssw0rd!" });
var plain = otto.DecryptString(cipher, header, new Options { Password = "P@ssw0rd!" });
Console.WriteLine(System.Text.Encoding.UTF8.GetString(plain)); // Hello

// Files (streaming)
otto.EncryptFile("in.mp4", "in.mp4.otto", new Options { Password = "P@ssw0rd!" });
otto.DecryptFile("in.mp4.otto", "in.dec.mp4", new Options { Password = "P@ssw0rd!" });

// X25519 E2E
var kp = KeyExchange.GenerateKeypair();
otto.EncryptFile("photo.jpg", "photo.jpg.otto", new Options { RecipientPublic = Convert.ToBase64String(kp.Public) });
otto.DecryptFile("photo.jpg.otto", "photo.jpg", new Options { SenderSecret = Convert.ToBase64String(kp.Secret) });
```

## Algorithm (brief)

- **AEAD**: AES-256-GCM (`AesGcm`) with 16-byte tags.
- **Master key** from:
  - **Argon2id** (`libsodium crypto_pwhash`) with `opslimit` & `memlimit` serialized in header,
  - **Raw 32-byte key**, or
  - **X25519** ECDH (ephemeral sender public key in header).
- **HKDF(SHA-256)**:
  - `enc_key   = HKDF(master, 32, "OTTO-ENC-KEY",  file_salt)`
  - `nonce_key = HKDF(master, 32, "OTTO-NONCE-KEY", file_salt)`
- **Deterministic per-chunk nonces** (HKDF-SIV-style):
  - `nonce_i = HKDF(nonce_key, 12, "OTTO-CHUNK-NONCE" || counter64be, salt="")`
- **Associated Data** = entire header.
- **Streaming format** per chunk: `[len(4-be)] [ciphertext] [tag(16)]`.



MIT © 2025 Ivan Sostarko
