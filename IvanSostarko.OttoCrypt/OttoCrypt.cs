using System;
using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Sodium;

namespace IvanSostarko.OttoCrypt
{
    public static class Constants
    {
        public static readonly byte[] MAGIC = Encoding.ASCII.GetBytes("OTTO1"); // 5 bytes
        public const byte ALGO_ID = 0xA1;
        public const byte KDF_PASSWORD = 0x01;
        public const byte KDF_RAWKEY   = 0x02;
        public const byte KDF_X25519   = 0x03;
        public const byte FLAG_CHUNKED = 0x01;

        // libsodium MODERATE defaults (bytes)
        public const long OPSLIMIT_MODERATE = 3;
        public const int  MEMLIMIT_MODERATE = 268435456; // 256 MiB
    }

    public sealed class Options
    {
        public string? Password { get; set; }
        public string? RecipientPublic { get; set; } // base64/hex/raw accepted
        public string? SenderSecret { get; set; }    // base64/hex/raw accepted
        public string? RawKey { get; set; }          // base64/hex/raw accepted
    }

    public static class KeyUtils
    {
        public static byte[] DecodeKey(string? s)
        {
            if (s == null) return Array.Empty<byte>();
            s = s.Trim();
            // hex?
            if (System.Text.RegularExpressions.Regex.IsMatch(s, "^[0-9a-fA-F]+$") && s.Length % 2 == 0)
            {
                try { return Convert.FromHexString(s); } catch { }
            }
            // base64?
            try
            {
                var b = Convert.FromBase64String(s);
                if (b.Length > 0) return b;
            }
            catch { }
            // utf8 fallback
            return Encoding.UTF8.GetBytes(s);
        }

        public static void WriteBe16(Stream s, ushort v)
        {
            Span<byte> b = stackalloc byte[2];
            BinaryPrimitives.WriteUInt16BigEndian(b, v);
            s.Write(b);
        }

        public static void WriteBe32(Stream s, uint v)
        {
            Span<byte> b = stackalloc byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(b, v);
            s.Write(b);
        }

        public static uint ReadBe32(ReadOnlySpan<byte> b) => BinaryPrimitives.ReadUInt32BigEndian(b);
    }

    public static class HKDF
    {
        public static byte[] Derive(byte[] ikm, int length, byte[] info, byte[] salt)
        {
            using var hmac = new HMACSHA256(salt.Length == 0 ? new byte[32] : salt);
            var prk = hmac.ComputeHash(ikm);
            using var hmac2 = new HMACSHA256(prk);
            var hashLen = 32;
            var n = (int)Math.Ceiling((double)length / hashLen);
            var t = Array.Empty<byte>();
            using var ms = new MemoryStream();
            for (int i = 1; i <= n; i++)
            {
                var input = new byte[t.Length + info.Length + 1];
                Buffer.BlockCopy(t, 0, input, 0, t.Length);
                Buffer.BlockCopy(info, 0, input, t.Length, info.Length);
                input[^1] = (byte)i;
                t = hmac2.ComputeHash(input);
                ms.Write(t, 0, t.Length);
            }
            var okm = ms.ToArray();
            Array.Resize(ref okm, length);
            CryptographicOperations.ZeroMemory(prk);
            return okm;
        }
    }

    public static class KeyExchange
    {
        /// <summary>Generate an X25519 keypair (secret/public).</summary>
        public static (byte[] Secret, byte[] Public) GenerateKeypair()
        {
            var secret = SodiumCore.GetRandomBytes(32);
            var pub = ScalarMult.Base(secret);
            return (secret, pub);
        }

        /// <summary>Compute a raw ECDH shared secret: scalarmult(secret, peerPublic).</summary>
        public static byte[] DeriveSharedSecret(byte[] mySecret, byte[] theirPublic)
        {
            return ScalarMult.Mult(mySecret, theirPublic);
        }

        /// <summary>Derive a 32-byte session key from a shared secret using HKDF-SHA256.</summary>
        public static byte[] DeriveSessionKey(byte[] shared, byte[] salt, string context = "OTTO-X25519-SESSION")
        {
            return HKDF.Derive(shared, 32, Encoding.ASCII.GetBytes(context), salt);
        }
    }

    public sealed class OttoCrypt
    {
        private readonly int _chunkSize;

        public OttoCrypt(int chunkSize = 1024 * 1024)
        {
            _chunkSize = chunkSize;
        }

        // ===== Strings =====
        public (byte[] CipherAndTag, byte[] Header) EncryptString(byte[] plaintext, Options options)
        {
            var ctx = InitContext(options, chunked: false);
            var nonce = ChunkNonce(ctx.NonceKey, 0);
            var (cipher, tag) = AesGcmEncrypt(plaintext, ctx.EncKey, nonce, ctx.Header);
            var result = new byte[cipher.Length + tag.Length];
            Buffer.BlockCopy(cipher, 0, result, 0, cipher.Length);
            Buffer.BlockCopy(tag, 0, result, cipher.Length, tag.Length);
            Zero(ctx.MasterKey);
            return (result, ctx.Header);
        }

        public byte[] DecryptString(byte[] cipherAndTag, byte[] header, Options options)
        {
            if (cipherAndTag.Length < 16) throw new ArgumentException("ciphertext too short");
            var ctx = InitContextForDecryption(header, options);
            var cipher = cipherAndTag.AsSpan(0, cipherAndTag.Length - 16).ToArray();
            var tag = cipherAndTag.AsSpan(cipherAndTag.Length - 16, 16).ToArray();
            var nonce = ChunkNonce(ctx.NonceKey, 0);
            var plain = AesGcmDecrypt(cipher, tag, ctx.EncKey, nonce, ctx.AAD);
            Zero(ctx.MasterKey);
            return plain;
        }

        // ===== Files (streaming) =====
        public void EncryptFile(string inPath, string outPath, Options options)
        {
            var ctx = InitContext(options, chunked: true);
            using var fin = File.OpenRead(inPath);
            using var fout = File.Create(outPath);

            // write header
            fout.Write(ctx.Header, 0, ctx.Header.Length);

            var buf = new byte[_chunkSize];
            long counter = 0;
            int read;
            while ((read = fin.Read(buf, 0, buf.Length)) > 0)
            {
                var chunk = new byte[read];
                Buffer.BlockCopy(buf, 0, chunk, 0, read);
                var nonce = ChunkNonce(ctx.NonceKey, counter);
                var (cipher, tag) = AesGcmEncrypt(chunk, ctx.EncKey, nonce, ctx.Header);
                KeyUtils.WriteBe32(fout, (uint)cipher.Length);
                fout.Write(cipher, 0, cipher.Length);
                fout.Write(tag, 0, tag.Length);
                counter++;
            }

            Zero(ctx.MasterKey);
        }

        public void DecryptFile(string inPath, string outPath, Options options)
        {
            using var fin = File.OpenRead(inPath);
            // read header
            var header = ReadHeader(fin);
            var ctx = InitContextForDecryption(header, options);

            using var fout = File.Create(outPath);

            long counter = 0;
            var lenBuf = new byte[4];
            while (true)
            {
                var rlen = fin.Read(lenBuf, 0, 4);
                if (rlen == 0) break;
                if (rlen < 4) throw new InvalidOperationException("truncated chunk length");
                var clen = KeyUtils.ReadBe32(lenBuf);
                if (clen == 0) break;
                var cipher = new byte[clen];
                var rc = fin.Read(cipher, 0, cipher.Length);
                if (rc != cipher.Length) throw new InvalidOperationException("truncated cipher");
                var tag = new byte[16];
                var rt = fin.Read(tag, 0, 16);
                if (rt != 16) throw new InvalidOperationException("missing tag");
                var nonce = ChunkNonce(ctx.NonceKey, counter);
                var plain = AesGcmDecrypt(cipher, tag, ctx.EncKey, nonce, ctx.AAD);
                fout.Write(plain, 0, plain.Length);
                counter++;
            }

            Zero(ctx.MasterKey);
        }

        // ===== Internals =====

        private static byte[] ReadHeader(Stream s)
        {
            Span<byte> fixedHdr = stackalloc byte[11];
            if (s.Read(fixedHdr) != 11) throw new InvalidOperationException("bad header");
            if (!fixedHdr.Slice(0, 5).SequenceEqual(Constants.MAGIC)) throw new InvalidOperationException("bad magic");
            if (fixedHdr[5] != Constants.ALGO_ID) throw new InvalidOperationException("unsupported algo");
            var hlen = BinaryPrimitives.ReadUInt16BigEndian(fixedHdr.Slice(9, 2));
            var varPart = new byte[hlen];
            var r = s.Read(varPart, 0, varPart.Length);
            if (r != hlen) throw new InvalidOperationException("truncated header");
            var header = new byte[11 + hlen];
            fixedHdr.CopyTo(header);
            Buffer.BlockCopy(varPart, 0, header, 11, hlen);
            return header;
        }

        private static byte[] ChunkNonce(byte[] nonceKey, long counter)
        {
            Span<byte> ctr8 = stackalloc byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(ctr8, (ulong)counter);
            var info = Concat(Encoding.ASCII.GetBytes("OTTO-CHUNK-NONCE"), ctr8.ToArray());
            return HKDF.Derive(nonceKey, 12, info, Array.Empty<byte>());
        }

        private (byte[] Cipher, byte[] Tag) AesGcmEncrypt(byte[] plain, byte[] key, byte[] nonce, byte[] aad)
        {
            var cipher = new byte[plain.Length];
            var tag = new byte[16];
            using var gcm = new AesGcm(key, 16);
            gcm.Encrypt(nonce, plain, cipher, tag, aad);
            return (cipher, tag);
        }

        private byte[] AesGcmDecrypt(byte[] cipher, byte[] tag, byte[] key, byte[] nonce, byte[] aad)
        {
            var plain = new byte[cipher.Length];
            using var gcm = new AesGcm(key, 16);
            gcm.Decrypt(nonce, cipher, tag, plain, aad);
            return plain;
        }

        private static byte[] Concat(byte[] a, byte[] b)
        {
            var r = new byte[a.Length + b.Length];
            Buffer.BlockCopy(a, 0, r, 0, a.Length);
            Buffer.BlockCopy(b, 0, r, a.Length, b.Length);
            return r;
        }

        private static void Zero(byte[]? b)
        {
            if (b == null) return;
            CryptographicOperations.ZeroMemory(b);
        }

        private record Ctx(byte[] Header, byte[] AAD, byte[] EncKey, byte[] NonceKey, byte[] MasterKey);

        private Ctx InitContext(Options options, bool chunked)
        {
            var fileSalt = RandomNumberGenerator.GetBytes(16);
            var algoId = new byte[] { Constants.ALGO_ID };
            var flags = new byte[] { chunked ? Constants.FLAG_CHUNKED : (byte)0 };
            var reserved = new byte[] { 0x00 };

            byte kdfId;
            var headerExtra = new MemoryStream();
            byte[] master;

            if (!string.IsNullOrEmpty(options.Password))
            {
                kdfId = Constants.KDF_PASSWORD;
                var pwSalt = RandomNumberGenerator.GetBytes(16);
                var opslimit = Constants.OPSLIMIT_MODERATE;
                var memlimit = Constants.MEMLIMIT_MODERATE;
                master = PasswordHash.ArgonHashBinary(
                    Encoding.UTF8.GetBytes(options.Password!),
                    pwSalt,
                    opslimit,
                    memlimit,
                    PasswordHash.ArgonAlgorithm.Argon_2ID13,
                    32);

                headerExtra.Write(pwSalt);
                KeyUtils.WriteBe32(headerExtra, (uint)opslimit);
                KeyUtils.WriteBe32(headerExtra, (uint)(memlimit / 1024)); // KiB
            }
            else if (!string.IsNullOrEmpty(options.RawKey))
            {
                kdfId = Constants.KDF_RAWKEY;
                master = KeyUtils.DecodeKey(options.RawKey!);
                if (master.Length != 32) throw new ArgumentException("raw_key must be 32 bytes");
            }
            else if (!string.IsNullOrEmpty(options.RecipientPublic))
            {
                kdfId = Constants.KDF_X25519;
                var rcpt = KeyUtils.DecodeKey(options.RecipientPublic!);
                if (rcpt.Length != 32) throw new ArgumentException("recipient_public invalid length");
                var ephSk = SodiumCore.GetRandomBytes(32);
                var ephPk = ScalarMult.Base(ephSk);
                var shared = ScalarMult.Mult(ephSk, rcpt);
                master = HKDF.Derive(shared, 32, Encoding.ASCII.GetBytes("OTTO-E2E-MASTER"), fileSalt);
                headerExtra.Write(ephPk);
                Zero(ephSk);
                Zero(shared);
            }
            else
            {
                throw new ArgumentException("Provide one of: Password, RawKey, RecipientPublic");
            }

            var encKey = HKDF.Derive(master, 32, Encoding.ASCII.GetBytes("OTTO-ENC-KEY"), fileSalt);
            var nonceKey = HKDF.Derive(master, 32, Encoding.ASCII.GetBytes("OTTO-NONCE-KEY"), fileSalt);

            var varPart = new MemoryStream();
            varPart.Write(fileSalt);
            varPart.Write(headerExtra.ToArray());
            var hvar = varPart.ToArray();

            var header = new MemoryStream();
            header.Write(Constants.MAGIC);
            header.Write(algoId);
            header.Write(new byte[] { kdfId });
            header.Write(flags);
            header.Write(reserved);
            KeyUtils.WriteBe16(header, (ushort)hvar.Length);
            header.Write(hvar);
            var headerBytes = header.ToArray();

            return new Ctx(headerBytes, headerBytes, encKey, nonceKey, master);
        }

        private Ctx InitContextForDecryption(byte[] header, Options options)
        {
            if (header.Length < 11) throw new ArgumentException("header too short");
            if (!header.AsSpan(0, 5).SequenceEqual(Constants.MAGIC)) throw new ArgumentException("bad magic");
            if (header[5] != Constants.ALGO_ID) throw new ArgumentException("unsupported algo");

            var kdf = header[6];
            var hlen = BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(9, 2));
            var varPart = header.AsSpan(11, hlen);
            int off = 0;
            var fileSalt = varPart.Slice(off, 16).ToArray(); off += 16;

            byte[] master;
            if (kdf == Constants.KDF_PASSWORD)
            {
                var pwSalt = varPart.Slice(off, 16).ToArray(); off += 16;
                var opslimit = KeyUtils.ReadBe32(varPart.Slice(off, 4)); off += 4;
                var memKiB   = KeyUtils.ReadBe32(varPart.Slice(off, 4)); off += 4;
                var memlimit = (int)memKiB * 1024;

                if (string.IsNullOrEmpty(options.Password)) throw new ArgumentException("Password required");
                master = PasswordHash.ArgonHashBinary(
                    Encoding.UTF8.GetBytes(options.Password!),
                    pwSalt,
                    opslimit,
                    memlimit,
                    PasswordHash.ArgonAlgorithm.Argon_2ID13,
                    32);
            }
            else if (kdf == Constants.KDF_RAWKEY)
            {
                var rk = KeyUtils.DecodeKey(options.RawKey);
                if (rk.Length != 32) throw new ArgumentException("raw_key (32 bytes) required");
                master = rk;
            }
            else if (kdf == Constants.KDF_X25519)
            {
                var ephPk = varPart.Slice(off, 32).ToArray(); off += 32;
                var sk = KeyUtils.DecodeKey(options.SenderSecret);
                if (sk.Length != 32) throw new ArgumentException("sender_secret invalid length");
                var shared = ScalarMult.Mult(sk, ephPk);
                master = HKDF.Derive(shared, 32, Encoding.ASCII.GetBytes("OTTO-E2E-MASTER"), fileSalt);
                Zero(shared);
            }
            else
            {
                throw new ArgumentException("Unknown KDF");
            }

            var encKey = HKDF.Derive(master, 32, Encoding.ASCII.GetBytes("OTTO-ENC-KEY"), fileSalt);
            var nonceKey = HKDF.Derive(master, 32, Encoding.ASCII.GetBytes("OTTO-NONCE-KEY"), fileSalt);
            return new Ctx(header.AsSpan(0, 11 + hlen).ToArray(), header.AsSpan(0, 11 + hlen).ToArray(), encKey, nonceKey, master);
        }
    }
}
