# Cryptography Utils Java

![Small sharp crypto](docs/images/banner.png)

[![Apache 2.0 License](https://img.shields.io/badge/License-Apache_2.0-blue)](LICENSE) [![Java 25](https://img.shields.io/badge/Java-25-ED8B00?logo=openjdk&logoColor=white)](pom.xml) [![CI](https://github.com/wallaceespindola/cryptography-utils-java/actions/workflows/ci.yml/badge.svg)](https://github.com/wallaceespindola/cryptography-utils-java/actions/workflows/ci.yml)

The idea: most applications need the same handful of cryptographic operations, and most of the ways to write them are wrong. This library is a few small static helpers over the JDK that make the safe choice the only choice. There are no dependencies, no factories and no configuration. If you want a different algorithm, you read about 40 lines of code and copy what you need.

It started as a 2021 sample with AES-CBC, unauthenticated RSA and a bcrypt dependency. It was rewritten for Java 25 and everything that was not safe to copy was removed.

## What to use when

| You need to | Use | Notes |
| --- | --- | --- |
| Encrypt data with a key you hold | `AesGcm` | AES-256-GCM, random 12-byte IV per call, output is `IV + ciphertext + tag` |
| Store a user password | `PasswordHasher` | PBKDF2-HMAC-SHA256, 600,000 iterations, random salt, constant-time compare |
| Fingerprint data | `Digests.sha256`, `Digests.sha3_256` | Not for passwords |
| Authenticate a message with a shared secret | `Digests.hmacSha256` | Verify with `hmacSha256Matches`, never `Arrays.equals` |
| Prove who sent something | `Signatures` | Ed25519, 64-byte signatures, standard JCA keys |
| Get several keys from one secret | `Hkdf` | HKDF-SHA256 through the JDK 25 `KDF` API |
| Make a session id, API key or reset token | `Tokens` | 256 random bits as URL-safe Base64 |
| Convert bytes to text | `Codec` | Base64, URL-safe Base64 and hex |

## Usage

Add the module to your build with `mvn install`, then depend on `com.wallaceespindola:crypto-utils`. Everything lives in `com.wallaceespindola.crypto`.

Encrypt and decrypt, with optional associated data that is authenticated but not encrypted:

```java
SecretKey key = AesGcm.newKey();
byte[] sealed = AesGcm.encrypt(key, "hello".getBytes(StandardCharsets.UTF_8), aad);
byte[] plain = AesGcm.decrypt(key, sealed, aad); // CryptoException if anything was changed
```

Hash and verify a password:

```java
String stored = PasswordHasher.hash(password);   // pbkdf2-sha256$600000$salt$hash
boolean ok = PasswordHasher.verify(password, stored);
```

The iteration count is stored in the string, so you can raise it later and old hashes keep verifying.

Sign and verify:

```java
KeyPair pair = Signatures.newKeyPair();
byte[] sig = Signatures.sign(pair.getPrivate(), message);
boolean valid = Signatures.verify(pair.getPublic(), message, sig);
```

MAC, key derivation and tokens:

```java
byte[] mac = Digests.hmacSha256(key, data);
boolean same = Digests.hmacSha256Matches(key, data, receivedMac);

byte[] okm = Hkdf.derive(sharedSecret, salt, "session-v1".getBytes(StandardCharsets.UTF_8), 32);
SecretKey sessionKey = AesGcm.keyFrom(okm);

String token = Tokens.random();        // 43 characters
String hex = Codec.hex(Digests.sha256(data));
```

## What was removed, and why

- **AES-CBC with PKCS5 padding.** No integrity check, so ciphertext can be changed undetected and padding oracles apply. Replaced by AES-GCM.
- **IV handed in by the caller.** Invites reuse. GCM breaks badly when an IV repeats, so the IV is now generated inside `encrypt` and never exposed.
- **`Cipher.getInstance("RSA")`.** That resolves to RSA/ECB/PKCS1Padding. RSA encryption with a private key is also not encryption, since anyone with the public key can read it. Removed, use `AesGcm` for data and `Signatures` for proof of origin.
- **Salted plain SHA-256 for passwords.** Fast hashes are cheap to brute force. Passwords now go through PBKDF2 only.
- **The jBCrypt dependency.** Unmaintained, and PBKDF2 is in the JDK. The project has no runtime dependencies now.
- **JCEKS key store helper.** Weak password-based protection and a wrapper around one JDK call. Use PKCS12 directly if you need a key store.
- **Platform default charset.** The old helpers called `getBytes()` on strings. The new API takes bytes, so encoding is your explicit choice.
- **RSA SHA256withRSA signatures.** Replaced by Ed25519, which has no parameters to get wrong.

## Build

Needs JDK 25 and Maven.

```bash
make build   # mvn verify: tests plus a JaCoCo gate at 80% line coverage
make test
```

The tests include published vectors for SHA-256, SHA3-256, HMAC-SHA256 (RFC 4231) and HKDF (RFC 5869).

## Limits

- Keys are passed in memory as `SecretKey` and `byte[]`. Storage and rotation are your job, ideally with a KMS or HSM.
- Not FIPS-validated and not audited. It is a thin layer over the JDK providers, which is where the real work happens.
- `AesGcm` is safe for a very large number of messages per key because IVs are random, but rotate keys long before about 2^32 messages.

## Support

If you find this project helpful, please consider:

[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-support%20my%20work-FFDD00?style=flat&labelColor=101010&logo=buy-me-a-coffee&logoColor=white)](https://www.buymeacoffee.com/wallace.espindola) [![Star on GitHub](https://img.shields.io/badge/Star%20on%20GitHub-cryptography-utils-java-181717?style=flat&logo=github)](https://github.com/wallaceespindola/cryptography-utils-java)

[![GitHub stars](https://img.shields.io/github/stars/wallaceespindola/cryptography-utils-java?style=social)](https://github.com/wallaceespindola/cryptography-utils-java/stargazers) [![GitHub forks](https://img.shields.io/github/forks/wallaceespindola/cryptography-utils-java?style=social)](https://github.com/wallaceespindola/cryptography-utils-java/network/members) [![GitHub watchers](https://img.shields.io/github/watchers/wallaceespindola/cryptography-utils-java?style=social)](https://github.com/wallaceespindola/cryptography-utils-java/watchers) [![GitHub issues](https://img.shields.io/github/issues/wallaceespindola/cryptography-utils-java)](https://github.com/wallaceespindola/cryptography-utils-java/issues) [![GitHub last commit](https://img.shields.io/github/last-commit/wallaceespindola/cryptography-utils-java)](https://github.com/wallaceespindola/cryptography-utils-java/commits/master)

Star the repo on GitHub if it helps your project. It motivates me a lot!

## Author

Wallace Espindola, Solution Architect

- Email: <wallace.espindola@gmail.com>
- LinkedIn: <https://www.linkedin.com/in/wallaceespindola/>
- GitHub: <https://github.com/wallaceespindola/>
- Twitter/X: [@wsespindola](https://x.com/wsespindola)
- Substack: [Code & Coffee by Wallace Espindola](https://wallaceespindola.substack.com)
- Medium: <https://medium.com/@wallaceespindola>
- Dev.to: <https://dev.to/wallaceespindola>
- DZone: <https://dzone.com/users/1254611/wallacese.html>
- Speaker Deck: <https://speakerdeck.com/wallacese>
- Speaker profile: <https://sessionize.com/wallace-espindola/>
- Company: [www.wtechitsolutions.com](http://www.wtechitsolutions.com)
- Buy Me a Coffee: <https://www.buymeacoffee.com/wallace.espindola>

## License

- This project is released under the Apache 2.0 License.
- See the [LICENSE](LICENSE) file for details.
- Copyright © 2026 [Wallace Espindola](https://github.com/wallaceespindola/).
