# Cryptography Checklist

Applied by Module E and the Web3 review. Every item is a question about the code,
not a claim about a standard.

## Key management

- [ ] Are private keys ever stored in source, configuration, or documentation?
- [ ] Are keys generated with a cryptographically secure generator?
- [ ] Is key rotation defined and possible?
- [ ] Are keys separated per environment (development / staging / production)?
- [ ] Are hardware-backed stores (HSM, TPM, keychain) used for production keys?

## Algorithm selection

- [ ] Are MD5 or SHA-1 used for any security purpose? (Not for checksums.)
- [ ] Are custom or "homegrown" cryptographic constructions present?
- [ ] Are authenticated encryption modes used (AES-GCM, ChaCha20-Poly1305)?
- [ ] Is ECB mode used anywhere?
- [ ] Are deprecated curves or key sizes present (RSA < 2048, DH < 2048)?

## Randomness

- [ ] Are tokens, session identifiers, or nonces generated with a CSPRNG?
- [ ] Is `Math.random`, `random.random`, or `rand()` used for a security purpose?
- [ ] Are UUIDs used where unpredictable values are required? (UUIDv4 is not a secret.)

## Protocol and transport

- [ ] Is TLS verification enabled on every outbound connection?
- [ ] Are certificate pinning or custom CA bundles justified and documented?
- [ ] Are weak TLS versions or cipher suites enabled?

## Storage and handling

- [ ] Are passwords hashed with argon2, bcrypt, or scrypt (never MD5/SHA-1)?
- [ ] Are salts unique per password?
- [ ] Is sensitive data encrypted at rest, and where does the key live?
- [ ] Are secrets logged, cached, or included in error messages?

## Smart contract specifics

- [ ] Are private keys ever embedded in contract source or tests?
- [ ] Is the admin key a single EOA? Is a multisig or timelock used?
- [ ] Can ownership be renounced, and what happens then?
- [ ] Are external calls made before state updates (reentrancy)?
- [ ] Is the return value of `.call`, `.send`, `.transfer` checked?
- [ ] Are integer overflow/underflow protections in place (Solidity 0.8+ or SafeMath)?
- [ ] Is there an oracle dependency, and what happens if it fails?
- [ ] Are upgrade mechanisms present, and who controls them?
- [ ] Is the fee or tax mechanism documented and bounded?

## Reporting rules

1. Distinguish **weak algorithm use** from **weak key management** — they have
   different remediation.
2. A deprecated algorithm in a non-security context (a checksum, a cache key) is
   not a finding.
3. Never claim a cryptographic implementation is broken without demonstrating a
   concrete attack path. Say "requires manual review" instead.
