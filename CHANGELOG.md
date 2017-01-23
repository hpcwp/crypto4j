# crypto4j Library Change Log

## 1.1

#### Enhancements

- Improved handling of confidential data in `MessageDigestUtil` (fixes #1)

#### Defects

- Call `reset()` on the JCA `MessageDigest` object to prevent digest corruption (fixes #2)

## 1.0

Initial release with support for:

- Pools
- Pooled SecureRandom artifacts
- Pooled MessageDigest artifacts
