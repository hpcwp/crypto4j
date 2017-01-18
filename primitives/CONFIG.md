# Configuration Options

## Cryptographic Primitives - Message Digest (hashing)

### md.providerName

Set the JCA provider to be used when instantiating a MessageDigest hash. When
set to `null`, then the `MessageDigestFactory` traverses the list of security
`Providers` that are registered with the JCA, starting with the most preferred
`Provider`. In this case, a `MessageDigest` object encapsulating the
`MessageDigestSpi` implementation from the first `Provider` that supports the
configured message digest algorithm is returned.

Default: `null`

### md.algorithmName

Set the Message Digest (hash) algorithm to be used when instantiating a
`MessageDigest` hash. When set to `null`, then the default algorithm is used.

See `MessageDigestSpec.DEFAULT_MD_ALGORITHM_NAME` for important notes on the
default algorithm.

Default: `SHA-256`

## Cryptographic Primitives - Secure Random

### prng.providerName

Set the JCA provider to be used when instantiating a SecureRandom PRNG. When
set to `null`, then the `SecureRandomFactory` traverses the list of security
`Providers` that are registered with the JCA, starting with the most preferred
`Provider`. In this case, a `SecureRandom` object encapsulating the
`SecureRandomSpi` implementation from the first `Provider` that supports the
configured PRNG algorithm is returned.

Default: `null`

### prng.algorithmName

Set the Random Number Generator (RNG) algorithm to be used when instantiating
a `SecureRandom` PRNG. When set to `null`, then the platform-default PRNG
algorithm (as configured in the JCA subsystem) is used.

Default: `null`
