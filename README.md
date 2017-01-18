# crypto4j Library

The crypto4j library provides a simple and pluggable crypto abstraction library
for Java, including both cryptographic primitives and the artifacts defined in 
the JOSE standard.

This library separates the cryptographic primitives from the JOSE artifacts.

For the cryptographic primitives, the library uses the algorithms available
through JCA (JCE). It uses caching / pooling mechanisms to improve performance
when connecting to the JCA subsystem, which (depending on the integrating
application) can lead to significant performance improvements. This library's
methods return the standard JCA objects, and can be configured and extended
through the default JCA mechanisms.
		
~~The JOSE portion of the library allows custom extensions by either replacing
the provided JOSE artifact implementations with custom implementations, or by
adding new JOSE artifacts, for instance in form of additional algorithms, which
is particularly useful in case that the JOSE standard is updated or in case
custom extensions to the JOSE standard should be implemented.~~
		
Extension points in the library include:
- Custom implementations of cryptographic primitives via JCA, including new
  cryptographic algorithms not originally supported by JCA and the library
- ~~Custom implementations of JOSE artifacts and algorithms~~
- ~~Custom JOSE artifacts (e.g. new JOSE artifacts defined in future versions
  of the JOSE standard)~~

~~The library implements the JOSE standard as of [TODO-DATE] with the specifications
as referenced here:~~

- [JOSE: JSON Object Signing and Encryption working group](https://datatracker.ietf.org/wg/jose/charter/)
- [JOSE Documents Overview](https://datatracker.ietf.org/wg/jose/documents/)
- [JSON Web Algorithms (JWA), RFC 7518](https://datatracker.ietf.org/doc/rfc7518/)
- [JSON Web Key (JWK), RFC 7517](https://datatracker.ietf.org/doc/rfc7517/)
- [JSON Web Key (JWK) Thumbprint, RFC 7638](https://datatracker.ietf.org/doc/rfc7638/)
- [JSON Web Encryption (JWE), RFC 7516](https://datatracker.ietf.org/doc/rfc7516/)
- [JSON Web Signature (JWS), RFC 7515](https://datatracker.ietf.org/doc/rfc7515/)
- [JSON Web Signature (JWS) Unencoded Payload Option, RFC 7797](https://datatracker.ietf.org/doc/rfc7797/)

## Documentation

### Components and Usage

See [CONFIG.md](CONFIG.md) for an overview on available components, features,
and configuration options.

### Generated Documentation

TBD - no release yet (stay tuned for Maven Project Docs + Java Docs)

### More Documentation

- [Changelog](CHANGELOG.md)
- [Build instructions](BUILD.md)
- [Configuration and usage instructions](CONFIG.md)
- [Contribute](CONTRIBUTE.md) - Some pointers for contributing

## Useful Links

- [Mike's Blog](http://www.michael.beiter.org)
- [Project home](http://mbeiter.github.io/crypto4j/)
- [Source on GitHub](https://github.com/mbeiter/crypto4j)
- [GitHub Issue Tracker](https://github.com/mbeiter/crypto4j/issues)

## License

Copyright (c) 2014, Michael Beiter (<michael@beiter.org>)

All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the 
following conditions are met:

- Redistributions of source code must retain the above copyright notice, this list of conditions and the following 
  disclaimer.
- Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following 
  disclaimer in the documentation and/or other materials provided with the distribution.
- Neither the name of the copyright holder nor the names of the contributors may be used to endorse or promote products 
  derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, 
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, 
OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF 
ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
