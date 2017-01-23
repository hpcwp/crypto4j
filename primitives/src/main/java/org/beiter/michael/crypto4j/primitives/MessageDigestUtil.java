/*
 * #%L
 * This file is part of crypto4j, a library that provides a pluggable crypto
 * abstraction. It is part of a module that contains cryptographic primitives.
 * %%
 * Copyright (C) 2014 - 2017 Michael Beiter <michael@beiter.org>
 * %%
 * All rights reserved.
 * .
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the copyright holder nor the names of the
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 * .
 * .
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * #L%
 */
package org.beiter.michael.crypto4j.primitives;

import org.apache.commons.codec.CharEncoding;
import org.apache.commons.codec.binary.StringUtils;
import org.apache.commons.lang3.Validate;
import org.beiter.michael.array.Cleanser;
import org.beiter.michael.crypto4j.pool.PoolSpec;
import org.beiter.michael.crypto4j.pool.PoolSpecBuilder;
import org.beiter.michael.crypto4j.primitives.spec.MessageDigestSpec;

import java.security.NoSuchAlgorithmException;
import java.text.Normalizer;
import java.util.Arrays;

/**
 * This class provides utility methods for common message digest operations, namely on {@code String} and {@code byte[]}
 * payloads. The methods use object pools to potentially improve performance of the JCA operations required to obtain
 * the JCA objects.
 * <p>
 * See {@link MessageDigestFactory#getPooledInstance(MessageDigestSpec, PoolSpec)} for more information about how the
 * pooling mechanism works.
 */
public final class MessageDigestUtil {

    /**
     * A private constructor to prevent instantiation of this class
     */
    private MessageDigestUtil() {
    }

    /**
     * This method computes a message digest for the provided payload, using the provided message digest spec.
     * <p>
     * The method is using an internal pool to avoid the JCA bottlenecks and improve performance on repeated
     * invocations. See {@link MessageDigestFactory#getPooledInstance(MessageDigestSpec, PoolSpec)} for more information
     * about how the pooling mechanism works. This method will extract the pool configuration from the "additional
     * properties" of the provided {@link MessageDigestSpec} object (see {@link PoolSpec} for valid pool configuration
     * options). If no pool configuration can be extracted, then this method will use the defaults as specified in
     * {@link PoolSpec}.
     * <p>
     * Before the message digest is computed, the String is <strong>normalized</strong> using the
     * {@link java.text.Normalizer.Form#NFC} form. The method also assumes that the String is <strong>encoded as UTF-8
     * </strong>. If your application provides String in a different encoding, or requires a different form of
     * normalization, then use the {@link MessageDigestUtil#getBytes(byte[], MessageDigestSpec)} method instead.
     *
     * @param payload The data to compute the MD for
     * @param mdSpec  The MD spec to use
     * @return The message digest (hash) of the payload
     * @throws NullPointerException     When {@code payload} or {@code mdSpec} are {@code null}
     * @throws NoSuchAlgorithmException When the hash algorithm is not available
     * @throws FactoryException         When the configured provider is not registered in the security provider list,
     *                                  or when the pool operation fails
     * @throws IllegalStateException    When the pool is reset in parallel thread, while the current thread tries to
     *                                  access it and borrow an object from the pool
     */
    public static byte[] getBytes(final String payload, final MessageDigestSpec mdSpec)
            throws FactoryException, NoSuchAlgorithmException {

        Validate.notNull(payload, "The validated object 'payload' is null");
        Validate.notNull(mdSpec, "The validated object 'mdSpec' is null");

        // no need for defensive copies of String
        // not copying mdSpec, because the called method in this class makes a defensive copy

        return getBytes(payload, mdSpec, PoolSpecBuilder.build(mdSpec.getAdditionalProperties()));
    }

    /**
     * This method computes a message digest for the provided payload, using the provided message digest spec.
     * <p>
     * The method is using an internal pool to avoid the JCA bottlenecks and improve performance on repeated
     * invocations. See {@link MessageDigestFactory#getPooledInstance(MessageDigestSpec, PoolSpec)} for more information
     * about how the pooling mechanism works. This method will extract the pool configuration from the "additional
     * properties" of the provided {@link MessageDigestSpec} object (see {@link PoolSpec} for valid pool configuration
     * options). If no pool configuration can be extracted, then this method will use the defaults as specified in
     * {@link PoolSpec}.
     *
     * @param payload The data to compute the MD for
     * @param mdSpec  The MD spec to use
     * @return The message digest (hash) of the payload
     * @throws NullPointerException     When {@code payload} or {@code mdSpec} are {@code null}
     * @throws NoSuchAlgorithmException When the hash algorithm is not available
     * @throws FactoryException         When the configured provider is not registered in the security provider list,
     *                                  or when the pool operation fails
     * @throws IllegalStateException    When the pool is reset in parallel thread, while the current thread tries to
     *                                  access it and borrow an object from the pool
     */
    public static byte[] getBytes(final byte[] payload, final MessageDigestSpec mdSpec)
            throws FactoryException, NoSuchAlgorithmException {

        Validate.notNull(payload, "The validated object 'payload' is null");
        Validate.notNull(mdSpec, "The validated object 'mdSpec' is null");

        // not copying the payload, because the called method in this class makes a defensive copy
        // not copying mdSpec, because the called method in this class makes a defensive copy

        return getBytes(payload, mdSpec, PoolSpecBuilder.build(mdSpec.getAdditionalProperties()));
    }

    /**
     * This method computes a message digest for the provided payload, using the provided message digest spec and pool
     * configuration. See {@link MessageDigestFactory#getPooledInstance(MessageDigestSpec, PoolSpec)} for more
     * information about how the pooling mechanism works.
     * <p>
     * Before the message digest is computed, the String is <strong>normalized</strong> using the
     * {@link java.text.Normalizer.Form#NFC} form. The method also assumes that the String is <strong>encoded as UTF-8
     * </strong>. If your application provides String in a different encoding, or requires a different form of
     * normalization, then use the {@link MessageDigestUtil#getBytes(byte[], MessageDigestSpec, PoolSpec)} method
     * instead.
     *
     * @param payload  The data to compute the MD for
     * @param mdSpec   The MD spec to use
     * @param poolSpec The pool spec to use
     * @return The message digest (hash) of the payload
     * @throws NullPointerException     When {@code payload}, {@code poolSpec}, or {@code mdSpec} are {@code null}
     * @throws NoSuchAlgorithmException When the hash algorithm is not available
     * @throws FactoryException         When the configured provider is not registered in the security provider list,
     *                                  or when the pool operation fails
     * @throws IllegalStateException    When the pool is reset in parallel thread, while the current thread tries to
     *                                  access it and borrow an object from the pool
     */
    public static byte[] getBytes(final String payload, final MessageDigestSpec mdSpec, final PoolSpec poolSpec)
            throws FactoryException, NoSuchAlgorithmException {

        Validate.notNull(payload, "The validated object 'payload' is null");
        Validate.notNull(mdSpec, "The validated object 'mdSpec' is null");
        Validate.notNull(poolSpec, "The validated object 'poolSpec' is null");

        // no need for defensive copies of String
        // not copying mdSpec, because the called method in this class makes a defensive copy
        // not copying poolSpec, because the called method in this class makes a defensive copy

        // normalize the string
        // compiler will optimize the extra variable assignment
        final String inputString = Normalizer.normalize(payload, Normalizer.Form.NFC);
        final byte[] inputByte = StringUtils.getBytesUnchecked(inputString, CharEncoding.UTF_8);

        final byte[] result = getBytes(inputByte, mdSpec, poolSpec);

        // clear the normalized byte array
        Cleanser.wipe(inputByte);

        return result;
    }

    /**
     * This method computes a message digest for the provided payload, using the provided message digest spec and pool
     * configuration. See {@link MessageDigestFactory#getPooledInstance(MessageDigestSpec, PoolSpec)} for more
     * information about how the pooling mechanism works.
     *
     * @param payload  The data to compute the MD for
     * @param mdSpec   The MD spec to use
     * @param poolSpec The pool spec to use
     * @return The message digest (hash) of the payload
     * @throws NullPointerException     When {@code payload}, {@code poolSpec}, or {@code mdSpec} are {@code null}
     * @throws NoSuchAlgorithmException When the hash algorithm is not available
     * @throws FactoryException         When the configured provider is not registered in the security provider list,
     *                                  or when the pool operation fails
     * @throws IllegalStateException    When the pool is reset in parallel thread, while the current thread tries to
     *                                  access it and borrow an object from the pool
     */
    public static byte[] getBytes(final byte[] payload, final MessageDigestSpec mdSpec, final PoolSpec poolSpec)
            throws FactoryException, NoSuchAlgorithmException {

        Validate.notNull(payload, "The validated object 'payload' is null");
        Validate.notNull(mdSpec, "The validated object 'mdSpec' is null");
        Validate.notNull(poolSpec, "The validated object 'poolSpec' is null");

        // not copying mdSpec
        // not copying poolSpec

        // make a defensive copy of the payload
        final byte[] input = Arrays.copyOf(payload, payload.length);

        // get an MD instance
        final java.security.MessageDigest digest = MessageDigestFactory.getPooledInstance(mdSpec, poolSpec);

        // compute and finalize the hash
        digest.reset(); // reset the digest in case we got a digest from the pool that has not yet been reset
        final byte[] result = digest.digest(input);
        digest.reset(); // reset the digest because we are nice and want to be sure that future users get a fresh start

        // return the MD instance to the pool
        MessageDigestFactory.returnPooledInstance(mdSpec, digest);

        // clear the temp copy
        Cleanser.wipe(input);

        return result;
    }
}
