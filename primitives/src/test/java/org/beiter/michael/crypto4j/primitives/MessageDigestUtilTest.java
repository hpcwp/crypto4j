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

import org.beiter.michael.crypto4j.pool.PoolSpec;
import org.beiter.michael.crypto4j.primitives.spec.MessageDigestSpec;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.Assert.assertThat;

public class MessageDigestUtilTest {

    /**
     * The logger object for this class
     */
    private static final Logger LOG = LoggerFactory.getLogger(MessageDigestUtilTest.class);

    // test strings that do not contain UTF-8 characters
    private static final HashMap<String, byte[]> SHA1_STRINGS = new HashMap<>();
    // test strings that contain UTF-8 characters
    private static final HashMap<String, byte[]> SHA256_STRINGS = new HashMap<>();
    // test strings that contain the same UTF-8 string in different normalizations
    private static final HashMap<String, byte[]> SHA256_UTF8_NORM_STRINGS = new HashMap<>();
    // random test byte[]
    private static final HashMap<byte[], byte[]> SHA1_BYTES = new HashMap<>();
    private static final HashMap<byte[], byte[]> SHA256_BYTES = new HashMap<>();

    /**
     * Test prep
     */
    @Before
    public void resetFactory() {

        // Reset the factory to ensure consistency between tests (even if we are not using the factory directly here).
        MessageDigestFactory.reset();

        // Initialize the test strings
        SHA1_STRINGS.clear();
        SHA1_STRINGS.put("abcd", new byte[]
                {-127, -2, -117, -2, -121, 87, 108, 62, -53, 34, 66, 111, -114, 87, -124, 115, -126, -111, 122, -49});
        SHA1_STRINGS.put("1234", new byte[]
                {113, 16, -19, -92, -48, -98, 6, 42, -91, -28, -93, -112, -80, -91, 114, -84, 13, 44, 2, 32});
        SHA1_STRINGS.put("!@#$", new byte[]
                {-40, 110, 29, 90, 52, -109, 115, -7, -81, -29, -30, 3, -111, -109, -59, 72, -80, -9, 4, 86});

        SHA256_STRINGS.clear();
        SHA256_STRINGS.put("\u00C4", new byte[]
                {47, -27, -54, 28, 26, 61, 80, -67, -110, -15, -45, -49, 109, -93, 76, -19, -38,
                        -66, 2, 2, 43, 42, 1, -125, -85, 11, -128, 90, -38, 111, 120, 122});
        SHA256_STRINGS.put("\u00E9", new byte[]
                {74, -103, 85, 126, 64, 51, -61, 83, -99, -30, -21, 101, 71, 32, 23, -54, -43,
                        -7, 85, 127, 122, 6, 37, -96, -97, 28, 63, 110, 43, -90, -100, 76});
        SHA256_STRINGS.put("!@#$", new byte[]
                {18, -106, -65, -76, 43, 36, 74, -91, -127, 30, 64, -104, 73, 115, 41, -13, -124,
                        92, -90, -93, 113, 92, 29, -88, 68, -47, -103, -102, -52, 92, -33, -35});

        SHA256_UTF8_NORM_STRINGS.clear();
        SHA256_UTF8_NORM_STRINGS.put("\u00C4", new byte[]
                {47, -27, -54, 28, 26, 61, 80, -67, -110, -15, -45, -49, 109, -93, 76, -19, -38,
                        -66, 2, 2, 43, 42, 1, -125, -85, 11, -128, 90, -38, 111, 120, 122});
        SHA256_UTF8_NORM_STRINGS.put("\u0041\u0308", SHA256_UTF8_NORM_STRINGS.get("\u00C4"));

        // Initialize the test bytes
        SHA1_BYTES.clear();
        SHA1_BYTES.put(new byte[]
                        {-44, 95, 37, 43, -29, 112, -72, 12, -14, 34, -99, 110, -14, -33, -2, 15, 26, 111, -22, -65},
                new byte[]
                        {-19, -118, 67, 92, -23, -65, 106, 57, 45, -102, -105, 24, -31, -40, -42, 5, -104, -92, -51, 3});
        SHA1_BYTES.put(new byte[]
                        {88, 52, 100, -124, 91, 115, 17, -52, 29, 81, 0, -92, 29, 72, 119, -97, -34, 55, -76, 91},
                new byte[]
                        {-88, -7, 66, -75, 40, 68, 72, -71, -20, -83, 6, 91, 126, 62, -88, 35, -117, 1, -85, 23});

        SHA256_BYTES.clear();
        SHA256_BYTES.put(new byte[]
                        {-90, -29, 21, 86, -108, 33, -39, -80, 98, -59, -61, -76, 2, 45, -109, 60, -61, 41, -19, 58},
                new byte[]
                        {-106, 61, -116, 36, -124, -96, 4, -20, -115, -30, 102, 101, -61, 87, -83, 65,
                                -86, -100, -68, -1, -81, -97, -33, 38, -127, 14, 3, 71, -40, 119, -10, 65});
        SHA256_BYTES.put(new byte[]
                        {-95, 12, 96, 44, -66, -10, -57, -90, 118, 8, -54, 108, 0, -19, 78, -103, 87, -6, 123, -74},
                new byte[]
                        {104, -84, -91, 84, -108, 15, -33, 81, -125, -65, 37, 111, -69, -56, 62, 77, -84,
                                -24, -60, 68, 31, -47, 29, 42, -37, -17, -104, 68, -88, -71, -25, -113});
    }

    /**
     * A set of test strings should yield specific hash results for different hash algorithms
     */
    @Test
    public void stringHashTest()
            throws FactoryException, NoSuchAlgorithmException {

        MessageDigestSpec mdSpec = new MessageDigestSpec();
        mdSpec.setAlgorithmName("SHA1");

        String error = "The computed hash does not match the expected value";
        for (Map.Entry<String, byte[]> entry : SHA1_STRINGS.entrySet()) {
            byte[] result = MessageDigestUtil.getBytes(entry.getKey(), mdSpec);
            assertThat(error, result, is(equalTo(entry.getValue())));
        }

        mdSpec.setAlgorithmName("SHA-256");
        for (Map.Entry<String, byte[]> entry : SHA256_STRINGS.entrySet()) {
            byte[] result = MessageDigestUtil.getBytes(entry.getKey(), mdSpec);
            assertThat(error, result, is(equalTo(entry.getValue())));
        }
    }

    /**
     * A set of test strings in different UTF-8 representations should all yield the same hash result, and this should
     * be reproducible for different hash algorithms
     */
    @Test
    public void stringNormalizationHashTest()
            throws FactoryException, NoSuchAlgorithmException {

        MessageDigestSpec mdSpec = new MessageDigestSpec();
        mdSpec.setAlgorithmName("SHA-256");

        String error = "The computed hash does not match the expected value";
        for (Map.Entry<String, byte[]> entry : SHA256_UTF8_NORM_STRINGS.entrySet()) {
            byte[] result = MessageDigestUtil.getBytes(entry.getKey(), mdSpec);
            assertThat(error, result, is(equalTo(entry.getValue())));
        }
    }

    /**
     * A set of test byte arrays yield specific hash results for different hash algorithms
     */
    @Test
    public void bytesHashTest()
            throws FactoryException, NoSuchAlgorithmException {


        MessageDigestSpec mdSpec = new MessageDigestSpec();
        mdSpec.setAlgorithmName("SHA1");

        String error = "The computed hash does not match the expected value";
        for (Map.Entry<byte[], byte[]> entry : SHA1_BYTES.entrySet()) {
            byte[] result = MessageDigestUtil.getBytes(entry.getKey(), mdSpec);
            assertThat(error, result, is(equalTo(entry.getValue())));
        }

        mdSpec.setAlgorithmName("SHA-256");
        for (Map.Entry<byte[], byte[]> entry : SHA256_BYTES.entrySet()) {
            byte[] result = MessageDigestUtil.getBytes(entry.getKey(), mdSpec);
            assertThat(error, result, is(equalTo(entry.getValue())));
        }
    }

    /**
     * A set of test strings should yield specific hash results for different hash algorithms (using an MD pool)
     */
    @Test
    public void stringPooledHashTest()
            throws FactoryException, NoSuchAlgorithmException {

        MessageDigestSpec mdSpec = new MessageDigestSpec();
        mdSpec.setAlgorithmName("SHA1");
        PoolSpec pSpec = new PoolSpec();

        String error = "The computed hash does not match the expected value";
        for (Map.Entry<String, byte[]> entry : SHA1_STRINGS.entrySet()) {
            byte[] result = MessageDigestUtil.getBytes(entry.getKey(), mdSpec, pSpec);
            assertThat(error, result, is(equalTo(entry.getValue())));
        }

        mdSpec.setAlgorithmName("SHA-256");
        for (Map.Entry<String, byte[]> entry : SHA256_STRINGS.entrySet()) {
            byte[] result = MessageDigestUtil.getBytes(entry.getKey(), mdSpec, pSpec);
            assertThat(error, result, is(equalTo(entry.getValue())));
        }
    }

    /**
     * A set of test strings in different UTF-8 representations should all yield the same hash result, and this should
     * be reproducible for different hash algorithms(using an MD pool)
     */
    @Test
    public void stringNormalizationPooledHashTest()
            throws FactoryException, NoSuchAlgorithmException {

        MessageDigestSpec mdSpec = new MessageDigestSpec();
        mdSpec.setAlgorithmName("SHA-256");
        PoolSpec pSpec = new PoolSpec();

        String error = "The computed hash does not match the expected value";
        for (Map.Entry<String, byte[]> entry : SHA256_UTF8_NORM_STRINGS.entrySet()) {
            byte[] result = MessageDigestUtil.getBytes(entry.getKey(), mdSpec, pSpec);
            assertThat(error, result, is(equalTo(entry.getValue())));
        }
    }

    /**
     * A set of test byte arrays yield specific hash results for different hash algorithms(using an MD pool)
     */
    @Test
    public void bytesPooledHashTest()
            throws FactoryException, NoSuchAlgorithmException {

        MessageDigestSpec mdSpec = new MessageDigestSpec();
        mdSpec.setAlgorithmName("SHA1");
        PoolSpec pSpec = new PoolSpec();

        String error = "The computed hash does not match the expected value";
        for (Map.Entry<byte[], byte[]> entry : SHA1_BYTES.entrySet()) {
            byte[] result = MessageDigestUtil.getBytes(entry.getKey(), mdSpec, pSpec);
            assertThat(error, result, is(equalTo(entry.getValue())));
        }

        mdSpec.setAlgorithmName("SHA-256");
        for (Map.Entry<byte[], byte[]> entry : SHA256_BYTES.entrySet()) {
            byte[] result = MessageDigestUtil.getBytes(entry.getKey(), mdSpec, pSpec);
            assertThat(error, result, is(equalTo(entry.getValue())));
        }
    }
}
