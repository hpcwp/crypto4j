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
package org.beiter.michael.crypto4j.primitives.performanceDemo;

import org.beiter.michael.crypto4j.pool.PoolSpec;
import org.beiter.michael.crypto4j.primitives.spec.SecureRandomSpec;
import org.beiter.michael.crypto4j.primitives.FactoryException;
import org.beiter.michael.crypto4j.primitives.SecureRandomFactory;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class SecureRandomDemo {

    /**
     * The logger object for this class
     */
    private static final Logger LOG = LoggerFactory.getLogger(SecureRandomDemo.class);

    /**
     * The library configuration
     */
    private SecureRandomSpec prngSpec;
    private PoolSpec poolSpec;

    @Before
    public void resetConfiguration() {

        // start with some default properties
        prngSpec = new SecureRandomSpec();
        poolSpec = new PoolSpec();

        // set additional properties
        // We set a specific algorithm to avoid looking up the default
        // (not needed for providers, but default algorithm lookup is expensive. Also, the SHA1PRNG is the cheapest
        // algorithm to use, because it removes any OS related issues (e.g. blocking random device) from the
        // performance equation).
        prngSpec.setProviderName(null);
        prngSpec.setAlgorithmName("SHA1PRNG");
    }

    /**
     * This test demos the performance of the traditional JCA access vs the singleton access.
     * <p>
     * <b>Disable logging to get meaningful results!</b>
     *
     * @throws FactoryException
     * @throws NoSuchAlgorithmException
     */
    @Test
    public void performanceTest()
            throws FactoryException, NoSuchAlgorithmException {

        final int executions = 5000;

        // test default new object creation
        long startTime = System.currentTimeMillis();
        for (int i = 0; i < executions; ++i) {
            SecureRandom prng = SecureRandomFactory.getInstance(prngSpec);
        }
        long stopTime = System.currentTimeMillis();
        long traditionalTime = stopTime - startTime;

        // test singleton
        startTime = System.currentTimeMillis();
        for (int i = 0; i < executions; ++i) {
            SecureRandom prng = SecureRandomFactory.getSingleton(prngSpec);
        }
        stopTime = System.currentTimeMillis();
        long singletonTime = stopTime - startTime;

        // test pool
        startTime = System.currentTimeMillis();
        for (int i = 0; i < executions; ++i) {
            SecureRandom prng = SecureRandomFactory.getPooledInstance(prngSpec, poolSpec);
            SecureRandomFactory.returnPooledInstance(prngSpec, prng);
        }
        stopTime = System.currentTimeMillis();
        long pooledTime = stopTime - startTime;

        LOG.info("Time (traditional JCA): " + traditionalTime + " ms");
        LOG.info("Time (singleton): " + singletonTime + " ms");
        LOG.info("Time (pooled): " + pooledTime + " ms");

        LOG.info(SecureRandomFactory.getPoolStats(prngSpec).toString());
    }
}
