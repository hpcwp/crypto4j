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
import java.security.MessageDigest;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.Assert.assertThat;

public class MessageDigestFactoryTest {

    /**
     * The logger object for this class
     */
    private static final Logger LOG = LoggerFactory.getLogger(MessageDigestFactoryTest.class);

    private static final String PROVIDER = "SUN";
    private static final String ALGORITHM_1 = "SHA-256";
    private static final String ALGORITHM_2 = "SHA-512";
    private static final int POOL_MAX_SIZE = 2;

    /**
     * Reset the factory to allow creating several instances of the underlying implementations.
     */
    @Before
    public void resetFactory() {

        MessageDigestFactory.reset();
    }

    ///////////////////////////////////////////////////////////////////////////
    // Basic Tests
    ///////////////////////////////////////////////////////////////////////////

    /**
     * A null spec should throw an exception
     */
    @Test(expected = NullPointerException.class)
    public void getNullSpecTest()
            throws FactoryException, NoSuchAlgorithmException {

        MessageDigestFactory.getInstance(null);
    }

    /**
     * An invalid (e.g. non-existing) algorithm name should throw an exception
     */
    @Test(expected = NoSuchAlgorithmException.class)
    public void getNonExistingImplementationTest()
            throws FactoryException, NoSuchAlgorithmException {

        MessageDigestSpec spec = new MessageDigestSpec();
        spec.setAlgorithmName("someGarbageName");

        MessageDigestFactory.getInstance(spec);
    }

    /**
     * An invalid (e.g. non-existing) provider name should throw an exception
     */
    @Test(expected = FactoryException.class)
    public void getInvalidImplementationTest()
            throws FactoryException, NoSuchAlgorithmException {

        MessageDigestSpec spec = new MessageDigestSpec();
        spec.setProviderName("someGarbageName");

        MessageDigestFactory.getInstance(spec);
    }

    ///////////////////////////////////////////////////////////////////////////
    // Advanced Tests
    ///////////////////////////////////////////////////////////////////////////

    /**
     * Retrieve a specific hash algorithm implementation, and assert that
     * the returned implementation equals the requested algorithm.
     */
    @Test
    public void getSpecificAlgorithmTest() {

        MessageDigestSpec spec = new MessageDigestSpec();
        spec.setAlgorithmName(ALGORITHM_1);

        MessageDigest messageDigest;
        try {
            messageDigest = MessageDigestFactory.getInstance(spec);
        } catch (FactoryException | NoSuchAlgorithmException e) {
            AssertionError ae = new AssertionError("Instantiation error");
            ae.initCause(e);
            throw ae;
        }

        String error = "The algorithm instantiated by the factory does not match the expected algorithm";
        assertThat(error, messageDigest.getAlgorithm(), is(equalTo(ALGORITHM_1)));
    }

    /**
     * Retrieve a specific MessageDigest provider implementation, and assert that
     * the returned implementation equals the requested provider.
     */
    @Test
    public void getSpecificProviderTest() {

        MessageDigestSpec spec = new MessageDigestSpec();
        spec.setProviderName(PROVIDER);

        MessageDigest messageDigest;
        try {
            messageDigest = MessageDigestFactory.getInstance(spec);
        } catch (FactoryException | NoSuchAlgorithmException e) {
            AssertionError ae = new AssertionError("Instantiation error");
            ae.initCause(e);
            throw ae;
        }

        String error = "The provider instantiated by the factory does not match the expected provider";
        assertThat(error, messageDigest.getProvider().getName(), is(equalTo(PROVIDER)));
    }

    /**
     * Retrieve two instances of {@code MessageDigest}, and assert that
     * the returned objects are two separate instances.
     */
    @Test
    public void twoInstancesAreDifferentTest() {

        MessageDigestSpec spec = new MessageDigestSpec();

        MessageDigest messageDigest1, messageDigest2;
        try {
            messageDigest1 = MessageDigestFactory.getInstance(spec);
            messageDigest2 = MessageDigestFactory.getInstance(spec);
        } catch (FactoryException | NoSuchAlgorithmException e) {
            AssertionError ae = new AssertionError("Instantiation error");
            ae.initCause(e);
            throw ae;
        }

        String error = "The factory returns a singleton instead of a new object";
        assertThat(error, messageDigest1, is(not(sameInstance(messageDigest2))));
    }

    /**
     * Retrieve two singleton instances of {@code MessageDigest}, and assert that the two returned objects are identical
     * (i.e. the factory returns a singleton).
     * <p>
     * Then, a regular (non-singleton) instance is retrieved, which are asserted to be different than the previously
     * retrieved objects.
     * <p>
     * Finally, the factory is reset, and another instance is retrieved. If the factory resets properly, the third
     * instance must be unequal to the first three instances.
     */
    @Test
    public void factoryReturnsSingletonTest() {

        MessageDigestSpec spec = new MessageDigestSpec();

        // test that two singletons retrieved from the factory are identical
        MessageDigest messageDigest1, messageDigest2;
        try {
            messageDigest1 = MessageDigestFactory.getSingleton(spec);
            messageDigest2 = MessageDigestFactory.getSingleton(spec);
        } catch (FactoryException | NoSuchAlgorithmException e) {
            AssertionError ae = new AssertionError("Instantiation error");
            ae.initCause(e);
            throw ae;
        }

        String error = "The factory does not return a singleton";
        assertThat(error, messageDigest1, is(sameInstance(messageDigest2)));

        // then test that a regular (non-singleton) instance is different
        MessageDigest messageDigest3;
        try {
            messageDigest3 = MessageDigestFactory.getInstance(spec);
        } catch (FactoryException | NoSuchAlgorithmException e) {
            AssertionError ae = new AssertionError("Instantiation error");
            ae.initCause(e);
            throw ae;
        }
        error = "The factory returns a singleton instead of a new object";
        assertThat(error, messageDigest1, is(not(sameInstance(messageDigest3))));
        assertThat(error, messageDigest2, is(not(sameInstance(messageDigest3))));

        // reset the factory
        MessageDigestFactory.reset();

        // now test that the factory return a new object (i.e. a new singleton)
        MessageDigest messageDigest4;
        try {
            messageDigest4 = MessageDigestFactory.getSingleton(spec);
        } catch (FactoryException | NoSuchAlgorithmException e) {
            AssertionError ae = new AssertionError("Instantiation error");
            ae.initCause(e);
            throw ae;
        }

        error = "The factory does not return a singleton, or does not reset properly";
        assertThat(error, messageDigest1, is(not(sameInstance(messageDigest4))));
        assertThat(error, messageDigest2, is(not(sameInstance(messageDigest4))));
        assertThat(error, messageDigest3, is(not(sameInstance(messageDigest4))));
    }

    ///////////////////////////////////////////////////////////////////////////
    // Pool Tests
    ///////////////////////////////////////////////////////////////////////////

    /**
     * Test that the pool factory method returns an instance
     */
    @Test
    public void factoryReturnsPooledInstanceTest() {

        MessageDigestSpec mdSpec = new MessageDigestSpec();
        PoolSpec poolSpec = new PoolSpec();

        MessageDigest messageDigest;
        try {
            messageDigest = MessageDigestFactory.getPooledInstance(mdSpec, poolSpec);
        } catch (FactoryException | NoSuchAlgorithmException e) {
            AssertionError ae = new AssertionError("Instantiation error");
            ae.initCause(e);
            throw ae;
        }

        String error = "The object returned by the pool is null";
        assertThat(error, messageDigest, is(notNullValue()));
        error = "The object returned by the pool has the wrong type";
        assertThat(error, messageDigest, is(instanceOf(MessageDigest.class)));

        MessageDigestFactory.returnPooledInstance(mdSpec, messageDigest);
    }

    /**
     * Test that the pool factory method returns two different instances
     * if called multiple times with the same pool properties
     */
    @Test
    public void factoryReturnsMultiplePooledInstancesTest() {

        MessageDigestSpec mdSpec = new MessageDigestSpec();
        PoolSpec poolSpec = new PoolSpec();
        poolSpec.setMaxTotal(POOL_MAX_SIZE);
        poolSpec.setMaxWaitMillis(0); // fail with an exception if no connections are available in the pool

        MessageDigest messageDigest1, messageDigest2;
        try {
            messageDigest1 = MessageDigestFactory.getPooledInstance(mdSpec, poolSpec);
            messageDigest2 = MessageDigestFactory.getPooledInstance(mdSpec, poolSpec);
        } catch (FactoryException | NoSuchAlgorithmException e) {
            AssertionError ae = new AssertionError("Instantiation error");
            ae.initCause(e);
            throw ae;
        }

        String error = "The first object returned by the pool is null";
        assertThat(error, messageDigest1, is(notNullValue()));
        error = "The second object returned by the pool is null";
        assertThat(error, messageDigest2, is(notNullValue()));
        error = "The first object returned by the pool is identical to the second object";
        assertThat(error, messageDigest2, is(not(sameInstance(messageDigest1))));

        // the pool supports only 2 objects (see POOL_MAX_SIZE)
        // borrowing a third instance will result in a FactoryException because the pool is exhausted
        // we return the first instance, and then should be able to borrow a third one - which should
        // be identical to the first one!
        MessageDigestFactory.returnPooledInstance(mdSpec, messageDigest1);

        MessageDigest messageDigest3;
        try {
            messageDigest3 = MessageDigestFactory.getPooledInstance(mdSpec, poolSpec);
        } catch (FactoryException | NoSuchAlgorithmException e) {
            AssertionError ae = new AssertionError("Instantiation error");
            ae.initCause(e);
            throw ae;
        }

        error = "The third object returned by the pool is null";
        assertThat(error, messageDigest3, is(notNullValue()));
        error = "The third object returned by the pool is NOT identical to the first object";
        assertThat(error, messageDigest3, is(sameInstance(messageDigest1)));

        // if we reset the factory, we should be able to borrow two new objects, which should
        // be different from the two objects we still reference from the old pool
        MessageDigestFactory.reset();
        MessageDigest messageDigest4, messageDigest5;
        try {
            messageDigest4 = MessageDigestFactory.getPooledInstance(mdSpec, poolSpec);
            messageDigest5 = MessageDigestFactory.getPooledInstance(mdSpec, poolSpec);
        } catch (FactoryException | NoSuchAlgorithmException e) {
            AssertionError ae = new AssertionError("Instantiation error");
            ae.initCause(e);
            throw ae;
        }

        error = "The fourth object returned by the pool is null";
        assertThat(error, messageDigest4, is(notNullValue()));
        error = "The fith object returned by the pool is null";
        assertThat(error, messageDigest5, is(notNullValue()));
        error = "The fourth object returned by the pool is identical to the fifth object";
        assertThat(error, messageDigest4, is(not(sameInstance(messageDigest5))));
        error = "The fourth object returned by the pool is identical to the second object";
        assertThat(error, messageDigest4, is(not(sameInstance(messageDigest2))));
        error = "The fourth object returned by the pool is identical to the third object";
        assertThat(error, messageDigest4, is(not(sameInstance(messageDigest3))));
        error = "The fifth object returned by the pool is identical to the second object";
        assertThat(error, messageDigest5, is(not(sameInstance(messageDigest2))));
        error = "The fifth object returned by the pool is identical to the third object";
        assertThat(error, messageDigest5, is(not(sameInstance(messageDigest3))));


        MessageDigestFactory.returnPooledInstance(mdSpec, messageDigest4);
        MessageDigestFactory.returnPooledInstance(mdSpec, messageDigest5);
    }

    /**
     * Test that the pool factory method does not return more more instances than are available in the pool
     * <p>
     * Note that this test is prone to resource leaks under certain conditions, which result in the borrowed
     * connections not being properly returned to the pool. This is still okay for the unit tests, because
     * the any pool resource leak does not longer matter after the tests are complete.
     *
     * @throws FactoryException When the instantiation does not work (expected)
     */
    @Test(expected = FactoryException.class)
    public void factoryReturnsMultiplePooledInstancesFromExhaustedPoolTest()
            throws FactoryException {

        MessageDigestSpec mdSpec = new MessageDigestSpec();
        PoolSpec poolSpec = new PoolSpec();
        poolSpec.setMaxTotal(POOL_MAX_SIZE);
        poolSpec.setMaxWaitMillis(0); // fail with an exception if no connections are available in the pool

        MessageDigest messageDigest1, messageDigest2;
        try {
            messageDigest1 = MessageDigestFactory.getPooledInstance(mdSpec, poolSpec);
            messageDigest2 = MessageDigestFactory.getPooledInstance(mdSpec, poolSpec);
        } catch (FactoryException | NoSuchAlgorithmException e) {
            AssertionError ae = new AssertionError("Instantiation error");
            ae.initCause(e);
            throw ae;
        }

        String error = "The first object returned by the pool is null";
        assertThat(error, messageDigest1, is(notNullValue()));
        error = "The second object returned by the pool is null";
        assertThat(error, messageDigest2, is(notNullValue()));
        error = "The first object returned by the pool is identical to the second object";
        assertThat(error, messageDigest2, is(not(sameInstance(messageDigest1))));


        // the pool supports only 2 objects (see POOL_MAX_SIZE)
        // borrowing a third instance will result in a FactoryException because the pool is exhausted
        MessageDigest messageDigest3 = null;
        try {
            messageDigest1 = MessageDigestFactory.getPooledInstance(mdSpec, poolSpec);
        } catch (NoSuchAlgorithmException e) {
            AssertionError ae = new AssertionError("Instantiation error - unknown algorithm, this should never happen!");
            ae.initCause(e);
            throw ae;
        } finally {

            if (messageDigest1 != null) {
                LOG.debug("returning resource 'messageDigest1'");
                MessageDigestFactory.returnPooledInstance(mdSpec, messageDigest1);
                LOG.debug("'messageDigest1' has been returned");
            }

            if (messageDigest2 != null) {
                LOG.debug("returning resource 'messageDigest2'");
                MessageDigestFactory.returnPooledInstance(mdSpec, messageDigest2);
                LOG.debug("'messageDigest2' has been returned");
            }

            if (messageDigest3 != null) {
                LOG.debug("returning resource 'messageDigest3'");
                MessageDigestFactory.returnPooledInstance(mdSpec, messageDigest3);
                LOG.debug("'messageDigest3' has been returned");
            }
        }
    }

    /**
     * Test that returning an object to a non-existing pool is properly handled
     *
     * @throws IllegalStateException When the pool return does not work (expected)
     */
    @Test(expected = IllegalStateException.class)
    public void factoryReturnToInvalidPoolTest()
            throws FactoryException, NoSuchAlgorithmException, IllegalStateException {

        MessageDigestSpec mdSpec1 = new MessageDigestSpec();
        mdSpec1.setAlgorithmName(ALGORITHM_1);
        MessageDigestSpec mdSpec2 = new MessageDigestSpec();
        mdSpec2.setAlgorithmName(ALGORITHM_2);
        PoolSpec poolSpec = new PoolSpec();

        MessageDigest messageDigest;
        messageDigest = MessageDigestFactory.getPooledInstance(mdSpec1, poolSpec);

        MessageDigestFactory.returnPooledInstance(mdSpec2, messageDigest);
    }

    /**
     * Return an object to the wrong pool
     *
     * @throws IllegalStateException When the pool return does not work (expected)
     */
    @Test(expected = IllegalStateException.class)
    public void factoryReturnToWrongPoolTest()
            throws FactoryException, NoSuchAlgorithmException {

        MessageDigestSpec mdSpec1 = new MessageDigestSpec();
        mdSpec1.setAlgorithmName(ALGORITHM_1);
        MessageDigestSpec mdSpec2 = new MessageDigestSpec();
        mdSpec2.setAlgorithmName(ALGORITHM_2);
        PoolSpec poolSpec = new PoolSpec();

        MessageDigest messageDigest1, messageDigest2;
        messageDigest1 = MessageDigestFactory.getPooledInstance(mdSpec1, poolSpec);
        messageDigest2 = MessageDigestFactory.getPooledInstance(mdSpec2, poolSpec);

        // return messageDigest2 to mdSpec1 pool, and vice versa
        MessageDigestFactory.returnPooledInstance(mdSpec1, messageDigest2);
        MessageDigestFactory.returnPooledInstance(mdSpec2, messageDigest1);
    }

    /**
     * Test that retrieving stats for an invalid pool throws an error
     *
     * @throws IllegalStateException When the requested pool does not exist (expected)
     */
    @Test(expected = IllegalStateException.class)
    public void invalidPoolStatTest()
            throws FactoryException {

        MessageDigestSpec mdSpec = new MessageDigestSpec();
        MessageDigestFactory.getPoolStats(mdSpec);
    }

    /**
     * Test that the pool stats are correct
     */
    @Test
    public void poolStatTest()
            throws FactoryException, NoSuchAlgorithmException {

        MessageDigestSpec mdSpec = new MessageDigestSpec();
        PoolSpec poolSpec = new PoolSpec();
        poolSpec.setMaxTotal(POOL_MAX_SIZE);
        poolSpec.setMaxWaitMillis(0); // fail with an exception if no connections are available in the pool

        // check pool utilization stats
        MessageDigest messageDigest1, messageDigest2, messageDigest3;

        // first instance
        messageDigest1 = MessageDigestFactory.getPooledInstance(mdSpec, poolSpec);
        String error = "The pool utilization statistic is incorrect";
        assertThat(error, MessageDigestFactory.getPoolStats(mdSpec).getCountBorrowed(), is(equalTo(1L)));
        assertThat(error, MessageDigestFactory.getPoolStats(mdSpec).getCountReturned(), is(equalTo(0L)));
        assertThat(error, MessageDigestFactory.getPoolStats(mdSpec).getNumActive(), is(equalTo(1)));
        assertThat(error, MessageDigestFactory.getPoolStats(mdSpec).getNumIdle(), is(equalTo(0)));

        // second instance
        messageDigest2 = MessageDigestFactory.getPooledInstance(mdSpec, poolSpec);
        assertThat(error, MessageDigestFactory.getPoolStats(mdSpec).getCountBorrowed(), is(equalTo(2L)));
        assertThat(error, MessageDigestFactory.getPoolStats(mdSpec).getCountReturned(), is(equalTo(0L)));
        assertThat(error, MessageDigestFactory.getPoolStats(mdSpec).getNumActive(), is(equalTo(2)));
        assertThat(error, MessageDigestFactory.getPoolStats(mdSpec).getNumIdle(), is(equalTo(0)));

        // return one instance
        MessageDigestFactory.returnPooledInstance(mdSpec, messageDigest1);
        assertThat(error, MessageDigestFactory.getPoolStats(mdSpec).getCountBorrowed(), is(equalTo(2L)));
        assertThat(error, MessageDigestFactory.getPoolStats(mdSpec).getCountReturned(), is(equalTo(1L)));
        assertThat(error, MessageDigestFactory.getPoolStats(mdSpec).getNumActive(), is(equalTo(1)));
        assertThat(error, MessageDigestFactory.getPoolStats(mdSpec).getNumIdle(), is(equalTo(1)));

        // return the second instance
        MessageDigestFactory.returnPooledInstance(mdSpec, messageDigest2);
        assertThat(error, MessageDigestFactory.getPoolStats(mdSpec).getCountBorrowed(), is(equalTo(2L)));
        assertThat(error, MessageDigestFactory.getPoolStats(mdSpec).getCountReturned(), is(equalTo(2L)));
        assertThat(error, MessageDigestFactory.getPoolStats(mdSpec).getNumActive(), is(equalTo(0)));
        assertThat(error, MessageDigestFactory.getPoolStats(mdSpec).getNumIdle(), is(equalTo(2)));

        // third instance
        messageDigest3 = MessageDigestFactory.getPooledInstance(mdSpec, poolSpec);
        assertThat(error, MessageDigestFactory.getPoolStats(mdSpec).getCountBorrowed(), is(equalTo(3L)));
        assertThat(error, MessageDigestFactory.getPoolStats(mdSpec).getCountReturned(), is(equalTo(2L)));
        assertThat(error, MessageDigestFactory.getPoolStats(mdSpec).getNumActive(), is(equalTo(1)));
        assertThat(error, MessageDigestFactory.getPoolStats(mdSpec).getNumIdle(), is(equalTo(1)));

        // return the third instance
        MessageDigestFactory.returnPooledInstance(mdSpec, messageDigest2);
        assertThat(error, MessageDigestFactory.getPoolStats(mdSpec).getCountBorrowed(), is(equalTo(3L)));
        assertThat(error, MessageDigestFactory.getPoolStats(mdSpec).getCountReturned(), is(equalTo(3L)));
        assertThat(error, MessageDigestFactory.getPoolStats(mdSpec).getNumActive(), is(equalTo(0)));
        assertThat(error, MessageDigestFactory.getPoolStats(mdSpec).getNumIdle(), is(equalTo(2)));
    }
}
