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
import org.beiter.michael.crypto4j.primitives.spec.SecureRandomSpec;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.Assert.assertThat;

public class SecureRandomFactoryTest {

    /**
     * The logger object for this class
     */
    private static final Logger LOG = LoggerFactory.getLogger(SecureRandomFactoryTest.class);

    private static final String PROVIDER = "SUN";
    private static final String ALGORITHM = "SHA1PRNG";
    private static final int POOL_MAX_SIZE = 2;

    /**
     * Reset the factory to allow creating several instances of the underlying implementations.
     */
    @Before
    public void resetFactory() {

        SecureRandomFactory.reset();
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

        SecureRandomFactory.getInstance(null);
    }

    /**
     * An invalid (e.g. non-existing) algorithm name should throw an exception
     */
    @Test(expected = NoSuchAlgorithmException.class)
    public void getNonExistingImplementationTest()
            throws FactoryException, NoSuchAlgorithmException {

        SecureRandomSpec spec = new SecureRandomSpec();
        spec.setAlgorithmName("someGarbageName");

        SecureRandomFactory.getInstance(spec);
    }

    /**
     * An invalid (e.g. non-existing) provider name should throw an exception
     */
    @Test(expected = FactoryException.class)
    public void getInvalidImplementationTest()
            throws FactoryException, NoSuchAlgorithmException {

        SecureRandomSpec spec = new SecureRandomSpec();
        spec.setProviderName("someGarbageName");

        SecureRandomFactory.getInstance(spec);
    }

    ///////////////////////////////////////////////////////////////////////////
    // Advanced Tests
    ///////////////////////////////////////////////////////////////////////////

    /**
     * Retrieve a specific PRNG algorithm implementation, and assert that
     * the returned implementation equals the requested algorithm.
     */
    @Test
    public void getSpecificAlgorithmTest() {

        SecureRandomSpec spec = new SecureRandomSpec();
        spec.setAlgorithmName(ALGORITHM);

        SecureRandom secureRandom;
        try {
            secureRandom = SecureRandomFactory.getInstance(spec);
        } catch (FactoryException | NoSuchAlgorithmException e) {
            AssertionError ae = new AssertionError("Instantiation error");
            ae.initCause(e);
            throw ae;
        }

        String error = "The algorithm instantiated by the factory does not match the expected algorithm";
        assertThat(error, secureRandom.getAlgorithm(), is(equalTo(ALGORITHM)));
    }

    /**
     * Retrieve a specific PRNG provider implementation, and assert that
     * the returned implementation equals the requested provider.
     */
    @Test
    public void getSpecificProviderTest() {

        SecureRandomSpec spec = new SecureRandomSpec();
        spec.setProviderName(PROVIDER);

        SecureRandom secureRandom;
        try {
            secureRandom = SecureRandomFactory.getInstance(spec);
        } catch (FactoryException | NoSuchAlgorithmException e) {
            AssertionError ae = new AssertionError("Instantiation error");
            ae.initCause(e);
            throw ae;
        }

        String error = "The provider instantiated by the factory does not match the expected provider";
        assertThat(error, secureRandom.getProvider().getName(), is(equalTo(PROVIDER)));
    }

    /**
     * Retrieve two instances of {@code SecureRandom}, and assert that
     * the returned objects are two separate instances.
     */
    @Test
    public void twoInstancesAreDifferentTest() {

        SecureRandomSpec spec = new SecureRandomSpec();

        SecureRandom secureRandom1, secureRandom2;
        try {
            secureRandom1 = SecureRandomFactory.getInstance(spec);
            secureRandom2 = SecureRandomFactory.getInstance(spec);
        } catch (FactoryException | NoSuchAlgorithmException e) {
            AssertionError ae = new AssertionError("Instantiation error");
            ae.initCause(e);
            throw ae;
        }

        String error = "The factory returns a singleton instead of a new object";
        assertThat(error, secureRandom1, is(not(sameInstance(secureRandom2))));
    }

    /**
     * Retrieve two singleton instances of {@code SecureRandom}, and assert that the two returned objects are identical
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

        SecureRandomSpec spec = new SecureRandomSpec();

        // test that two singletons retrieved from the factory are identical
        SecureRandom secureRandom1, secureRandom2;
        try {
            secureRandom1 = SecureRandomFactory.getSingleton(spec);
            secureRandom2 = SecureRandomFactory.getSingleton(spec);
        } catch (FactoryException | NoSuchAlgorithmException e) {
            AssertionError ae = new AssertionError("Instantiation error");
            ae.initCause(e);
            throw ae;
        }

        String error = "The factory does not return a singleton";
        assertThat(error, secureRandom1, is(sameInstance(secureRandom2)));

        // then test that a regular (non-singleton) instance is different
        SecureRandom secureRandom3;
        try {
            secureRandom3 = SecureRandomFactory.getInstance(spec);
        } catch (FactoryException | NoSuchAlgorithmException e) {
            AssertionError ae = new AssertionError("Instantiation error");
            ae.initCause(e);
            throw ae;
        }
        error = "The factory returns a singleton instead of a new object";
        assertThat(error, secureRandom1, is(not(sameInstance(secureRandom3))));
        assertThat(error, secureRandom2, is(not(sameInstance(secureRandom3))));

        // reset the factory
        SecureRandomFactory.reset();

        // now test that the factory return a new object (i.e. a new singleton)
        SecureRandom secureRandom4;
        try {
            secureRandom4 = SecureRandomFactory.getSingleton(spec);
        } catch (FactoryException | NoSuchAlgorithmException e) {
            AssertionError ae = new AssertionError("Instantiation error");
            ae.initCause(e);
            throw ae;
        }

        error = "The factory does not return a singleton, or does not reset properly";
        assertThat(error, secureRandom1, is(not(sameInstance(secureRandom4))));
        assertThat(error, secureRandom2, is(not(sameInstance(secureRandom4))));
        assertThat(error, secureRandom3, is(not(sameInstance(secureRandom4))));
    }

    ///////////////////////////////////////////////////////////////////////////
    // Pool Tests
    ///////////////////////////////////////////////////////////////////////////

    /**
     * Test that the pool factory method returns an instance
     */
    @Test
    public void factoryReturnsPooledInstanceTest() {

        SecureRandomSpec srSpec = new SecureRandomSpec();
        PoolSpec poolSpec = new PoolSpec();

        SecureRandom secureRandom;
        try {
            secureRandom = SecureRandomFactory.getPooledInstance(srSpec, poolSpec);
        } catch (FactoryException | NoSuchAlgorithmException e) {
            AssertionError ae = new AssertionError("Instantiation error");
            ae.initCause(e);
            throw ae;
        }

        String error = "The object returned by the pool is null";
        assertThat(error, secureRandom, is(notNullValue()));
        error = "The object returned by the pool has the wrong type";
        assertThat(error, secureRandom, is(instanceOf(SecureRandom.class)));

        SecureRandomFactory.returnPooledInstance(srSpec, secureRandom);
    }

    /**
     * Test that the pool factory method returns two different instances
     * if called multiple times with the same pool properties
     */
    @Test
    public void factoryReturnsMultiplePooledInstancesTest() {

        SecureRandomSpec srSpec = new SecureRandomSpec();
        PoolSpec poolSpec = new PoolSpec();
        poolSpec.setMaxTotal(POOL_MAX_SIZE);
        poolSpec.setMaxWaitMillis(0); // fail with an exception if no connections are available in the pool

        SecureRandom secureRandom1, secureRandom2;
        try {
            secureRandom1 = SecureRandomFactory.getPooledInstance(srSpec, poolSpec);
            secureRandom2 = SecureRandomFactory.getPooledInstance(srSpec, poolSpec);
        } catch (FactoryException | NoSuchAlgorithmException e) {
            AssertionError ae = new AssertionError("Instantiation error");
            ae.initCause(e);
            throw ae;
        }

        String error = "The first object returned by the pool is null";
        assertThat(error, secureRandom1, is(notNullValue()));
        error = "The second object returned by the pool is null";
        assertThat(error, secureRandom2, is(notNullValue()));
        error = "The first object returned by the pool is identical to the second object";
        assertThat(error, secureRandom2, is(not(sameInstance(secureRandom1))));

        // the pool supports only 2 objects (see POOL_MAX_SIZE)
        // borrowing a third instance will result in a FactoryException because the pool is exhausted
        // we return the first instance, and then should be able to borrow a third one - which should
        // be identical to the first one!
        SecureRandomFactory.returnPooledInstance(srSpec, secureRandom1);

        SecureRandom secureRandom3;
        try {
            secureRandom3 = SecureRandomFactory.getPooledInstance(srSpec, poolSpec);
        } catch (FactoryException | NoSuchAlgorithmException e) {
            AssertionError ae = new AssertionError("Instantiation error");
            ae.initCause(e);
            throw ae;
        }

        error = "The third object returned by the pool is null";
        assertThat(error, secureRandom3, is(notNullValue()));
        error = "The third object returned by the pool is NOT identical to the first object";
        assertThat(error, secureRandom3, is(sameInstance(secureRandom1)));

        // if we reset the factory, we should be able to borrow two new objects, which should
        // be different from the two objects we still reference from the old pool
        SecureRandomFactory.reset();
        SecureRandom secureRandom4, secureRandom5;
        try {
            secureRandom4 = SecureRandomFactory.getPooledInstance(srSpec, poolSpec);
            secureRandom5 = SecureRandomFactory.getPooledInstance(srSpec, poolSpec);
        } catch (FactoryException | NoSuchAlgorithmException e) {
            AssertionError ae = new AssertionError("Instantiation error");
            ae.initCause(e);
            throw ae;
        }

        error = "The fourth object returned by the pool is null";
        assertThat(error, secureRandom4, is(notNullValue()));
        error = "The fith object returned by the pool is null";
        assertThat(error, secureRandom5, is(notNullValue()));
        error = "The fourth object returned by the pool is identical to the fifth object";
        assertThat(error, secureRandom4, is(not(sameInstance(secureRandom5))));
        error = "The fourth object returned by the pool is identical to the second object";
        assertThat(error, secureRandom4, is(not(sameInstance(secureRandom2))));
        error = "The fourth object returned by the pool is identical to the third object";
        assertThat(error, secureRandom4, is(not(sameInstance(secureRandom3))));
        error = "The fifth object returned by the pool is identical to the second object";
        assertThat(error, secureRandom5, is(not(sameInstance(secureRandom2))));
        error = "The fifth object returned by the pool is identical to the third object";
        assertThat(error, secureRandom5, is(not(sameInstance(secureRandom3))));


        SecureRandomFactory.returnPooledInstance(srSpec, secureRandom4);
        SecureRandomFactory.returnPooledInstance(srSpec, secureRandom5);
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

        SecureRandomSpec srSpec = new SecureRandomSpec();
        PoolSpec poolSpec = new PoolSpec();
        poolSpec.setMaxTotal(POOL_MAX_SIZE);
        poolSpec.setMaxWaitMillis(0); // fail with an exception if no connections are available in the pool

        SecureRandom secureRandom1, secureRandom2;
        try {
            secureRandom1 = SecureRandomFactory.getPooledInstance(srSpec, poolSpec);
            secureRandom2 = SecureRandomFactory.getPooledInstance(srSpec, poolSpec);
        } catch (FactoryException | NoSuchAlgorithmException e) {
            AssertionError ae = new AssertionError("Instantiation error");
            ae.initCause(e);
            throw ae;
        }

        String error = "The first object returned by the pool is null";
        assertThat(error, secureRandom1, is(notNullValue()));
        error = "The second object returned by the pool is null";
        assertThat(error, secureRandom2, is(notNullValue()));
        error = "The first object returned by the pool is identical to the second object";
        assertThat(error, secureRandom2, is(not(sameInstance(secureRandom1))));


        // the pool supports only 2 objects (see POOL_MAX_SIZE)
        // borrowing a third instance will result in a FactoryException because the pool is exhausted
        SecureRandom secureRandom3 = null;
        try {
            secureRandom1 = SecureRandomFactory.getPooledInstance(srSpec, poolSpec);
        } catch (NoSuchAlgorithmException e) {
            AssertionError ae = new AssertionError("Instantiation error - unknown algorithm, this should never happen!");
            ae.initCause(e);
            throw ae;
        } finally {

            if (secureRandom1 != null) {
                LOG.debug("returning resource 'secureRandom1'");
                SecureRandomFactory.returnPooledInstance(srSpec, secureRandom1);
                LOG.debug("'secureRandom1' has been returned");
            }

            if (secureRandom2 != null) {
                LOG.debug("returning resource 'secureRandom2'");
                SecureRandomFactory.returnPooledInstance(srSpec, secureRandom2);
                LOG.debug("'secureRandom2' has been returned");
            }

            if (secureRandom3 != null) {
                LOG.debug("returning resource 'secureRandom3'");
                SecureRandomFactory.returnPooledInstance(srSpec, secureRandom3);
                LOG.debug("'secureRandom3' has been returned");
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

        SecureRandomSpec srSpec1 = new SecureRandomSpec();
        SecureRandomSpec srSpec2 = new SecureRandomSpec();
        srSpec2.setAlgorithmName(ALGORITHM);
        PoolSpec poolSpec = new PoolSpec();

        SecureRandom secureRandom;
        secureRandom = SecureRandomFactory.getPooledInstance(srSpec1, poolSpec);

        SecureRandomFactory.returnPooledInstance(srSpec2, secureRandom);
    }

    /**
     * Return an object to the wrong pool
     *
     * @throws IllegalStateException When the pool return does not work (expected)
     */
    @Test(expected = IllegalStateException.class)
    public void factoryReturnToWrongPoolTest()
            throws FactoryException, NoSuchAlgorithmException {

        SecureRandomSpec srSpec1 = new SecureRandomSpec();
        SecureRandomSpec srSpec2 = new SecureRandomSpec();
        srSpec2.setAlgorithmName(ALGORITHM);
        PoolSpec poolSpec = new PoolSpec();

        SecureRandom secureRandom1, secureRandom2;
        secureRandom1 = SecureRandomFactory.getPooledInstance(srSpec1, poolSpec);
        secureRandom2 = SecureRandomFactory.getPooledInstance(srSpec2, poolSpec);

        // return secureRandom2 to srSpec1 pool, and vice versa
        SecureRandomFactory.returnPooledInstance(srSpec1, secureRandom2);
        SecureRandomFactory.returnPooledInstance(srSpec2, secureRandom1);
    }

    /**
     * Test that retrieving stats for an invalid pool throws an error
     *
     * @throws IllegalStateException When the requested pool does not exist (expected)
     */
    @Test(expected = IllegalStateException.class)
    public void invalidPoolStatTest()
            throws FactoryException {

        SecureRandomSpec srSpec = new SecureRandomSpec();
        SecureRandomFactory.getPoolStats(srSpec);
    }

    /**
     * Test that the pool stats are correct
     */
    @Test
    public void poolStatTest()
            throws FactoryException, NoSuchAlgorithmException {

        SecureRandomSpec srSpec = new SecureRandomSpec();
        PoolSpec poolSpec = new PoolSpec();
        poolSpec.setMaxTotal(POOL_MAX_SIZE);
        poolSpec.setMaxWaitMillis(0); // fail with an exception if no connections are available in the pool

        // check pool utilization stats
        SecureRandom secureRandom1, secureRandom2, secureRandom3;

        // first instance
        secureRandom1 = SecureRandomFactory.getPooledInstance(srSpec, poolSpec);
        String error = "The pool utilization statistic is incorrect";
        assertThat(error, SecureRandomFactory.getPoolStats(srSpec).getCountBorrowed(), is(equalTo(1L)));
        assertThat(error, SecureRandomFactory.getPoolStats(srSpec).getCountReturned(), is(equalTo(0L)));
        assertThat(error, SecureRandomFactory.getPoolStats(srSpec).getNumActive(), is(equalTo(1)));
        assertThat(error, SecureRandomFactory.getPoolStats(srSpec).getNumIdle(), is(equalTo(0)));

        // second instance
        secureRandom2 = SecureRandomFactory.getPooledInstance(srSpec, poolSpec);
        assertThat(error, SecureRandomFactory.getPoolStats(srSpec).getCountBorrowed(), is(equalTo(2L)));
        assertThat(error, SecureRandomFactory.getPoolStats(srSpec).getCountReturned(), is(equalTo(0L)));
        assertThat(error, SecureRandomFactory.getPoolStats(srSpec).getNumActive(), is(equalTo(2)));
        assertThat(error, SecureRandomFactory.getPoolStats(srSpec).getNumIdle(), is(equalTo(0)));

        // return one instance
        SecureRandomFactory.returnPooledInstance(srSpec, secureRandom1);
        assertThat(error, SecureRandomFactory.getPoolStats(srSpec).getCountBorrowed(), is(equalTo(2L)));
        assertThat(error, SecureRandomFactory.getPoolStats(srSpec).getCountReturned(), is(equalTo(1L)));
        assertThat(error, SecureRandomFactory.getPoolStats(srSpec).getNumActive(), is(equalTo(1)));
        assertThat(error, SecureRandomFactory.getPoolStats(srSpec).getNumIdle(), is(equalTo(1)));

        // return the second instance
        SecureRandomFactory.returnPooledInstance(srSpec, secureRandom2);
        assertThat(error, SecureRandomFactory.getPoolStats(srSpec).getCountBorrowed(), is(equalTo(2L)));
        assertThat(error, SecureRandomFactory.getPoolStats(srSpec).getCountReturned(), is(equalTo(2L)));
        assertThat(error, SecureRandomFactory.getPoolStats(srSpec).getNumActive(), is(equalTo(0)));
        assertThat(error, SecureRandomFactory.getPoolStats(srSpec).getNumIdle(), is(equalTo(2)));

        // third instance
        secureRandom3 = SecureRandomFactory.getPooledInstance(srSpec, poolSpec);
        assertThat(error, SecureRandomFactory.getPoolStats(srSpec).getCountBorrowed(), is(equalTo(3L)));
        assertThat(error, SecureRandomFactory.getPoolStats(srSpec).getCountReturned(), is(equalTo(2L)));
        assertThat(error, SecureRandomFactory.getPoolStats(srSpec).getNumActive(), is(equalTo(1)));
        assertThat(error, SecureRandomFactory.getPoolStats(srSpec).getNumIdle(), is(equalTo(1)));

        // return the third instance
        SecureRandomFactory.returnPooledInstance(srSpec, secureRandom2);
        assertThat(error, SecureRandomFactory.getPoolStats(srSpec).getCountBorrowed(), is(equalTo(3L)));
        assertThat(error, SecureRandomFactory.getPoolStats(srSpec).getCountReturned(), is(equalTo(3L)));
        assertThat(error, SecureRandomFactory.getPoolStats(srSpec).getNumActive(), is(equalTo(0)));
        assertThat(error, SecureRandomFactory.getPoolStats(srSpec).getNumIdle(), is(equalTo(2)));
    }
}
