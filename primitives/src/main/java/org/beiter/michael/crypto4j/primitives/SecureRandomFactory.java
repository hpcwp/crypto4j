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

import org.apache.commons.lang3.Validate;
import org.apache.commons.pool2.impl.GenericObjectPool;
import org.apache.commons.pool2.impl.GenericObjectPoolConfig;
import org.beiter.michael.crypto4j.pool.PoolStats;
import org.beiter.michael.crypto4j.primitives.poolable.SecureRandomPoolFactory;
import org.beiter.michael.crypto4j.pool.PoolSpec;
import org.beiter.michael.crypto4j.primitives.spec.SecureRandomSpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A factory to create instances of objects that implement the {@link SecureRandom} interface.
 */
// CHECKSTYLE:OFF
// this is flagged in checkstyle with a missing whitespace before '}', which is a bug in checkstyle
// Cyclomatic complexity of 4 (out of 10) is not worth bothering a major overhaul
// suppress CPD Warnings for this class
@SuppressWarnings({"CPD-START", "PMD.CyclomaticComplexity"})
// CHECKSTYLE:ON
public final class SecureRandomFactory {

    /**
     * The logger object for this class
     */
    private static final Logger LOG = LoggerFactory.getLogger(SecureRandomFactory.class);

    /**
     * The singleton instances (per provider and algorithm) of the objects managed by this factory
     */
    private static final ConcurrentHashMap<String, SecureRandom> SINGLETONS = new ConcurrentHashMap<>();

    /**
     * The singleton instance of the object pool.
     * <p>
     * Unfortunately, we cannot use the GenericKeyedObjectPool here: That pool still requires to submit the factory
     * at creation time. However, the factory takes a configuration object, which which is different for each sub-pool.
     * This requires managing a map of pools, each with its individual configuration, through a map, with the core
     * configuration settings (provider and algorithm) as the identifying key.
     */
    private static final ConcurrentHashMap<String, GenericObjectPool<SecureRandom>> OBJECT_POOL
            = new ConcurrentHashMap<>();

    /**
     * A private constructor to prevent instantiation of this class
     */
    private SecureRandomFactory() {
    }

    /**
     * Returns a new instance of {@link SecureRandom} with the provider and algorithm configured in the provided
     * configuration object.
     * <p>
     * When sharing the object returned by this method across several threads, configure the JCA subsystem to only
     * use <b>thread safe</b> algorithm implementations, or utilize <b>appropriate locking mechanisms</b> in your
     * code to prevent concurrent access.
     *
     * @param prngSpec The prngSpec to initialize the instance with
     * @return An instance of {@link SecureRandom}
     * @throws NullPointerException     When {@code prngSpec} is {@code null}
     * @throws NoSuchAlgorithmException When the random number generator is not available
     * @throws FactoryException         When the configured provider is not registered in the security provider list
     */
    public static SecureRandom getInstance(final SecureRandomSpec prngSpec)
            throws NoSuchAlgorithmException, FactoryException {

        Validate.notNull(prngSpec, "The validated object 'prngSpec' is null");

        // compiler will optimize this:
        final String providerName = prngSpec.getProviderName();
        final String algorithmName = prngSpec.getAlgorithmName();

        return getInstance(providerName, algorithmName);
    }

    /**
     * Returns a singleton instance of {@link SecureRandom} with the provider and algorithm configured in the provided
     * configuration object. Note that different singletons are returned for permutations of the provided algorithm and
     * provider settings.
     * <p>
     * Retrieving a singleton by this method will cause the factory to keep state, and store a reference to the
     * singleton for later use. Use the singleton for low utilization use cases only, as there may be congestion
     * otherwise. Getting a singleton object is slightly faster than getting a pooled object, and also reduces memory
     * overhead, which makes using a singleton the go-forward approach unless the singleton cannot handle the
     * computational load in multi-threaded applications.
     * <p>
     * <b>Additional notes</b>
     * <ul>
     * <li>When sharing the object returned by this method across several threads, configure the JCA subsystem to only
     * use <b>thread safe</b> algorithm implementations, or utilize <b>appropriate locking mechanisms</b> in your
     * code to prevent concurrent access.</li>
     * <li>You may reset the factory state using the {@code reset()} method to retrieve a new / different singleton the
     * next time this method is called.</li>
     * <li>If you need tight control over the singleton, including its lifecycle and configuration, then you should
     * create such objects with the {@code getInstance()} method and maintain their state as "singletons" in your
     * application's business logic.</li>
     * <li>Note that there is no "seeded" variant of this method, because fully reseeding a {@link SecureRandom} PRNG is
     * not possible: Any provided seed supplements, rather than replaces, the existing seed, thus guaranteeing to
     * never reduce randomness.</li>
     * </ul>
     *
     * @param prngSpec The prngSpec to initialize the instance with
     * @return An instance of {@link SecureRandom}
     * @throws NullPointerException     When {@code prngSpec} is {@code null}
     * @throws NoSuchAlgorithmException When the random number generator is not available
     * @throws FactoryException         When the configured provider is not registered in the security provider list
     */
    @SuppressWarnings("PMD.ConfusingTernary")
    public static SecureRandom getSingleton(final SecureRandomSpec prngSpec)
            throws NoSuchAlgorithmException, FactoryException {

        Validate.notNull(prngSpec, "The validated object 'prngSpec' is null");

        // this would be harder to read when following PMD's advice - ignoring the PMD and checkstyle warnings
        //CHECKSTYLE:OFF checkstyle:avoidinlineconditionalscheck
        final String providerName = (prngSpec.getProviderName() == null) ? "" : prngSpec.getProviderName();
        final String algorithmName = (prngSpec.getAlgorithmName() == null) ? "" : prngSpec.getAlgorithmName();
        //CHECKSTYLE:ON checkstyle:avoidinlineconditionalscheck

        final String key = getPoolKey(prngSpec);

        // create an instance if needed. The double-check idiom is not used for thread safety (the map already is
        // thread safe), but to prevent unnecessary (expensive) object creation.
        if (!SINGLETONS.containsKey(key)) {
            synchronized (SecureRandomFactory.class) {
                if (!SINGLETONS.containsKey(key)) {

                    LOG.debug("Creating a new singleton for key '" + key + "'...");

                    SINGLETONS.putIfAbsent(key, getInstance(providerName, algorithmName));

                    LOG.debug("Successfully created a new singleton for key '" + key + "'");
                }
            }
        }

        return SINGLETONS.get(key);
    }

    /**
     * Returns a pooled instance of {@link SecureRandom}. Initializing {@code SecureRandom} can be very time consuming,
     * and (based on the local Java security configuration) may be even blocking. Using a {@code ThreadLocal} instance
     * to reduce the impact of problem without introducing congestion on a shared object can be very problematic in an
     * application server that reuses threads, and can lead to memory leaks and security issues. To improve performance
     * on object management, and avoid repeated JCA "create" calls, this method provides access to an object pool that
     * manages shared object instances.
     * <p>
     * This method allows borrowing an object from a pool of {@link SecureRandom} with the provider and algorithm
     * configured in the provided configuration object. In other words, when requesting an object of a specific
     * configuration, this methods creates the necessary pooling infrastructure, properly configures the pool, and
     * pre-populates it if needed. Note that different object configurations may use different object pools. However,
     * <b>once a pool for a specific object configuration has been created, the pool and object configuration can not be
     * changed without resetting this factory.</b> In other words, the pool spec for existing object specs is ignored in
     * subsequent calls to this method, but a new object spec leads to creation of a new pool with that pool spec. See
     * {@link SecureRandomFactory#reset()} on how to reset the factory.
     * <p>
     * <b>The object must be returned to the pool once it is not longer needed to prevent pool starvation!</b> See the
     * {@link SecureRandomFactory#returnPooledInstance(SecureRandomSpec, SecureRandom)} method on how to return objects
     * to the pool.
     * <p>
     * Retrieving an object by this method will cause the factory to keep state, and store a reference to the object
     * pool for later use. Use the object pool to create a set of objects for sharing across multiple threads. This is
     * less memory efficient than using a singleton, but allows an application to control object congestion. <b>Set
     * the pool size to a value smaller than the number of concurrently active threads</b>, and use pooled objects over
     * singletons in high utilization use cases. Getting a pooled object is slightly slower than getting a singleton.
     * <p>
     * The pool spec object controls how this factory manages the object pool. Chose the correct configuration and
     * pool size (if needed) based on the expected utilization and congestion of the returned {@link SecureRandom}
     * object pool in your application.
     * <p>
     * See {@link SecureRandomFactory#getSingleton(SecureRandomSpec)} for additional notes, in particular for the
     * <b>thread safety requirements</b> that particularly apply when <b>sharing singletons across threads</b>.
     *
     * @param prngSpec The spec to initialize the instances with
     * @param poolSpec The spec to initialize the pool with
     * @return A pooled instance of {@link SecureRandom}
     * @throws NullPointerException     When {@code poolSpec} or {@code prngSpec} are {@code null}
     * @throws NoSuchAlgorithmException When the random number generator is not available
     * @throws FactoryException         When the configured provider is not registered in the security provider list,
     *                                  or when the pool operation fails
     * @throws IllegalStateException    When the pool is reset in parallel thread, while the current thread tries to
     *                                  access it and borrow an object from the pool
     */
    // CHECKSTYLE:OFF
    // this is flagged in checkstyle with a missing whitespace before '}', which is a bug in checkstyle
    // We cannot remove the cause of the NPE without introducing complex synchronized locking. That would be a poor
    // decision from a performance perspective, because the client still needs to handle the FactoryException anyway.
    @SuppressWarnings({"PMD.AvoidCatchingNPE", "PMD.AvoidCatchingGenericException"})
    // CHECKSTYLE:ON
    public static SecureRandom getPooledInstance(final SecureRandomSpec prngSpec, final PoolSpec poolSpec)
            throws NoSuchAlgorithmException, FactoryException {

        Validate.notNull(poolSpec, "The validated object 'poolSpec' is null");
        Validate.notNull(prngSpec, "The validated object 'prngSpec' is null");

        // create an inbound defensive copy of the SecureRandomSpec
        final SecureRandomSpec myPrngSpec = new SecureRandomSpec(prngSpec);

        final String key = getPoolKey(myPrngSpec);

        // create an instance if needed. The double-check idiom is not used for thread safety (the map already is
        // thread safe), but to prevent unnecessary (expensive) object creation.
        if (!OBJECT_POOL.containsKey(key)) {
            synchronized (SecureRandomFactory.class) {
                if (!OBJECT_POOL.containsKey(key)) {

                    LOG.debug("Creating a new object pool for key '" + key + "'...");

                    // create a defensive copy of the configuration object for the pool
                    final GenericObjectPoolConfig config = getPoolConfig(poolSpec);

                    // create a new pool for this key
                    final GenericObjectPool<SecureRandom> pool
                            = new GenericObjectPool<SecureRandom>(new SecureRandomPoolFactory(myPrngSpec), config);

                    // store the pool in the map
                    OBJECT_POOL.putIfAbsent(key, pool);

                    LOG.debug("Successfully created a new object pool for key '" + key + "'");
                }
            }
        }

        // get the correct pool, borrow an object, and return it
        try {
            // Note: the get() operation can lead to an NPE if the pool is reset at the same time when this method
            // is executed. Any exception that would happen during the pool operation is swallowed by the pool.
            return OBJECT_POOL.get(key).borrowObject();

        } catch (NullPointerException e) {
            final String error = "Error when returning the object to the pool."
                    + " Has the factory been reset in a parallel thread?";
            LOG.warn(error);
            throw new IllegalStateException(error, e);
        } catch (Exception e) {
            LOG.debug("Failing object pool ID: " + key);
            final String error = "No object could be retrieved from the pool";
            LOG.warn(error, e);
            throw new FactoryException(error, e);
        }
    }

    /**
     * Return a pooled instance back to the pool.
     * <p>
     * Note that the pooled objects are standard JCA classes, and hence do not implement the {@link java.io.Closeable}
     * interface. Use this method to return an object back to the pool for reuse.
     * <p>
     * As this factory may potentially manage several pools of objects with equal type that have been created with
     * varying specifications, provide the object spec used to create the pooled object, thus allowing this method to
     * identify the correct pool to return the object to.
     *
     * @param prngSpec     The object spec used to create the pooled object
     * @param secureRandom The object to be returned to the pool
     * @throws NullPointerException  When {@code prngSpec} or {@code secureRandom} are {@code null}
     * @throws IllegalStateException If no pool exists for the provided object spec, or
     *                               if an object is returned to to the wrong pool (i.e. the wrong {@code }prngSpec})
     */
    // CHECKSTYLE:OFF
    // this is flagged in checkstyle with a missing whitespace before '}', which is a bug in checkstyle
    // We cannot remove the cause of the NPE without introducing complex synchronized locking. That would be a poor
    // decision from a performance perspective, because the client still needs to handle the FactoryException anyway.
    @SuppressWarnings({"PMD.AvoidCatchingNPE", "PMD.AvoidCatchingGenericException"})
    // CHECKSTYLE:ON
    public static void returnPooledInstance(final SecureRandomSpec prngSpec, final SecureRandom secureRandom)
            throws IllegalStateException {

        Validate.notNull(prngSpec, "The validated object 'prngSpec' is null");
        Validate.notNull(secureRandom, "The validated object 'secureRandom' is null");

        // create an inbound defensive copy of the SecureRandomSpec
        final SecureRandomSpec myPrngSpec = new SecureRandomSpec(prngSpec);

        final String key = getPoolKey(myPrngSpec);

        // return the object to the correct pool
        if (OBJECT_POOL.containsKey(key)) {
            try {
                // Note: the get() operation can lead to an NPE if the pool is reset at the same time when this method
                // is executed. Any exception that would happen during the pool operation is swallowed by the pool.
                OBJECT_POOL.get(key).returnObject(secureRandom);

            } catch (NullPointerException e) {
                final String error = "Error when returning the object to the pool."
                        + " Has the factory been reset in a parallel thread?";
                LOG.warn(error);
            }
        } else {
            LOG.debug("Failing object pool ID: " + key);
            final String error = "The object pool does not exist";
            LOG.warn(error);
            throw new IllegalStateException(error);
        }
    }

    /**
     * Return the statistics of a specific pool for a certain object spec.
     * <p>
     * As this factory may potentially manage several pools of objects of equal type that have been created with
     * varying specifications, provide the object spec used to create the pooled object, thus allowing this method to
     * identify the correct pool to return stats for.
     *
     * @param prngSpec The object spec used to create the pooled object
     * @return a {@code PoolStats} object with the usage statistics of the pool identified by the provided spec
     * @throws NullPointerException  When {@code prngSpec} is {@code null}
     * @throws IllegalStateException If no pool exists for the provided object spec
     */
    // CHECKSTYLE:OFF
    // this is flagged in checkstyle with a missing whitespace before '}', which is a bug in checkstyle
    // We cannot remove the cause of the NPE without introducing complex synchronized locking. That would be a poor
    // decision from a performance perspective, because the client still needs to handle the FactoryException anyway.
    @SuppressWarnings({"PMD.AvoidCatchingNPE", "PMD.AvoidCatchingGenericException"})
    // CHECKSTYLE:ON
    public static PoolStats getPoolStats(final SecureRandomSpec prngSpec) {

        Validate.notNull(prngSpec, "The validated object 'prngSpec' is null");

        // create an inbound defensive copy of the SecureRandomSpec
        final SecureRandomSpec myPrngSpec = new SecureRandomSpec(prngSpec);

        final String key = getPoolKey(myPrngSpec);

        if (OBJECT_POOL.containsKey(key)) {
            try {
                // Note: the get() operation can lead to an NPE if the pool is reset at the same time when this method
                // is executed. Any exception that would happen during the pool operation is swallowed by the pool.

                final GenericObjectPool<SecureRandom> pool = OBJECT_POOL.get(key);

                return new PoolStats(
                        pool.getNumActive(),
                        pool.getNumIdle(),
                        pool.getNumWaiters(),
                        pool.getBorrowedCount(),
                        pool.getCreatedCount(),
                        pool.getDestroyedCount(),
                        pool.getDestroyedByBorrowValidationCount(),
                        pool.getDestroyedByEvictorCount(),
                        pool.getReturnedCount(),
                        pool.getMeanActiveTimeMillis(),
                        pool.getMeanBorrowWaitTimeMillis(),
                        pool.getMeanIdleTimeMillis()
                );

            } catch (NullPointerException e) {
                final String error = "Error when accessing the pool. Has the factory been reset in a parallel thread?";
                LOG.warn(error);
                throw new IllegalStateException(error, e);
            }
        } else {
            LOG.debug("Failing object pool ID: " + key);
            final String error = "The object pool does not exist";
            LOG.warn(error);
            throw new IllegalStateException(error);
        }
    }

    /**
     * Resets the internal state of the factory. This includes resetting the pool, which causes the following methods
     * to return new {@link SecureRandom} instances the next time they are called:
     * <p>
     * <ul>
     * <li>{@link SecureRandomFactory#getSingleton(SecureRandomSpec)}</li>
     * <li>{@link SecureRandomFactory#getPooledInstance(SecureRandomSpec, PoolSpec)}</li>
     * </ul>
     */
    public static void reset() {

        // clear the singletons
        if (SINGLETONS.size() > 0) {

            SINGLETONS.clear();

            LOG.debug("Singletons cleared");
        }

        // clear the pools with all objects. The double-check idiom is not used for thread safety (the map already is
        // thread safe), but to prevent unnecessary (expensive) object operations.
        if (OBJECT_POOL.size() > 0) {
            synchronized (SecureRandomFactory.class) {
                if (OBJECT_POOL.size() > 0) {

                    // Note: the final cleanup will be complete once all borrowed objects have been returned to the
                    //       pools, but this class will no longer return any new instances from the pools.

                    // first close all pools...
                    for (final Map.Entry<String, GenericObjectPool<SecureRandom>> entry : OBJECT_POOL.entrySet()) {
                        entry.getValue().close();
                        LOG.debug("Object pool for key '" + entry.getKey() + "' closed");
                    }

                    // ...then clear the map, hence de-referencing all the pools
                    OBJECT_POOL.clear();
                    LOG.debug("Object pool cleared");
                }
            }
        }

    }

    /**
     * Returns an instance of SecureRandom that implements the specified Random Number Generator (RNG) algorithm.
     * <p>
     * This method returns a SecureRandom object encapsulating the SecureRandomSpi implementation from the specified
     * provider. The specified provider must be registered in the security provider list.
     * <p>
     * If the specified provider is <code>null</code> or empty, this method traverses the list of registered security
     * Providers, starting with the most preferred Provider. A new SecureRandom object encapsulating the
     * SecureRandomSpi implementation from the first Provider that supports the configured PRNG algorithm is returned.
     *
     * @param providerName  The name of the provider
     * @param algorithmName The name of the PRNG algorithm, as defined in the JCA Standard Algorithm Name Documentation
     * @return Instance of SecureRandom
     * @throws NoSuchAlgorithmException When the random number generator is not available
     * @throws FactoryException         When the specified provider is not registered in the security provider list
     */
    private static SecureRandom getInstance(final String providerName, final String algorithmName)
            throws NoSuchAlgorithmException, FactoryException {

        // no validation - private method

        if (providerName == null || providerName.isEmpty()) {
            String error = "The PRNG provider name is not set, using the JCA default provider";
            LOG.info(error);

            if (algorithmName == null || algorithmName.isEmpty()) {
                error = "The PRNG algorithm name is not set, using the JCA default algorithm";
                LOG.info(error);

                return new SecureRandom();

            } else {
                try {
                    return SecureRandom.getInstance(algorithmName);
                } catch (NoSuchAlgorithmException e) {
                    final String error2 = "The provided PRNG algorithm '" + algorithmName + "' is not supported";
                    LOG.warn(error2, e);
                    throw new NoSuchAlgorithmException(error, e);
                }
            }
        } else {

            String algorithm = algorithmName;

            if (algorithm == null || algorithm.isEmpty()) {
                String error = "The PRNG algorithm name is not set, obtaining the JCA default algorithm";
                LOG.info(error);

                // maybe there is a more efficient way to get the default algorithm name...
                algorithm = new SecureRandom().getAlgorithm();

                error = "The default PRNG algorithm name is '" + algorithm + "'";
                LOG.info(error);
            }

            try {
                return SecureRandom.getInstance(algorithm, providerName);
            } catch (NoSuchAlgorithmException e) {
                final String error = "The provided PRNG algorithm '" + algorithm + "' is not supported";
                LOG.warn(error, e);
                throw new NoSuchAlgorithmException(error, e);
            } catch (NoSuchProviderException e) {
                final String error = "The provided PRNG provider '" + providerName
                        + "' is not registered in the security provider list";
                LOG.warn(error, e);
                throw new FactoryException(error, e);
            }
        }
    }

    /**
     * Compute a key to uniquely reference objects of a specific spec (i.e. a spec that results in a different object
     * behavior will produce a different key).
     *
     * @param prngSpec The object spec
     * @return a key that uniquely identifies the object spec
     */
    @SuppressWarnings("PMD.ConfusingTernary")
    private static String getPoolKey(final SecureRandomSpec prngSpec) {

        // this would be harder to read when following PMD's advice - ignoring the PMD and checkstyle warnings
        //CHECKSTYLE:OFF checkstyle:avoidinlineconditionalscheck
        final String providerName = (prngSpec.getProviderName() == null) ? "" : prngSpec.getProviderName();
        final String algorithmName = (prngSpec.getAlgorithmName() == null) ? "" : prngSpec.getAlgorithmName();
        //CHECKSTYLE:ON checkstyle:avoidinlineconditionalscheck

        // key for a PRNG are the provider and the algorithm
        // (concatenation is good enough here)
        final String key = providerName + algorithmName; // compiler will optimize this

        return key;
    }

    /**
     * Returns a pool configuration object based on the provided pool spec
     *
     * @param poolSpec The pool spec with the pool's settings
     * @return the pool configuration object
     */
    private static GenericObjectPoolConfig getPoolConfig(final PoolSpec poolSpec) {

        // no validation - private method

        final GenericObjectPoolConfig config = new GenericObjectPoolConfig();

        config.setMaxTotal(poolSpec.getMaxTotal());
        config.setMaxIdle(poolSpec.getMaxIdle());
        config.setMinIdle(poolSpec.getMinIdle());
        config.setMaxWaitMillis(poolSpec.getMaxWaitMillis());
        config.setTestOnCreate(poolSpec.isTestOnCreate());
        config.setTestOnBorrow(poolSpec.isTestOnBorrow());
        config.setTestOnReturn(poolSpec.isTestOnReturn());
        config.setTestWhileIdle(poolSpec.isTestWhileIdle());
        config.setTimeBetweenEvictionRunsMillis(poolSpec.getTimeBetweenEvictionRunsMillis());
        config.setNumTestsPerEvictionRun(poolSpec.getNumTestsPerEvictionRun());
        config.setMinEvictableIdleTimeMillis(poolSpec.getMinEvictableIdleTimeMillis());
        config.setSoftMinEvictableIdleTimeMillis(poolSpec.getSoftMinEvictableIdleTimeMillis());
        config.setEvictionPolicyClassName(poolSpec.getEvictionPolicyClassName());
        config.setLifo(poolSpec.isLifo());
        config.setFairness(poolSpec.isFairness());
        config.setBlockWhenExhausted(poolSpec.isBlockWhenExhausted());
        config.setJmxEnabled(poolSpec.isJmxEnabled());
        config.setJmxNamePrefix(poolSpec.getJmxNamePrefix());
        config.setJmxNameBase(poolSpec.getJmxNameBase());

        return config;
    }
}
