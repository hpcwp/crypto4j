/*
 * #%L
 * This file is part of crypto4j, a library that provides a pluggable crypto
 * abstraction. It is part of a module that facilitates object pool management.
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
package org.beiter.michael.crypto4j.pool;

import org.apache.commons.lang3.Validate;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * This class specifies properties to configure an object pool.
 */
// CHECKSTYLE:OFF
// this is flagged in checkstyle with a missing whitespace before '}', which is a bug in checkstyle
// suppress warnings about the number of fields
// suppress warnings about the long variable names that are "inherited" from Apache DBCP (which I used as a blueprint)
@SuppressWarnings({"PMD.TooManyFields", "PMD.LongVariable"})
// CHECKSTYLE:ON
public class PoolSpec {

    // #################
    // # Default values
    // #################

    /**
     * @see PoolSpec#setMaxTotal(int)
     */
    public static final int DEFAULT_MAX_TOTAL = 8;

    /**
     * @see PoolSpec#setMaxIdle(int)
     */
    public static final int DEFAULT_MAX_IDLE = 8;

    /**
     * @see PoolSpec#setMinIdle(int)
     */
    public static final int DEFAULT_MIN_IDLE = 0;

    /**
     * @see PoolSpec#setMaxWaitMillis(long)
     */
    public static final long DEFAULT_MAX_WAIT_MILLIS = -1L;

    /**
     * @see PoolSpec#setTestOnCreate(boolean)
     */
    public static final boolean DEFAULT_TEST_ON_CREATE = false;

    /**
     * @see PoolSpec#setTestOnBorrow(boolean)
     */
    public static final boolean DEFAULT_TEST_ON_BORROW = false;

    /**
     * @see PoolSpec#setTestOnReturn(boolean)
     */
    public static final boolean DEFAULT_TEST_ON_RETURN = false;

    /**
     * @see PoolSpec#setTestWhileIdle(boolean)
     */
    public static final boolean DEFAULT_TEST_WHILE_IDLE = false;

    /**
     * @see PoolSpec#setTimeBetweenEvictionRunsMillis(long)
     */
    public static final long DEFAULT_TIME_BETWEEN_EVICTION_RUNS_MILLIS = -1L;

    /**
     * @see PoolSpec#setNumTestsPerEvictionRun(int)
     */
    public static final int DEFAULT_NUM_TESTS_PER_EVICTION_RUN = 3;

    /**
     * @see PoolSpec#setMinEvictableIdleTimeMillis(long)
     */
    public static final long DEFAULT_MIN_EVICTABLE_IDLE_TIME_MILLIS = 1000L * 60L * 30L;

    /**
     * @see PoolSpec#setSoftMinEvictableIdleTimeMillis(long)
     */
    public static final long DEFAULT_SOFT_MIN_EVICTABLE_IDLE_TIME_MILLIS = -1;

    /**
     * @see PoolSpec#setEvictionPolicyClassName(String)
     */
    public static final String DEFAULT_EVICTION_POLICY_CLASS_NAME =
            "org.apache.commons.pool2.impl.DefaultEvictionPolicy";

    /**
     * @see PoolSpec#setLifo(boolean)
     */
    public static final boolean DEFAULT_LIFO = true;

    /**
     * @see PoolSpec#setFairness(boolean)
     */
    public static final boolean DEFAULT_FAIRNESS = false;

    /**
     * @see PoolSpec#setBlockWhenExhausted(boolean)
     */
    public static final boolean DEFAULT_BLOCK_WHEN_EXHAUSTED = true;

    /**
     * @see PoolSpec#setJmxEnabled(boolean)
     */
    public static final boolean DEFAULT_JMX_ENABLED = false;

    /**
     * @see PoolSpec#setJmxNamePrefix(String)
     */
    public static final String DEFAULT_JMX_NAME_PREFIX = "pool";

    /**
     * @see PoolSpec#setJmxNameBase(String)
     */
    public static final String DEFAULT_JMX_NAME_BASE = null;

    // ===================================================================

    /**
     * @see PoolSpec#setMaxTotal(int)
     */
    private int maxTotal = DEFAULT_MAX_TOTAL;

    /**
     * @see PoolSpec#setMaxIdle(int)
     */
    private int maxIdle = DEFAULT_MAX_IDLE;

    /**
     * @see PoolSpec#setMinIdle(int)
     */
    private int minIdle = DEFAULT_MIN_IDLE;

    /**
     * @see PoolSpec#setMaxWaitMillis(long)
     */
    private long maxWaitMillis = DEFAULT_MAX_WAIT_MILLIS;

    /**
     * @see PoolSpec#setTestOnCreate(boolean)
     */
    private boolean testOnCreate = DEFAULT_TEST_ON_CREATE;

    /**
     * @see PoolSpec#setTestOnBorrow(boolean)
     */
    private boolean testOnBorrow = DEFAULT_TEST_ON_BORROW;

    /**
     * @see PoolSpec#setTestOnReturn(boolean)
     */
    private boolean testOnReturn = DEFAULT_TEST_ON_RETURN;

    /**
     * @see PoolSpec#setTestWhileIdle(boolean)
     */
    private boolean testWhileIdle = DEFAULT_TEST_WHILE_IDLE;

    /**
     * @see PoolSpec#setTimeBetweenEvictionRunsMillis(long)
     */
    private long timeBetweenEvictionRunsMillis = DEFAULT_TIME_BETWEEN_EVICTION_RUNS_MILLIS;

    /**
     * @see PoolSpec#setNumTestsPerEvictionRun(int)
     */
    private int numTestsPerEvictionRun = DEFAULT_NUM_TESTS_PER_EVICTION_RUN;

    /**
     * @see PoolSpec#setMinEvictableIdleTimeMillis(long)
     */
    private long minEvictableIdleTimeMillis = DEFAULT_MIN_EVICTABLE_IDLE_TIME_MILLIS;

    /**
     * @see PoolSpec#setSoftMinEvictableIdleTimeMillis(long)
     */
    private long softMinEvictableIdleTimeMillis = DEFAULT_SOFT_MIN_EVICTABLE_IDLE_TIME_MILLIS;

    /**
     * @see PoolSpec#setEvictionPolicyClassName(String)
     */
    private String evictionPolicyClassName = DEFAULT_EVICTION_POLICY_CLASS_NAME;

    /**
     * @see PoolSpec#setLifo(boolean)
     */
    private boolean lifo = DEFAULT_LIFO;

    /**
     * @see PoolSpec#setFairness(boolean)
     */
    private boolean fairness = DEFAULT_FAIRNESS;

    /**
     * @see PoolSpec#setBlockWhenExhausted(boolean)
     */
    private boolean blockWhenExhausted = DEFAULT_BLOCK_WHEN_EXHAUSTED;

    /**
     * @see PoolSpec#setJmxEnabled(boolean)
     */
    private boolean jmxEnabled = DEFAULT_JMX_ENABLED;

    /**
     * @see PoolSpec#setJmxNamePrefix(String)
     */
    private String jmxNamePrefix = DEFAULT_JMX_NAME_PREFIX;

    /**
     * @see PoolSpec#setJmxNameBase(String)
     */
    private String jmxNameBase = DEFAULT_JMX_NAME_BASE;

    /**
     * @see PoolSpec#setAdditionalProperties(Map <String, String>)
     */
    private Map<String, String> additionalProperties = new ConcurrentHashMap<>();

    /**
     * Constructs an empty spec, with the values being set to the class' default values ({@code DEFAULT_*} properties
     * in this class). Usually this constructor is used if this configuration POJO is populated in an automated fashion
     * (e.g. injection).
     * <p>
     * If you need to build them manually (possibly with defaults), use or create a properties builder.
     * <p>
     * To change individual fields, use the provided setters.
     */
    public PoolSpec() {

        // no code here, constructor just for java docs
    }

    /**
     * Creates a spec from an existing spec, making a defensive copy.
     *
     * @param spec The set of spec to copy
     * @throws NullPointerException When {@code spec} is {@code null}
     * @see PoolSpec#PoolSpec()
     */
    public PoolSpec(final PoolSpec spec) {

        this();

        Validate.notNull(spec, "The validated object 'spec' is null");

        setMaxTotal(spec.getMaxTotal());
        setMaxIdle(spec.getMaxIdle());
        setMinIdle(spec.getMinIdle());
        setMaxWaitMillis(spec.getMaxWaitMillis());
        setTestOnCreate(spec.isTestOnCreate());
        setTestOnBorrow(spec.isTestOnBorrow());
        setTestOnReturn(spec.isTestOnReturn());
        setTestWhileIdle(spec.isTestWhileIdle());
        setTimeBetweenEvictionRunsMillis(spec.getTimeBetweenEvictionRunsMillis());
        setNumTestsPerEvictionRun(spec.getNumTestsPerEvictionRun());
        setMinEvictableIdleTimeMillis(spec.getMinEvictableIdleTimeMillis());
        setSoftMinEvictableIdleTimeMillis(spec.getSoftMinEvictableIdleTimeMillis());
        setEvictionPolicyClassName(spec.getEvictionPolicyClassName());
        setLifo(spec.isLifo());
        setFairness(spec.isFairness());
        setBlockWhenExhausted(spec.isBlockWhenExhausted());
        setJmxEnabled(spec.isJmxEnabled());
        setJmxNamePrefix(spec.getJmxNamePrefix());
        setJmxNameBase(spec.getJmxNameBase());
        setAdditionalProperties(spec.getAdditionalProperties());
    }

    /**
     * @return The maximum numbers of active connections
     * @see PoolSpec#setMaxTotal(int)
     */
    public final int getMaxTotal() {

        // no need for defensive copies of int

        return maxTotal;
    }

    /**
     * The maximum number of active objects that can be allocated from this pool at the same time, or negative
     * for no limit.
     *
     * @param maxTotal The maximum numbers of active objects
     */
    public final void setMaxTotal(final int maxTotal) {

        // no need for validation, as int cannot be null and all possible values are allowed
        // no need for defensive copies of int

        this.maxTotal = maxTotal;
    }

    /**
     * @return The maximum number of idle objects
     * @see PoolSpec#setMaxIdle(int)
     */
    public final int getMaxIdle() {

        // no need for defensive copies of int

        return maxIdle;
    }

    /**
     * The maximum number of objects that can remain idle in the pool, without extra ones being released, or
     * negative for no limit.
     *
     * @param maxIdle The maximum number of idle objects
     */
    public final void setMaxIdle(final int maxIdle) {

        // no need for validation, as int cannot be null and all possible values are allowed
        // no need for defensive copies of int

        this.maxIdle = maxIdle;
    }

    /**
     * @return The minimum number of idle objects
     * @see PoolSpec#setMinIdle(int)
     */
    public final int getMinIdle() {

        // no need for defensive copies of int

        return minIdle;
    }

    /**
     * The minimum number of objects that can remain idle in the pool, without extra ones being created, or zero
     * to create none.
     *
     * @param minIdle The minimum number of idle objects
     * @throws IllegalArgumentException When the provided value of {@code minIdle} is out of range
     */
    public final void setMinIdle(final int minIdle) {

        Validate.inclusiveBetween(0, Integer.MAX_VALUE, minIdle);

        // no need for defensive copies of int

        this.minIdle = minIdle;
    }

    /**
     * @return The maximum number of milliseconds that the pool will wait for a connection
     * @see PoolSpec#setMaxWaitMillis(long)
     */
    public final long getMaxWaitMillis() {

        // no need for defensive copies of long

        return maxWaitMillis;
    }

    /**
     * The maximum number of milliseconds that the pool will block (when there are no available objects) before
     * throwing an exception when the pool is exhausted and {@link PoolSpec#isBlockWhenExhausted()} is {@code true}.
     * Set to {@code -1} to wait indefinitely.
     *
     * @param maxWaitMillis The maximum number of milliseconds that the pool will wait for a connection
     * @throws IllegalArgumentException When the provided value of {@code maxWaitMillis} is out of range
     */
    public final void setMaxWaitMillis(final long maxWaitMillis) {

        Validate.inclusiveBetween(-1, Integer.MAX_VALUE, maxWaitMillis);

        // no need for defensive copies of long

        this.maxWaitMillis = maxWaitMillis;
    }

    /**
     * @return The indication of whether objects will be validated after creation
     * @see PoolSpec#setTestOnCreate(boolean)
     */
    public final boolean isTestOnCreate() {

        // no need for defensive copies of boolean

        return testOnCreate;
    }

    /**
     * The indication of whether objects will be validated after creation. If the object fails to validate, the borrow
     * attempt that triggered the object creation will fail.
     *
     * @param testOnCreate The indication of whether objects will be validated after creation
     */
    public final void setTestOnCreate(final boolean testOnCreate) {

        // no need for validation, as boolean cannot be null and all possible values are allowed
        // no need for defensive copies of boolean

        this.testOnCreate = testOnCreate;
    }

    /**
     * @return The indication of whether objects will be validated before being borrowed from the pool
     * @see PoolSpec#setTestOnBorrow(boolean)
     */
    public final boolean isTestOnBorrow() {

        // no need for defensive copies of boolean

        return testOnBorrow;
    }

    /**
     * The indication of whether objects will be validated before being borrowed from the pool. If the object fails to
     * validate, it will be dropped from the pool, and we will attempt to borrow another.
     *
     * @param testOnBorrow The indication of whether objects will be validated before being borrowed from the pool
     */
    public final void setTestOnBorrow(final boolean testOnBorrow) {

        // no need for validation, as boolean cannot be null and all possible values are allowed
        // no need for defensive copies of boolean

        this.testOnBorrow = testOnBorrow;
    }

    /**
     * @return The indication of whether objects will be validated before being returned to the pool
     * @see PoolSpec#setTestOnReturn(boolean)
     */
    public final boolean isTestOnReturn() {

        // no need for defensive copies of boolean

        return testOnReturn;
    }

    /**
     * The indication of whether objects will be validated before being returned to the pool.
     *
     * @param testOnReturn The indication of whether objects will be validated before being returned to the pool
     */
    public final void setTestOnReturn(final boolean testOnReturn) {

        // no need for validation, as boolean cannot be null and all possible values are allowed
        // no need for defensive copies of boolean

        this.testOnReturn = testOnReturn;
    }

    /**
     * @return The indication of whether objects will be validated by the idle object evictor (if any)
     * @see PoolSpec#setTestWhileIdle(boolean)
     */
    public final boolean isTestWhileIdle() {

        // no need for defensive copies of boolean

        return testWhileIdle;
    }

    /**
     * The indication of whether objects will be validated by the idle object evictor (if any, see
     * {@link PoolSpec#setTimeBetweenEvictionRunsMillis(long)})). If an object fails to validate, it will be dropped
     * from the pool.
     *
     * @param testWhileIdle The indication of whether objects will be validated by the idle object evictor (if any)
     */
    public final void setTestWhileIdle(final boolean testWhileIdle) {

        // no need for validation, as boolean cannot be null and all possible values are allowed
        // no need for defensive copies of boolean

        this.testWhileIdle = testWhileIdle;
    }

    /**
     * @return The number of milliseconds to sleep between runs of the idle object evictor thread
     * @see PoolSpec#setTimeBetweenEvictionRunsMillis(long)
     */
    public final long getTimeBetweenEvictionRunsMillis() {

        // no need for defensive copies of long

        return timeBetweenEvictionRunsMillis;
    }

    /**
     * The number of milliseconds to sleep between runs of the idle object evictor thread. Set to {@code -1} to not run
     * any idle object evictor thread.
     *
     * @param timeBetweenEvictionRunsMillis The number of milliseconds to sleep between runs of the idle object evictor
     *                                      thread
     * @throws IllegalArgumentException When the provided value of {@code timeBetweenEvictionRunsMillis} is out of range
     */
    public final void setTimeBetweenEvictionRunsMillis(final long timeBetweenEvictionRunsMillis) {

        Validate.inclusiveBetween(-1, Integer.MAX_VALUE, timeBetweenEvictionRunsMillis);

        // no need for defensive copies of long

        this.timeBetweenEvictionRunsMillis = timeBetweenEvictionRunsMillis;
    }

    /**
     * @return the number of objects to examine during each run of the idle object evictor thread (if any)
     * @see PoolSpec#setNumTestsPerEvictionRun(int)
     */
    public final int getNumTestsPerEvictionRun() {

        // no need for defensive copies of int

        return numTestsPerEvictionRun;
    }

    /**
     * The maximum number of objects to examine during each run (if any) of the idle object evictor thread. When
     * positive, the number of tests performed for a run will be the minimum of the configured value and the number of
     * idle instances in the pool. When negative, the number of tests performed will be roughly one nth of the idle
     * objects per run.
     *
     * @param numTestsPerEvictionRun The number of objects to examine during each run of the idle object evictor thread
     *                               (if any)
     * @throws IllegalArgumentException When the provided value of {@code numTestsPerEvictionRun} is out of range
     */
    public final void setNumTestsPerEvictionRun(final int numTestsPerEvictionRun) {

        // no need for validation, as int cannot be null and all possible values are allowed
        // no need for defensive copies of long

        this.numTestsPerEvictionRun = numTestsPerEvictionRun;
    }


    /**
     * @return The minimum amount of time an object may sit idle in the pool before it is eligable for eviction by the
     * idle object evictor (if any)
     * @see PoolSpec#setMinEvictableIdleTimeMillis(long)
     */
    public final long getMinEvictableIdleTimeMillis() {

        // no need for defensive copies of long

        return minEvictableIdleTimeMillis;
    }

    /**
     * The minimum amount of time an object may sit idle in the pool before it is eligible for eviction by the idle
     * object evictor (if any, see {@link PoolSpec#setTimeBetweenEvictionRunsMillis(long)}). When non-positive, no
     * objects will be evicted from the pool due to idle time alone.
     *
     * @param minEvictableIdleTimeMillis The minimum amount of time an object may sit idle in the pool before it is
     *                                   eligable for eviction by the idle object evictor (if any).
     */
    public final void setMinEvictableIdleTimeMillis(final long minEvictableIdleTimeMillis) {

        // no need for validation, as long cannot be null and all possible values are allowed
        // no need for defensive copies of long

        this.minEvictableIdleTimeMillis = minEvictableIdleTimeMillis;
    }

    /**
     * @return The minimum amount of time a connection may sit idle in the pool before it is eligible for eviction by
     * the idle connection evictor, with the extra condition that at least "minIdle" objects remain in the pool.
     * @see PoolSpec#setSoftMinEvictableIdleTimeMillis(long)
     */
    public final long getSoftMinEvictableIdleTimeMillis() {

        // no need for defensive copies of long

        return softMinEvictableIdleTimeMillis;
    }

    /**
     * The minimum amount of time a connection may sit idle in the pool before it is eligible for eviction by the idle
     * connection evictor, with the extra condition that at least {@code minIdle} objects remain in the pool.
     * When {@code miniEvictableIdleTimeMillis} is set to a positive value, {@code miniEvictableIdleTimeMillis} is
     * examined first by the idle connection evictor - i.e. when idle objects are visited by the evictor, idle time
     * is first compared against {@code miniEvictableIdleTimeMillis} (without considering the number of idle
     * objects in the pool) and then against {@code softMinEvictableIdleTimeMillis}, including the {@code minIdle}
     * constraint.
     *
     * @param softMinEvictableIdleTimeMillis The minimum amount of time a connection may sit idle in the pool before it
     *                                       is eligible for eviction by the idle connection evictor, with the extra
     *                                       condition that at least "minIdle" objects remain in the pool.
     */
    public final void setSoftMinEvictableIdleTimeMillis(final long softMinEvictableIdleTimeMillis) {

        // no need for validation, as long cannot be null and all possible values are allowed
        // no need for defensive copies of long

        this.softMinEvictableIdleTimeMillis = softMinEvictableIdleTimeMillis;
    }

    /**
     * @return The fully qualified class name of the {@code EvictionPolicy}
     * @see PoolSpec#setEvictionPolicyClassName(String)
     */
    public final String getEvictionPolicyClassName() {

        // no need for defensive copies of String

        return evictionPolicyClassName;
    }

    /**
     * Sets the name of the {@link org.apache.commons.pool2.impl.EvictionPolicy} implementation that is used by this
     * pool. The pool will attempt to load the class using the thread context class loader. If that fails, the pool
     * will attempt to load the class using the class loader that loaded this class.
     *
     * @param evictionPolicyClassName The fully qualified class name of the new eviction policy
     * @throws NullPointerException     When the {@code evictionPolicyClassName} is {@code null}
     * @throws IllegalArgumentException When {@code evictionPolicyClassName} is empty
     */
    public final void setEvictionPolicyClassName(final String evictionPolicyClassName) {

        Validate.notBlank(evictionPolicyClassName,
                "The validated character sequence 'evictionPolicyClassName' is null or empty");

        this.evictionPolicyClassName = evictionPolicyClassName;
    }

    /**
     * @return {@code true} if the pool returns the most recently used ("last in") object, {@code false}
     * the pool behaves as a FIFO queue
     * @see PoolSpec#setLifo(boolean)
     */
    public final boolean isLifo() {

        // no need for defensive copies of boolean

        return lifo;
    }

    /**
     * {@code True} means that the pool returns the most recently used ("last in") object in the pool (if there are
     * idle objects available). {@code False} means that the pool behaves as a FIFO queue - objects are taken
     * from the idle instance pool in the order that they are returned to the pool.
     *
     * @param lifo {@code true} if the pool returns the most recently used ("last in") object,
     *             {@code false} if the pool behaves as a FIFO queue
     */
    public final void setLifo(final boolean lifo) {

        // no need for validation, as boolean cannot be null and all possible values are allowed
        // no need for defensive copies of boolean

        this.lifo = lifo;
    }

    /**
     * @return {@code true} if waiting threads are served as if waiting in a FIFO queue
     * @see PoolSpec#setFairness(boolean)
     */
    public final boolean isFairness() {

        // no need for defensive copies of boolean

        return fairness;
    }

    /**
     * Indicates whether or not the pool serves threads waiting to borrow objects fairly. {@code True} means that
     * waiting threads are served as if waiting in a FIFO queue.
     *
     * @param fairness {@code true} if waiting threads are to be served by the pool in arrival order
     */
    public final void setFairness(final boolean fairness) {

        // no need for validation, as boolean cannot be null and all possible values are allowed
        // no need for defensive copies of boolean

        this.fairness = fairness;
    }

    /**
     * @return {@code true} if the borrow method should block when the pool is exhausted
     * @see PoolSpec#isBlockWhenExhausted()
     */
    public final boolean isBlockWhenExhausted() {

        // no need for defensive copies of boolean

        return blockWhenExhausted;
    }

    /**
     * {@code True} means that the borrow methods blocks when the pool is exhausted (the maximum number of "active"
     * objects has been reached).
     *
     * @param blockWhenExhausted {@code true} if the borrow method should block when the pool is exhausted
     */
    public final void setBlockWhenExhausted(final boolean blockWhenExhausted) {

        // no need for validation, as boolean cannot be null and all possible values are allowed
        // no need for defensive copies of boolean

        this.blockWhenExhausted = blockWhenExhausted;
    }

    /**
     * @return {@code true} if JMX will be enabled for newly created pools that use this spec
     * @see PoolSpec#setJmxEnabled(boolean)
     */
    public final boolean isJmxEnabled() {

        // no need for defensive copies of boolean

        return jmxEnabled;
    }

    /**
     * {@code True} means that JMX will be enabled for newly created pools that use this spec
     *
     * @param jmxEnabled {@code true} if JMX should be enabled for newly created pools that use this spec
     */
    public final void setJmxEnabled(final boolean jmxEnabled) {

        // no need for validation, as boolean cannot be null and all possible values are allowed
        // no need for defensive copies of boolean

        this.jmxEnabled = jmxEnabled;
    }

    /**
     * @return the value of the JMX name prefix
     * @see PoolSpec#setJmxNamePrefix(String)
     */
    public final String getJmxNamePrefix() {

        // no need for defensive copies of String

        return jmxNamePrefix;
    }

    /**
     * Set the value of the JMX name prefix that will be used as part of the name assigned to JMX enabled pools created
     * with this pool spec
     *
     * @param jmxNamePrefix The value of the JMX name prefix
     * @throws NullPointerException     When the {@code jmxNamePrefix} is {@code null}
     * @throws IllegalArgumentException When {@code jmxNamePrefix} is empty
     */
    public final void setJmxNamePrefix(final String jmxNamePrefix) {

        Validate.notBlank(jmxNamePrefix,
                "The validated character sequence 'jmxNamePrefix' is null or empty");

        // no need for defensive copies of String

        this.jmxNamePrefix = jmxNamePrefix;
    }

    /**
     * @return The value of the JMX name base, or {@code null} if the pool manages the JMX name base
     * @see PoolSpec#setJmxNameBase(String)
     */
    public final String getJmxNameBase() {

        // no need for defensive copies of String

        return jmxNameBase;
    }

    /**
     * Set the value of the JMX name base that will be used as part of the name assigned to JMX enabled pools created
     * with this pool spec. A value of {@code null} means that the pool will define the JMX name base.
     *
     * @param jmxNameBase The value of the JMX name base, or {@code null} if the pool manages the JMX name base
     */
    public final void setJmxNameBase(final String jmxNameBase) {

        // no need for validation, as we cannot possible validate all name bases and null is allowed for this string
        // no need for defensive copies of String

        this.jmxNameBase = jmxNameBase;
    }

    /**
     * @return Any additional properties stored in this object that have not explicitly been parsed
     * @see PoolSpec#setAdditionalProperties(Map)
     */
    public final Map<String, String> getAdditionalProperties() {

        // create a defensive copy of the map and all its properties
        if (this.additionalProperties == null) {
            // this should never happen!
            return new ConcurrentHashMap<>();
        } else {
            final Map<String, String> tempMap = new ConcurrentHashMap<>();
            // putAll() is safe here, because we always apply it on a ConcurrentHashMap
            tempMap.putAll(additionalProperties);

            return tempMap;
        }
    }

    /**
     * Set additional properties which are not parsed by this class, and for which no getter/setter exists, but which
     * are to be stored in this object nevertheless for later use by other spec classes.
     * <p>
     * This property is commonly used to preserve original properties from upstream components that are to be passed
     * on to downstream components unchanged. This properties set may or may not include properties that have been
     * extracted from the map, and been made available through this POJO.
     * <p>
     * Note that these additional properties may be <code>null</code> or empty, even in a fully populated POJO where
     * other properties commonly have values assigned to.
     *
     * @param additionalProperties The additional properties to store
     */
    public final void setAdditionalProperties(final Map<String, String> additionalProperties) {

        // create a defensive copy of the map and all its properties
        if (additionalProperties == null) {
            // create a new (empty) properties map if the provided parameter was null
            this.additionalProperties = new ConcurrentHashMap<>();
        } else {
            // create a defensive copy of the map and all its properties
            // the code looks a little more complicated than a simple "putAll()", but it catches situations
            // where a Map is provided that supports null values (e.g. a HashMap) vs Map implementations
            // that do not (e.g. ConcurrentHashMap).
            this.additionalProperties = new ConcurrentHashMap<>();
            for (final Map.Entry<String, String> entry : additionalProperties.entrySet()) {
                final String key = entry.getKey();
                final String value = entry.getValue();

                if (value != null) {
                    this.additionalProperties.put(key, value);
                }
            }
        }
    }
}
