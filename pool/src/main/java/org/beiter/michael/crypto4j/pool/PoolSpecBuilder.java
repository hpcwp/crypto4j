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

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Validate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * This class builds a {@link PoolSpec} using the settings obtained from a {@link Map}.
 * <p>
 * Use the keys from the various {@code KEY_*} fields to properly populate the {@link Map} before calling this class'
 * methods.
 */
// suppress warnings about the long variable names that are "inherited" from Apache DBCP (which I used as a blueprint)
@SuppressWarnings("PMD.LongVariable")
public final class PoolSpecBuilder {

    /**
     * The logger object for this class
     */
    private static final Logger LOG = LoggerFactory.getLogger(PoolSpecBuilder.class);

    // #####################
    // # Configuration Keys
    // #####################

    /**
     * @see PoolSpec#setMaxTotal(int)
     */
    public static final String KEY_MAX_TOTAL = "pool.maxTotal";

    /**
     * @see PoolSpec#setMaxIdle(int)
     */
    public static final String KEY_MAX_IDLE = "pool.maxIdle";

    /**
     * @see PoolSpec#setMinIdle(int)
     */
    public static final String KEY_MIN_IDLE = "pool.minIdle";

    /**
     * @see PoolSpec#setMaxWaitMillis(long)
     */
    public static final String KEY_MAX_WAIT_MILLIS = "pool.maxWaitMillis";

    /**
     * @see PoolSpec#setTestOnCreate(boolean)
     */
    public static final String KEY_TEST_ON_CREATE = "pool.testOnCreate";

    /**
     * @see PoolSpec#setTestOnBorrow(boolean)
     */
    public static final String KEY_TEST_ON_BORROW = "pool.testOnBorrow";

    /**
     * @see PoolSpec#setTestOnReturn(boolean)
     */
    public static final String KEY_TEST_ON_RETURN = "pool.testOnReturn";

    /**
     * @see PoolSpec#setTestWhileIdle(boolean)
     */
    public static final String KEY_TEST_WHILE_IDLE = "pool.testWhileIdle";

    /**
     * @see PoolSpec#setTimeBetweenEvictionRunsMillis(long)
     */
    public static final String KEY_TIME_BETWEEN_EVICTION_RUNS_MILLIS = "pool.timeBetweenEvictionRunsMillis";

    /**
     * @see PoolSpec#setNumTestsPerEvictionRun(int)
     */
    public static final String KEY_NUM_TESTS_PER_EVICTION_RUN = "pool.numTestsPerEvictionRun";

    /**
     * @see PoolSpec#setMinEvictableIdleTimeMillis(long)
     */
    public static final String KEY_MIN_EVICTABLE_IDLE_TIME_MILLIS = "pool.minEvictableIdleTimeMillis";

    /**
     * @see PoolSpec#setSoftMinEvictableIdleTimeMillis(long)
     */
    public static final String KEY_SOFT_MIN_EVICTABLE_IDLE_TIME_MILLIS = "pool.softMinEvictableIdleTimeMillis";

    /**
     * @see PoolSpec#setEvictionPolicyClassName(String)
     */
    public static final String KEY_EVICTION_POLICY_CLASS_NAME = "pool.evictionPolicyClassName";

    /**
     * @see PoolSpec#setLifo(boolean)
     */
    public static final String KEY_LIFO = "pool.lifo";

    /**
     * @see PoolSpec#setFairness(boolean)
     */
    public static final String KEY_FAIRNESS = "pool.fairness";

    /**
     * @see PoolSpec#setBlockWhenExhausted(boolean)
     */
    public static final String KEY_BLOCK_WHEN_EXHAUSTED = "pool.blockWhenExhausted";

    /**
     * @see PoolSpec#setJmxEnabled(boolean)
     */
    public static final String KEY_JMX_ENABLED = "pool.jmxEnabled";

    /**
     * @see PoolSpec#setJmxNamePrefix(String)
     */
    public static final String KEY_JMX_NAME_PREFIX = "pool.jmxNamePrefix";

    /**
     * @see PoolSpec#setJmxNameBase(String)
     */
    public static final String KEY_JMX_NAME_BASE = "pool.jmxNameBase";


    /**
     * A private constructor to prevent instantiation of this class
     */
    private PoolSpecBuilder() {
    }

    /**
     * Create a spec based on key / values in a <code>HashMap</code>.
     *
     * @param properties A <code>HashMap</code> with configuration properties, using the keys as specified in this class
     * @return A spec object with default values, plus the provided parameters
     * @throws NullPointerException When {@code properties} is {@code null}
     */
    // CHECKSTYLE:OFF
    // this is flagged in checkstyle with a missing whitespace before '}', which is a bug in checkstyle
    // suppress warnings about this method being too long (not much point in splitting up this one!)
    // suppress warnings about this method being too complex (can't extract a generic subroutine to reduce exec paths)
    @SuppressWarnings({"PMD.ExcessiveMethodLength", "PMD.NPathComplexity", "PMD.NcssMethodCount", "PMD.CyclomaticComplexity", "PMD.StdCyclomaticComplexity", "PMD.ModifiedCyclomaticComplexity"})
    // CHECKSTYLE:ON
    public static PoolSpec build(final Map<String, String> properties) {

        Validate.notNull(properties, "The validated object 'properties' is null");

        final PoolSpec spec = new PoolSpec();
        String tmp = properties.get(KEY_MAX_TOTAL);
        if (StringUtils.isNotEmpty(tmp)) {
            if (StringUtils.isNumeric(tmp)) {
                spec.setMaxTotal(Integer.decode(tmp));
                logValue(KEY_MAX_TOTAL, tmp);
            } else {
                logDefault(KEY_MAX_TOTAL, tmp, "not numeric", String.valueOf(spec.getMaxTotal()));
            }
        } else {
            logDefault(KEY_MAX_TOTAL, String.valueOf(spec.getMaxTotal()));
        }

        tmp = properties.get(KEY_MAX_IDLE);
        if (StringUtils.isNotEmpty(tmp)) {
            if (StringUtils.isNumeric(tmp)) {
                spec.setMaxIdle(Integer.decode(tmp));
                logValue(KEY_MAX_IDLE, tmp);
            } else {
                logDefault(KEY_MAX_IDLE, tmp, "not numeric", String.valueOf(spec.getMaxIdle()));
            }
        } else {
            logDefault(KEY_MAX_IDLE, String.valueOf(spec.getMaxIdle()));
        }

        tmp = properties.get(KEY_MIN_IDLE);
        if (StringUtils.isNotEmpty(tmp)) {
            if (StringUtils.isNumeric(tmp)) {
                spec.setMinIdle(Integer.decode(tmp));
                logValue(KEY_MIN_IDLE, tmp);
            } else {
                logDefault(KEY_MIN_IDLE, tmp, "not numeric", String.valueOf(spec.getMinIdle()));
            }
        } else {
            logDefault(KEY_MIN_IDLE, String.valueOf(spec.getMinIdle()));
        }

        tmp = properties.get(KEY_MAX_WAIT_MILLIS);
        if (StringUtils.isNotEmpty(tmp)) {
            if (StringUtils.isNumeric(tmp)) {
                spec.setMaxWaitMillis(Long.decode(tmp));
                logValue(KEY_MAX_WAIT_MILLIS, tmp);
            } else {
                logDefault(KEY_MAX_WAIT_MILLIS, tmp, "not numeric", String.valueOf(spec.getMaxWaitMillis()));
            }
        } else {
            logDefault(KEY_MAX_WAIT_MILLIS, String.valueOf(spec.getMaxWaitMillis()));
        }

        tmp = properties.get(KEY_TEST_ON_CREATE);
        if (StringUtils.isNotEmpty(tmp)) {
            spec.setTestOnCreate(Boolean.parseBoolean(tmp));
            logValue(KEY_TEST_ON_CREATE, tmp);
        } else {
            logDefault(KEY_TEST_ON_CREATE, String.valueOf(spec.isTestOnCreate()));
        }

        tmp = properties.get(KEY_TEST_ON_BORROW);
        if (StringUtils.isNotEmpty(tmp)) {
            spec.setTestOnBorrow(Boolean.parseBoolean(tmp));
            logValue(KEY_TEST_ON_BORROW, tmp);
        } else {
            logDefault(KEY_TEST_ON_BORROW, String.valueOf(spec.isTestOnBorrow()));
        }

        tmp = properties.get(KEY_TEST_ON_RETURN);
        if (StringUtils.isNotEmpty(tmp)) {
            spec.setTestOnReturn(Boolean.parseBoolean(tmp));
            logValue(KEY_TEST_ON_RETURN, tmp);
        } else {
            logDefault(KEY_TEST_ON_RETURN, String.valueOf(spec.isTestOnReturn()));
        }

        tmp = properties.get(KEY_TEST_WHILE_IDLE);
        if (StringUtils.isNotEmpty(tmp)) {
            spec.setTestWhileIdle(Boolean.parseBoolean(tmp));
            logValue(KEY_TEST_WHILE_IDLE, tmp);
        } else {
            logDefault(KEY_TEST_WHILE_IDLE, String.valueOf(spec.isTestWhileIdle()));
        }

        tmp = properties.get(KEY_TIME_BETWEEN_EVICTION_RUNS_MILLIS);
        if (StringUtils.isNotEmpty(tmp)) {
            if (StringUtils.isNumeric(tmp)) {
                spec.setTimeBetweenEvictionRunsMillis(Long.decode(tmp));
                logValue(KEY_TIME_BETWEEN_EVICTION_RUNS_MILLIS, tmp);
            } else {
                logDefault(KEY_TIME_BETWEEN_EVICTION_RUNS_MILLIS, tmp, "not numeric",
                        String.valueOf(spec.getTimeBetweenEvictionRunsMillis()));
            }
        } else {
            logDefault(KEY_TIME_BETWEEN_EVICTION_RUNS_MILLIS, String.valueOf(spec.getTimeBetweenEvictionRunsMillis()));
        }

        tmp = properties.get(KEY_NUM_TESTS_PER_EVICTION_RUN);
        if (StringUtils.isNotEmpty(tmp)) {
            if (StringUtils.isNumeric(tmp)) {
                spec.setNumTestsPerEvictionRun(Integer.decode(tmp));
                logValue(KEY_NUM_TESTS_PER_EVICTION_RUN, tmp);
            } else {
                logDefault(KEY_NUM_TESTS_PER_EVICTION_RUN, tmp, "not numeric",
                        String.valueOf(spec.getNumTestsPerEvictionRun()));
            }
        } else {
            logDefault(KEY_NUM_TESTS_PER_EVICTION_RUN, String.valueOf(spec.getNumTestsPerEvictionRun()));
        }

        tmp = properties.get(KEY_MIN_EVICTABLE_IDLE_TIME_MILLIS);
        if (StringUtils.isNotEmpty(tmp)) {
            if (StringUtils.isNumeric(tmp)) {
                spec.setMinEvictableIdleTimeMillis(Long.decode(tmp));
                logValue(KEY_MIN_EVICTABLE_IDLE_TIME_MILLIS, tmp);
            } else {
                logDefault(KEY_MIN_EVICTABLE_IDLE_TIME_MILLIS, tmp, "not numeric",
                        String.valueOf(spec.getMinEvictableIdleTimeMillis()));
            }
        } else {
            logDefault(KEY_MIN_EVICTABLE_IDLE_TIME_MILLIS, String.valueOf(spec.getMinEvictableIdleTimeMillis()));
        }

        tmp = properties.get(KEY_SOFT_MIN_EVICTABLE_IDLE_TIME_MILLIS);
        if (StringUtils.isNotEmpty(tmp)) {
            if (StringUtils.isNumeric(tmp)) {
                spec.setSoftMinEvictableIdleTimeMillis(Long.decode(tmp));
                logValue(KEY_SOFT_MIN_EVICTABLE_IDLE_TIME_MILLIS, tmp);
            } else {
                logDefault(KEY_SOFT_MIN_EVICTABLE_IDLE_TIME_MILLIS, tmp, "not numeric",
                        String.valueOf(spec.getSoftMinEvictableIdleTimeMillis()));
            }
        } else {
            logDefault(KEY_SOFT_MIN_EVICTABLE_IDLE_TIME_MILLIS,
                    String.valueOf(spec.getSoftMinEvictableIdleTimeMillis()));
        }

        tmp = properties.get(KEY_EVICTION_POLICY_CLASS_NAME);
        if (StringUtils.isNotEmpty(tmp)) {
            spec.setEvictionPolicyClassName(tmp);
            logValue(KEY_EVICTION_POLICY_CLASS_NAME, tmp);
        } else {
            logDefault(KEY_EVICTION_POLICY_CLASS_NAME, spec.getEvictionPolicyClassName());
        }

        tmp = properties.get(KEY_LIFO);
        if (StringUtils.isNotEmpty(tmp)) {
            spec.setLifo(Boolean.parseBoolean(tmp));
            logValue(KEY_LIFO, tmp);
        } else {
            logDefault(KEY_LIFO, String.valueOf(spec.isLifo()));
        }

        tmp = properties.get(KEY_FAIRNESS);
        if (StringUtils.isNotEmpty(tmp)) {
            spec.setFairness(Boolean.parseBoolean(tmp));
            logValue(KEY_FAIRNESS, tmp);
        } else {
            logDefault(KEY_FAIRNESS, String.valueOf(spec.isFairness()));
        }

        tmp = properties.get(KEY_BLOCK_WHEN_EXHAUSTED);
        if (StringUtils.isNotEmpty(tmp)) {
            spec.setBlockWhenExhausted(Boolean.parseBoolean(tmp));
            logValue(KEY_BLOCK_WHEN_EXHAUSTED, tmp);
        } else {
            logDefault(KEY_BLOCK_WHEN_EXHAUSTED, String.valueOf(spec.isBlockWhenExhausted()));
        }

        tmp = properties.get(KEY_JMX_ENABLED);
        if (StringUtils.isNotEmpty(tmp)) {
            spec.setJmxEnabled(Boolean.parseBoolean(tmp));
            logValue(KEY_JMX_ENABLED, tmp);
        } else {
            logDefault(KEY_JMX_ENABLED, String.valueOf(spec.isJmxEnabled()));
        }

        tmp = properties.get(KEY_JMX_NAME_PREFIX);
        if (StringUtils.isNotEmpty(tmp)) {
            spec.setJmxNamePrefix(tmp);
            logValue(KEY_JMX_NAME_PREFIX, tmp);
        } else {
            logDefault(KEY_JMX_NAME_PREFIX, spec.getJmxNamePrefix());
        }

        tmp = properties.get(KEY_JMX_NAME_BASE);
        if (StringUtils.isNotEmpty(tmp)) {
            spec.setJmxNameBase(tmp);
            logValue(KEY_JMX_NAME_BASE, tmp);
        } else {
            logDefault(KEY_JMX_NAME_BASE, spec.getJmxNameBase());
        }

        // set the additional properties, preserving the originally provided properties
        // create a defensive copy of the map and all its properties
        // the code looks a little more complicated than a simple "putAll()", but it catches situations
        // where a Map is provided that supports null values (e.g. a HashMap) vs Map implementations
        // that do not (e.g. ConcurrentHashMap).
        final Map<String, String> tempMap = new ConcurrentHashMap<>();
        for (final Map.Entry<String, String> entry : properties.entrySet()) {
            final String key = entry.getKey();
            final String value = entry.getValue();

            if (value != null) {
                tempMap.put(key, value);
            }
        }
        spec.setAdditionalProperties(tempMap);

        return spec;
    }

    /**
     * Create a log entry when a value has been successfully configured.
     *
     * @param key   The configuration key
     * @param value The value that is being used
     */
    private static void logValue(final String key, final String value) {

        // Fortify will report a violation here because of disclosure of potentially confidential information.
        // However, the configuration keys are not confidential, which makes this a non-issue / false positive.
        if (LOG.isInfoEnabled()) {
            final StringBuilder msg = new StringBuilder("Key found in configuration ('")
                    .append(key)
                    .append("'), using configured value (not disclosed here for security reasons)");
            LOG.info(msg.toString());
        }

        // Fortify will report a violation here because of disclosure of potentially confidential information.
        // The configuration VALUES are confidential. DO NOT activate DEBUG logging in production.
        if (LOG.isDebugEnabled()) {
            final StringBuilder msg = new StringBuilder("Key found in configuration ('")
                    .append(key)
                    .append("'), using configured value ('");
            if (value == null) {
                msg.append("null')");
            } else {
                msg.append(value).append("')");
            }
            LOG.debug(msg.toString());
        }
    }

    /**
     * Create a log entry when a default value is being used in case the propsbuilder key has not been provided in the
     * configuration.
     *
     * @param key          The configuration key
     * @param defaultValue The default value that is being used
     */
    private static void logDefault(final String key, final String defaultValue) {

        // Fortify will report a violation here because of disclosure of potentially confidential information.
        // However, neither the configuration keys nor the default propsbuilder values are confidential, which makes
        // this a non-issue / false positive.
        if (LOG.isInfoEnabled()) {
            final StringBuilder msg = new StringBuilder("Key is not configured ('")
                    .append(key)
                    .append("'), using default value ('");
            if (defaultValue == null) {
                msg.append("null')");
            } else {
                msg.append(defaultValue).append("')");
            }
            LOG.info(msg.toString());
        }
    }

    /**
     * Create a log entry when a default value is being used in case that an invalid configuration value has been
     * provided in the configuration for the propsbuilder key.
     *
     * @param key             The configuration key
     * @param invalidValue    The invalid value that cannot be used
     * @param validationError The validation error that caused the invalid value to be refused
     * @param defaultValue    The default value that is being used
     */
    // suppress warnings about not using an object for the four strings in this PRIVATE method
    @SuppressWarnings("PMD.UseObjectForClearerAPI")
    private static void logDefault(final String key,
                                   final String invalidValue,
                                   final String validationError,
                                   final String defaultValue) {

        if (LOG.isWarnEnabled()) {
            final StringBuilder msg = new StringBuilder("Invalid value ('")
                    .append(invalidValue)
                    .append("', ")
                    .append(validationError)
                    .append(") for key '")
                    .append(key)
                    .append("', using default instead ('");
            if (defaultValue == null) {
                msg.append("null')");
            } else {
                msg.append(defaultValue).append("')");
            }
            LOG.warn(msg.toString());
        }
    }
}
