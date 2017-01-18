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

import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.Assert.assertThat;

public class PoolSpecBuilderTest {

    ///////////////////////////////////////////////////////////////////////////
    // Named Properties Tests
    //   (test the explicitly named properties)
    ///////////////////////////////////////////////////////////////////////////

    /**
     * Max Total test
     */
    @Test
    public void maxTotalTest() {

        Map<String, String> map = new HashMap<>();

        // test that a missing value in the map results in the default value being set in the spec
        PoolSpec spec = PoolSpecBuilder.build(map);
        String error = "spec value does not match expected default value";
        assertThat(error, spec.getMaxTotal(), is(equalTo(PoolSpec.DEFAULT_MAX_TOTAL)));

        // test that a null value in the map results in the default value being set in the spec
        map.put(PoolSpecBuilder.KEY_MAX_TOTAL, null);
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected default value";
        assertThat(error, spec.getMaxTotal(), is(equalTo(PoolSpec.DEFAULT_MAX_TOTAL)));

        // test that an invalid value in the map results in the default value being set in the spec
        map.put(PoolSpecBuilder.KEY_MAX_TOTAL, "asdf");
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected default value";
        assertThat(error, spec.getMaxTotal(), is(equalTo(PoolSpec.DEFAULT_MAX_TOTAL)));

        // test that a value in the map is correctly set in the spec
        map.put(PoolSpecBuilder.KEY_MAX_TOTAL, "42");
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected value";
        assertThat(error, spec.getMaxTotal(), is(equalTo(42)));
    }

    /**
     * Max Idle test
     */
    @Test
    public void maxIdleTest() {

        Map<String, String> map = new HashMap<>();

        // test that a missing value in the map results in the default value being set in the spec
        PoolSpec spec = PoolSpecBuilder.build(map);
        String error = "spec value does not match expected default value";
        assertThat(error, spec.getMaxIdle(), is(equalTo(PoolSpec.DEFAULT_MAX_IDLE)));

        // test that a null value in the map results in the default value being set in the spec
        map.put(PoolSpecBuilder.KEY_MAX_IDLE, null);
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected default value";
        assertThat(error, spec.getMaxIdle(), is(equalTo(PoolSpec.DEFAULT_MAX_IDLE)));

        // test that an invalid value in the map results in the default value being set in the spec
        map.put(PoolSpecBuilder.KEY_MAX_IDLE, "asdf");
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected default value";
        assertThat(error, spec.getMaxIdle(), is(equalTo(PoolSpec.DEFAULT_MAX_IDLE)));

        // test that a value in the map is correctly set in the spec
        map.put(PoolSpecBuilder.KEY_MAX_IDLE, "42");
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected value";
        assertThat(error, spec.getMaxIdle(), is(equalTo(42)));
    }

    /**
     * Min Idle test
     */
    @Test
    public void minIdleTest() {

        Map<String, String> map = new HashMap<>();

        // test that a missing value in the map results in the default value being set in the spec
        PoolSpec spec = PoolSpecBuilder.build(map);
        String error = "spec value does not match expected default value";
        assertThat(error, spec.getMinIdle(), is(equalTo(PoolSpec.DEFAULT_MIN_IDLE)));

        // test that a null value in the map results in the default value being set in the spec
        map.put(PoolSpecBuilder.KEY_MIN_IDLE, null);
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected default value";
        assertThat(error, spec.getMinIdle(), is(equalTo(PoolSpec.DEFAULT_MIN_IDLE)));

        // test that an invalid value in the map results in the default value being set in the spec
        map.put(PoolSpecBuilder.KEY_MIN_IDLE, "asdf");
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected default value";
        assertThat(error, spec.getMinIdle(), is(equalTo(PoolSpec.DEFAULT_MIN_IDLE)));

        // test that a value in the map is correctly set in the spec
        map.put(PoolSpecBuilder.KEY_MIN_IDLE, "42");
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected value";
        assertThat(error, spec.getMinIdle(), is(equalTo(42)));
    }

    /**
     * Max Wait Millis test
     */
    @Test
    public void maxWaitMillisTest() {

        Map<String, String> map = new HashMap<>();

        // test that a missing value in the map results in the default value being set in the spec
        PoolSpec spec = PoolSpecBuilder.build(map);
        String error = "spec value does not match expected default value";
        assertThat(error, spec.getMaxWaitMillis(), is(equalTo(PoolSpec.DEFAULT_MAX_WAIT_MILLIS)));

        // test that a null value in the map results in the default value being set in the spec
        map.put(PoolSpecBuilder.KEY_MAX_WAIT_MILLIS, null);
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected default value";
        assertThat(error, spec.getMaxWaitMillis(), is(equalTo(PoolSpec.DEFAULT_MAX_WAIT_MILLIS)));

        // test that an invalid value in the map results in the default value being set in the spec
        map.put(PoolSpecBuilder.KEY_MAX_WAIT_MILLIS, "asdf");
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected default value";
        assertThat(error, spec.getMaxWaitMillis(), is(equalTo(PoolSpec.DEFAULT_MAX_WAIT_MILLIS)));

        // test that a value in the map is correctly set in the spec
        map.put(PoolSpecBuilder.KEY_MAX_WAIT_MILLIS, "42");
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected value";
        assertThat(error, spec.getMaxWaitMillis(), is(equalTo(42L)));
    }

    /**
     * Test On Create test
     */
    @Test
    public void testOnCreateTest() {

        Map<String, String> map = new HashMap<>();

        // test that a missing value in the map results in the default value being set in the spec
        PoolSpec spec = PoolSpecBuilder.build(map);
        String error = "spec value does not match expected default value";
        assertThat(error, spec.isTestOnCreate(), is(equalTo(PoolSpec.DEFAULT_TEST_ON_CREATE)));

        // test that a null value in the map results in the default value being set in the spec
        map.put(PoolSpecBuilder.KEY_TEST_ON_CREATE, null);
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected default value";
        assertThat(error, spec.isTestOnCreate(), is(equalTo(PoolSpec.DEFAULT_TEST_ON_CREATE)));

        // test that an invalid value in the map results in 'false' being set in the spec
        map.put(PoolSpecBuilder.KEY_TEST_ON_CREATE, "asdf");
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected default value";
        assertThat(error, spec.isTestOnCreate(), is(equalTo(false)));

        // test that a value in the map is correctly set in the spec
        map.put(PoolSpecBuilder.KEY_TEST_ON_CREATE, "tRuE");
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected value";
        assertThat(error, spec.isTestOnCreate(), is(equalTo(true)));
    }

    /**
     * Test On Borrow test
     */
    @Test
    public void testOnBorrowTest() {

        Map<String, String> map = new HashMap<>();

        // test that a missing value in the map results in the default value being set in the spec
        PoolSpec spec = PoolSpecBuilder.build(map);
        String error = "spec value does not match expected default value";
        assertThat(error, spec.isTestOnBorrow(), is(equalTo(PoolSpec.DEFAULT_TEST_ON_BORROW)));

        // test that a null value in the map results in the default value being set in the spec
        map.put(PoolSpecBuilder.KEY_TEST_ON_BORROW, null);
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected default value";
        assertThat(error, spec.isTestOnBorrow(), is(equalTo(PoolSpec.DEFAULT_TEST_ON_BORROW)));

        // test that an invalid value in the map results in 'false' being set in the spec
        map.put(PoolSpecBuilder.KEY_TEST_ON_BORROW, "asdf");
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected default value";
        assertThat(error, spec.isTestOnBorrow(), is(equalTo(false)));

        // test that a value in the map is correctly set in the spec
        map.put(PoolSpecBuilder.KEY_TEST_ON_BORROW, "tRuE");
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected value";
        assertThat(error, spec.isTestOnBorrow(), is(equalTo(true)));
    }

    /**
     * Test On Return test
     */
    @Test
    public void testOnReturnTest() {

        Map<String, String> map = new HashMap<>();

        // test that a missing value in the map results in the default value being set in the spec
        PoolSpec spec = PoolSpecBuilder.build(map);
        String error = "spec value does not match expected default value";
        assertThat(error, spec.isTestOnReturn(), is(equalTo(PoolSpec.DEFAULT_TEST_ON_RETURN)));

        // test that a null value in the map results in the default value being set in the spec
        map.put(PoolSpecBuilder.KEY_TEST_ON_RETURN, null);
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected default value";
        assertThat(error, spec.isTestOnReturn(), is(equalTo(PoolSpec.DEFAULT_TEST_ON_RETURN)));

        // test that an invalid value in the map results in 'false' being set in the spec
        map.put(PoolSpecBuilder.KEY_TEST_ON_RETURN, "asdf");
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected default value";
        assertThat(error, spec.isTestOnReturn(), is(equalTo(false)));

        // test that a value in the map is correctly set in the spec
        map.put(PoolSpecBuilder.KEY_TEST_ON_RETURN, "tRuE");
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected value";
        assertThat(error, spec.isTestOnReturn(), is(equalTo(true)));
    }

    /**
     * Test While Idle test
     */
    @Test
    public void testWhileIdleTest() {

        Map<String, String> map = new HashMap<>();

        // test that a missing value in the map results in the default value being set in the spec
        PoolSpec spec = PoolSpecBuilder.build(map);
        String error = "spec value does not match expected default value";
        assertThat(error, spec.isTestWhileIdle(), is(equalTo(PoolSpec.DEFAULT_TEST_WHILE_IDLE)));

        // test that a null value in the map results in the default value being set in the spec
        map.put(PoolSpecBuilder.KEY_TEST_WHILE_IDLE, null);
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected default value";
        assertThat(error, spec.isTestWhileIdle(), is(equalTo(PoolSpec.DEFAULT_TEST_WHILE_IDLE)));

        // test that an invalid value in the map results in 'false' being set in the spec
        map.put(PoolSpecBuilder.KEY_TEST_WHILE_IDLE, "asdf");
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected default value";
        assertThat(error, spec.isTestWhileIdle(), is(equalTo(false)));

        // test that a value in the map is correctly set in the spec
        map.put(PoolSpecBuilder.KEY_TEST_WHILE_IDLE, "tRuE");
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected value";
        assertThat(error, spec.isTestWhileIdle(), is(equalTo(true)));
    }

    /**
     * Time Between Eviction Runs Millis test
     */
    @Test
    public void timeBetweenEvictionRunsMillisTest() {

        Map<String, String> map = new HashMap<>();

        // test that a missing value in the map results in the default value being set in the spec
        PoolSpec spec = PoolSpecBuilder.build(map);
        String error = "spec value does not match expected default value";
        assertThat(error, spec.getTimeBetweenEvictionRunsMillis(),
                is(equalTo(PoolSpec.DEFAULT_TIME_BETWEEN_EVICTION_RUNS_MILLIS)));

        // test that a null value in the map results in the default value being set in the spec
        map.put(PoolSpecBuilder.KEY_TIME_BETWEEN_EVICTION_RUNS_MILLIS, null);
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected default value";
        assertThat(error, spec.getTimeBetweenEvictionRunsMillis(),
                is(equalTo(PoolSpec.DEFAULT_TIME_BETWEEN_EVICTION_RUNS_MILLIS)));

        // test that an invalid value in the map results in the default value being set in the spec
        map.put(PoolSpecBuilder.KEY_TIME_BETWEEN_EVICTION_RUNS_MILLIS, "asdf");
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected default value";
        assertThat(error, spec.getTimeBetweenEvictionRunsMillis(),
                is(equalTo(PoolSpec.DEFAULT_TIME_BETWEEN_EVICTION_RUNS_MILLIS)));

        // test that a value in the map is correctly set in the spec
        map.put(PoolSpecBuilder.KEY_TIME_BETWEEN_EVICTION_RUNS_MILLIS, "42");
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected value";
        assertThat(error, spec.getTimeBetweenEvictionRunsMillis(), is(equalTo(42L)));
    }

    /**
     * Num Tests Per Eviction Run test
     */
    @Test
    public void numTestsPerEvictionRunTest() {

        Map<String, String> map = new HashMap<>();

        // test that a missing value in the map results in the default value being set in the spec
        PoolSpec spec = PoolSpecBuilder.build(map);
        String error = "spec value does not match expected default value";
        assertThat(error, spec.getNumTestsPerEvictionRun(),
                is(equalTo(PoolSpec.DEFAULT_NUM_TESTS_PER_EVICTION_RUN)));

        // test that a null value in the map results in the default value being set in the spec
        map.put(PoolSpecBuilder.KEY_NUM_TESTS_PER_EVICTION_RUN, null);
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected default value";
        assertThat(error, spec.getNumTestsPerEvictionRun(),
                is(equalTo(PoolSpec.DEFAULT_NUM_TESTS_PER_EVICTION_RUN)));

        // test that an invalid value in the map results in the default value being set in the spec
        map.put(PoolSpecBuilder.KEY_NUM_TESTS_PER_EVICTION_RUN, "asdf");
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected default value";
        assertThat(error, spec.getNumTestsPerEvictionRun(),
                is(equalTo(PoolSpec.DEFAULT_NUM_TESTS_PER_EVICTION_RUN)));

        // test that a value in the map is correctly set in the spec
        map.put(PoolSpecBuilder.KEY_NUM_TESTS_PER_EVICTION_RUN, "42");
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected value";
        assertThat(error, spec.getNumTestsPerEvictionRun(), is(equalTo(42)));
    }

    /**
     * Min Evictable Idle Time Millis test
     */
    @Test
    public void minEvictableIdleTimeMillisTest() {

        Map<String, String> map = new HashMap<>();

        // test that a missing value in the map results in the default value being set in the spec
        PoolSpec spec = PoolSpecBuilder.build(map);
        String error = "spec value does not match expected default value";
        assertThat(error, spec.getMinEvictableIdleTimeMillis(),
                is(equalTo(PoolSpec.DEFAULT_MIN_EVICTABLE_IDLE_TIME_MILLIS)));

        // test that a null value in the map results in the default value being set in the spec
        map.put(PoolSpecBuilder.KEY_MIN_EVICTABLE_IDLE_TIME_MILLIS, null);
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected default value";
        assertThat(error, spec.getMinEvictableIdleTimeMillis(),
                is(equalTo(PoolSpec.DEFAULT_MIN_EVICTABLE_IDLE_TIME_MILLIS)));

        // test that an invalid value in the map results in the default value being set in the spec
        map.put(PoolSpecBuilder.KEY_MIN_EVICTABLE_IDLE_TIME_MILLIS, "asdf");
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected default value";
        assertThat(error, spec.getMinEvictableIdleTimeMillis(),
                is(equalTo(PoolSpec.DEFAULT_MIN_EVICTABLE_IDLE_TIME_MILLIS)));

        // test that a value in the map is correctly set in the spec
        map.put(PoolSpecBuilder.KEY_MIN_EVICTABLE_IDLE_TIME_MILLIS, "42");
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected value";
        assertThat(error, spec.getMinEvictableIdleTimeMillis(), is(equalTo(42L)));
    }

    /**
     * Soft Min Evictable Idle Time Millis test
     */
    @Test
    public void softMinEvictableIdleTimeMillisTest() {

        Map<String, String> map = new HashMap<>();

        // test that a missing value in the map results in the default value being set in the spec
        PoolSpec spec = PoolSpecBuilder.build(map);
        String error = "spec value does not match expected default value";
        assertThat(error, spec.getSoftMinEvictableIdleTimeMillis(),
                is(equalTo(PoolSpec.DEFAULT_SOFT_MIN_EVICTABLE_IDLE_TIME_MILLIS)));

        // test that a null value in the map results in the default value being set in the spec
        map.put(PoolSpecBuilder.KEY_SOFT_MIN_EVICTABLE_IDLE_TIME_MILLIS, null);
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected default value";
        assertThat(error, spec.getSoftMinEvictableIdleTimeMillis(),
                is(equalTo(PoolSpec.DEFAULT_SOFT_MIN_EVICTABLE_IDLE_TIME_MILLIS)));

        // test that an invalid value in the map results in the default value being set in the spec
        map.put(PoolSpecBuilder.KEY_SOFT_MIN_EVICTABLE_IDLE_TIME_MILLIS, "asdf");
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected default value";
        assertThat(error, spec.getSoftMinEvictableIdleTimeMillis(),
                is(equalTo(PoolSpec.DEFAULT_SOFT_MIN_EVICTABLE_IDLE_TIME_MILLIS)));

        // test that a value in the map is correctly set in the spec
        map.put(PoolSpecBuilder.KEY_SOFT_MIN_EVICTABLE_IDLE_TIME_MILLIS, "42");
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected value";
        assertThat(error, spec.getSoftMinEvictableIdleTimeMillis(), is(equalTo(42L)));
    }

    /**
     * Eviction Policy Class Name test
     */
    @Test
    public void evictionPolicyClassNameTest() {

        Map<String, String> map = new HashMap<>();

        // test that a missing value in the map results in the default value being set in the spec
        PoolSpec spec = PoolSpecBuilder.build(map);
        String error = "spec value does not match expected default value";
        assertThat(error, spec.getEvictionPolicyClassName(),
                is(equalTo(PoolSpec.DEFAULT_EVICTION_POLICY_CLASS_NAME)));

        // test that a null value in the map results in the default value being set in the spec
        map.put(PoolSpecBuilder.KEY_EVICTION_POLICY_CLASS_NAME, null);
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected default value";
        assertThat(error, spec.getEvictionPolicyClassName(),
                is(equalTo(PoolSpec.DEFAULT_EVICTION_POLICY_CLASS_NAME)));

        // test that a value in the map is correctly set in the spec
        map.put(PoolSpecBuilder.KEY_EVICTION_POLICY_CLASS_NAME, "42");
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected value";
        assertThat(error, spec.getEvictionPolicyClassName(), is(equalTo("42")));
    }

    /**
     * Lifo test
     */
    @Test
    public void lifoTest() {

        Map<String, String> map = new HashMap<>();

        // test that a missing value in the map results in the default value being set in the spec
        PoolSpec spec = PoolSpecBuilder.build(map);
        String error = "spec value does not match expected default value";
        assertThat(error, spec.isLifo(), is(equalTo(PoolSpec.DEFAULT_LIFO)));

        // test that a null value in the map results in the default value being set in the spec
        map.put(PoolSpecBuilder.KEY_LIFO, null);
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected default value";
        assertThat(error, spec.isLifo(), is(equalTo(PoolSpec.DEFAULT_LIFO)));

        // test that an invalid value in the map results in 'false' being set in the spec
        map.put(PoolSpecBuilder.KEY_LIFO, "asdf");
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected default value";
        assertThat(error, spec.isLifo(), is(equalTo(false)));

        // test that a value in the map is correctly set in the spec
        map.put(PoolSpecBuilder.KEY_LIFO, "tRuE");
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected value";
        assertThat(error, spec.isLifo(), is(equalTo(true)));
    }

    /**
     * Fairness test
     */
    @Test
    public void fairnessTest() {

        Map<String, String> map = new HashMap<>();

        // test that a missing value in the map results in the default value being set in the spec
        PoolSpec spec = PoolSpecBuilder.build(map);
        String error = "spec value does not match expected default value";
        assertThat(error, spec.isFairness(), is(equalTo(PoolSpec.DEFAULT_FAIRNESS)));

        // test that a null value in the map results in the default value being set in the spec
        map.put(PoolSpecBuilder.KEY_FAIRNESS, null);
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected default value";
        assertThat(error, spec.isFairness(), is(equalTo(PoolSpec.DEFAULT_FAIRNESS)));

        // test that an invalid value in the map results in 'false' being set in the spec
        map.put(PoolSpecBuilder.KEY_FAIRNESS, "asdf");
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected default value";
        assertThat(error, spec.isFairness(), is(equalTo(false)));

        // test that a value in the map is correctly set in the spec
        map.put(PoolSpecBuilder.KEY_FAIRNESS, "tRuE");
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected value";
        assertThat(error, spec.isFairness(), is(equalTo(true)));
    }

    /**
     * Block When Exhausted test
     */
    @Test
    public void blockWhenExhaustedTest() {

        Map<String, String> map = new HashMap<>();

        // test that a missing value in the map results in the default value being set in the spec
        PoolSpec spec = PoolSpecBuilder.build(map);
        String error = "spec value does not match expected default value";
        assertThat(error, spec.isBlockWhenExhausted(), is(equalTo(PoolSpec.DEFAULT_BLOCK_WHEN_EXHAUSTED)));

        // test that a null value in the map results in the default value being set in the spec
        map.put(PoolSpecBuilder.KEY_BLOCK_WHEN_EXHAUSTED, null);
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected default value";
        assertThat(error, spec.isBlockWhenExhausted(), is(equalTo(PoolSpec.DEFAULT_BLOCK_WHEN_EXHAUSTED)));

        // test that an invalid value in the map results in 'false' being set in the spec
        map.put(PoolSpecBuilder.KEY_BLOCK_WHEN_EXHAUSTED, "asdf");
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected default value";
        assertThat(error, spec.isBlockWhenExhausted(), is(equalTo(false)));

        // test that a value in the map is correctly set in the spec
        map.put(PoolSpecBuilder.KEY_BLOCK_WHEN_EXHAUSTED, "tRuE");
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected value";
        assertThat(error, spec.isBlockWhenExhausted(), is(equalTo(true)));
    }

    /**
     * Jmx Enabled test
     */
    @Test
    public void jmxEnabledTest() {

        Map<String, String> map = new HashMap<>();

        // test that a missing value in the map results in the default value being set in the spec
        PoolSpec spec = PoolSpecBuilder.build(map);
        String error = "spec value does not match expected default value";
        assertThat(error, spec.isJmxEnabled(), is(equalTo(PoolSpec.DEFAULT_JMX_ENABLED)));

        // test that a null value in the map results in the default value being set in the spec
        map.put(PoolSpecBuilder.KEY_JMX_ENABLED, null);
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected default value";
        assertThat(error, spec.isJmxEnabled(), is(equalTo(PoolSpec.DEFAULT_JMX_ENABLED)));

        // test that an invalid value in the map results in 'false' being set in the spec
        map.put(PoolSpecBuilder.KEY_JMX_ENABLED, "asdf");
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected default value";
        assertThat(error, spec.isJmxEnabled(), is(equalTo(false)));

        // test that a value in the map is correctly set in the spec
        map.put(PoolSpecBuilder.KEY_JMX_ENABLED, "tRuE");
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected value";
        assertThat(error, spec.isJmxEnabled(), is(equalTo(true)));
    }

    /**
     * Jmx Name Prefix test
     */
    @Test
    public void jmxNamePrefixTest() {

        Map<String, String> map = new HashMap<>();

        // test that a missing value in the map results in the default value being set in the spec
        PoolSpec spec = PoolSpecBuilder.build(map);
        String error = "spec value does not match expected default value";
        assertThat(error, spec.getJmxNamePrefix(), is(equalTo(PoolSpec.DEFAULT_JMX_NAME_PREFIX)));

        // test that a null value in the map results in the default value being set in the spec
        map.put(PoolSpecBuilder.KEY_JMX_NAME_PREFIX, null);
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected default value";
        assertThat(error, spec.getJmxNamePrefix(), is(equalTo(PoolSpec.DEFAULT_JMX_NAME_PREFIX)));

        // test that a value in the map is correctly set in the spec
        map.put(PoolSpecBuilder.KEY_JMX_NAME_PREFIX, "42");
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected value";
        assertThat(error, spec.getJmxNamePrefix(), is(equalTo("42")));
    }

    /**
     * Jmx Name Base test
     */
    @Test
    public void jmxNameBaseTest() {

        Map<String, String> map = new HashMap<>();

        // test that a missing value in the map results in the default value being set in the spec
        PoolSpec spec = PoolSpecBuilder.build(map);
        String error = "spec value does not match expected default value";
        assertThat(error, spec.getJmxNameBase(), is(equalTo(PoolSpec.DEFAULT_JMX_NAME_BASE)));

        // test that a null value in the map results in the default value being set in the spec
        map.put(PoolSpecBuilder.KEY_JMX_NAME_BASE, null);
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected default value";
        assertThat(error, spec.getJmxNameBase(), is(equalTo(PoolSpec.DEFAULT_JMX_NAME_BASE)));

        // test that a value in the map is correctly set in the spec
        map.put(PoolSpecBuilder.KEY_JMX_NAME_BASE, "42");
        spec = PoolSpecBuilder.build(map);
        error = "spec value does not match expected value";
        assertThat(error, spec.getJmxNameBase(), is(equalTo("42")));
    }

    ///////////////////////////////////////////////////////////////////////////
    // Additional Properties Tests
    //   (test the additional properties that are not explicitly named)
    ///////////////////////////////////////////////////////////////////////////

    /**
     * additionalProperties test: make sure that the additional properties
     * are being set to a new object (i.e. a defensive copy is being made)
     */
    @Test
    public void additionalPropertiesNoSingletonTest() {

        String key = "some property";
        String value = "some value";

        Map<String, String> map = new HashMap<>();

        map.put(key, value);
        PoolSpec spec = PoolSpecBuilder.build(map);

        String error = "The properties builder returns a singleton";
        assertThat(error, map, is(not(sameInstance(spec.getAdditionalProperties()))));
    }
}
