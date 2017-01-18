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

import org.junit.Before;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.Assert.assertThat;

public class PoolSpecTest {

    private java.lang.reflect.Field field_additionalProperties;

    ///////////////////////////////////////////////////////////////////////////
    // Copy Constructor Tests
    ///////////////////////////////////////////////////////////////////////////

    /**
     * Test that the copy constructor creates a new object instance
     */
    @Test
    public void copyConstructorTest() {

        PoolSpec spec1 = new PoolSpec();
        PoolSpec spec2 = new PoolSpec(spec1);

        String error = "The copy constructor does not create a new object instance";
        assertThat(error, spec1, is(not(sameInstance(spec2))));
    }

    ///////////////////////////////////////////////////////////////////////////
    // Named Properties Tests
    ///////////////////////////////////////////////////////////////////////////

    /**
     * Max Total test
     */
    @Test
    public void maxTotalTest() {

        PoolSpec spec = new PoolSpec();

        // test default value
        String error = "property value does not match expected default value";
        assertThat(error, spec.getMaxTotal(),
                is(equalTo(PoolSpec.DEFAULT_MAX_TOTAL)));

        // test setter and getter
        error = "property value does not match expected value";
        spec.setMaxTotal(42);
        assertThat(error, spec.getMaxTotal(), is(equalTo(42)));

        // test copy constructor
        PoolSpec spec2 = new PoolSpec(spec);
        error = "copy constructor does not copy field";
        assertThat(error, spec2.getMaxTotal(), is(equalTo(42)));
    }

    /**
     * Max Idle test
     */
    @Test
    public void maxIdleTest() {

        PoolSpec spec = new PoolSpec();

        // test default value
        String error = "property value does not match expected default value";
        assertThat(error, spec.getMaxIdle(),
                is(equalTo(PoolSpec.DEFAULT_MAX_IDLE)));

        // test setter and getter
        error = "property value does not match expected value";
        spec.setMaxIdle(42);
        assertThat(error, spec.getMaxIdle(), is(equalTo(42)));

        // test copy constructor
        PoolSpec spec2 = new PoolSpec(spec);
        error = "copy constructor does not copy field";
        assertThat(error, spec2.getMaxIdle(), is(equalTo(42)));
    }

    /**
     * Min Idle test
     */
    @Test
    public void minIdleTest() {

        PoolSpec spec = new PoolSpec();

        // test default value
        String error = "property value does not match expected default value";
        assertThat(error, spec.getMinIdle(),
                is(equalTo(PoolSpec.DEFAULT_MIN_IDLE)));

        // test setter and getter
        error = "property value does not match expected value";
        spec.setMinIdle(42);
        assertThat(error, spec.getMinIdle(), is(equalTo(42)));

        // test copy constructor
        PoolSpec spec2 = new PoolSpec(spec);
        error = "copy constructor does not copy field";
        assertThat(error, spec2.getMinIdle(), is(equalTo(42)));
    }

    /**
     * Max Wait Millis test
     */
    @Test
    public void maxWaitMillisTest() {

        PoolSpec spec = new PoolSpec();

        // test default value
        String error = "property value does not match expected default value";
        assertThat(error, spec.getMaxWaitMillis(),
                is(equalTo(PoolSpec.DEFAULT_MAX_WAIT_MILLIS)));

        // test setter and getter
        error = "property value does not match expected value";
        spec.setMaxWaitMillis(42);
        assertThat(error, spec.getMaxWaitMillis(), is(equalTo(42L)));

        // test copy constructor
        PoolSpec spec2 = new PoolSpec(spec);
        error = "copy constructor does not copy field";
        assertThat(error, spec2.getMaxWaitMillis(), is(equalTo(42L)));
    }

    /**
     * Test On Create test
     */
    @Test
    public void testOnCreateTest() {

        PoolSpec spec = new PoolSpec();

        // test default value
        String error = "property value does not match expected default value";
        assertThat(error, spec.isTestOnCreate(),
                is(equalTo(PoolSpec.DEFAULT_TEST_ON_CREATE)));

        // test setter and getter
        error = "property value does not match expected value";
        spec.setTestOnCreate(!PoolSpec.DEFAULT_TEST_ON_CREATE);
        assertThat(error, spec.isTestOnCreate(), is(equalTo(!PoolSpec.DEFAULT_TEST_ON_CREATE)));

        // test copy constructor
        PoolSpec spec2 = new PoolSpec(spec);
        error = "copy constructor does not copy field";
        assertThat(error, spec2.isTestOnCreate(), is(equalTo(!PoolSpec.DEFAULT_TEST_ON_CREATE)));
    }

    /**
     * Test On Borrow test
     */
    @Test
    public void testOnBorrowTest() {

        PoolSpec spec = new PoolSpec();

        // test default value
        String error = "property value does not match expected default value";
        assertThat(error, spec.isTestOnBorrow(),
                is(equalTo(PoolSpec.DEFAULT_TEST_ON_BORROW)));

        // test setter and getter
        error = "property value does not match expected value";
        spec.setTestOnBorrow(!PoolSpec.DEFAULT_TEST_ON_BORROW);
        assertThat(error, spec.isTestOnBorrow(), is(equalTo(!PoolSpec.DEFAULT_TEST_ON_BORROW)));

        // test copy constructor
        PoolSpec spec2 = new PoolSpec(spec);
        error = "copy constructor does not copy field";
        assertThat(error, spec2.isTestOnBorrow(), is(equalTo(!PoolSpec.DEFAULT_TEST_ON_BORROW)));
    }

    /**
     * Test On Return test
     */
    @Test
    public void testOnReturnTest() {

        PoolSpec spec = new PoolSpec();

        // test default value
        String error = "property value does not match expected default value";
        assertThat(error, spec.isTestOnReturn(),
                is(equalTo(PoolSpec.DEFAULT_TEST_ON_RETURN)));

        // test setter and getter
        error = "property value does not match expected value";
        spec.setTestOnReturn(!PoolSpec.DEFAULT_TEST_ON_RETURN);
        assertThat(error, spec.isTestOnReturn(), is(equalTo(!PoolSpec.DEFAULT_TEST_ON_RETURN)));

        // test copy constructor
        PoolSpec spec2 = new PoolSpec(spec);
        error = "copy constructor does not copy field";
        assertThat(error, spec2.isTestOnReturn(), is(equalTo(!PoolSpec.DEFAULT_TEST_ON_RETURN)));
    }

    /**
     * Test While Idle test
     */
    @Test
    public void testWhileIdleTest() {

        PoolSpec spec = new PoolSpec();

        // test default value
        String error = "property value does not match expected default value";
        assertThat(error, spec.isTestWhileIdle(),
                is(equalTo(PoolSpec.DEFAULT_TEST_WHILE_IDLE)));

        // test setter and getter
        error = "property value does not match expected value";
        spec.setTestWhileIdle(!PoolSpec.DEFAULT_TEST_WHILE_IDLE);
        assertThat(error, spec.isTestWhileIdle(), is(equalTo(!PoolSpec.DEFAULT_TEST_WHILE_IDLE)));

        // test copy constructor
        PoolSpec spec2 = new PoolSpec(spec);
        error = "copy constructor does not copy field";
        assertThat(error, spec2.isTestWhileIdle(), is(equalTo(!PoolSpec.DEFAULT_TEST_WHILE_IDLE)));
    }

    /**
     * Time Between Eviction Runs Millis test
     */
    @Test
    public void timeBetweenEvictionRunsTest() {

        PoolSpec spec = new PoolSpec();

        // test default value
        String error = "property value does not match expected default value";
        assertThat(error, spec.getTimeBetweenEvictionRunsMillis(),
                is(equalTo(PoolSpec.DEFAULT_TIME_BETWEEN_EVICTION_RUNS_MILLIS)));

        // test setter and getter
        error = "property value does not match expected value";
        spec.setTimeBetweenEvictionRunsMillis(42);
        assertThat(error, spec.getTimeBetweenEvictionRunsMillis(), is(equalTo(42L)));

        // test copy constructor
        PoolSpec spec2 = new PoolSpec(spec);
        error = "copy constructor does not copy field";
        assertThat(error, spec2.getTimeBetweenEvictionRunsMillis(), is(equalTo(42L)));
    }

    /**
     * Num Tests Per Eviction Run test
     */
    @Test
    public void numTestsPerEvictionRunTest() {

        PoolSpec spec = new PoolSpec();

        // test default value
        String error = "property value does not match expected default value";
        assertThat(error, spec.getNumTestsPerEvictionRun(),
                is(equalTo(PoolSpec.DEFAULT_NUM_TESTS_PER_EVICTION_RUN)));

        // test setter and getter
        error = "property value does not match expected value";
        spec.setNumTestsPerEvictionRun(42);
        assertThat(error, spec.getNumTestsPerEvictionRun(), is(equalTo(42)));

        // test copy constructor
        PoolSpec spec2 = new PoolSpec(spec);
        error = "copy constructor does not copy field";
        assertThat(error, spec2.getNumTestsPerEvictionRun(), is(equalTo(42)));
    }

    /**
     * Min Evictable Idle Time Millis test
     */
    @Test
    public void minEvictableIdleTimeMillisTest() {

        PoolSpec spec = new PoolSpec();

        // test default value
        String error = "property value does not match expected default value";
        assertThat(error, spec.getMinEvictableIdleTimeMillis(),
                is(equalTo(PoolSpec.DEFAULT_MIN_EVICTABLE_IDLE_TIME_MILLIS)));

        // test setter and getter
        error = "property value does not match expected value";
        spec.setMinEvictableIdleTimeMillis(42);
        assertThat(error, spec.getMinEvictableIdleTimeMillis(), is(equalTo(42L)));

        // test copy constructor
        PoolSpec spec2 = new PoolSpec(spec);
        error = "copy constructor does not copy field";
        assertThat(error, spec2.getMinEvictableIdleTimeMillis(), is(equalTo(42L)));
    }

    /**
     * Soft Min Evictable Idle Time Millis test
     */
    @Test
    public void softMinEvictableIdleTimeMillisTest() {

        PoolSpec spec = new PoolSpec();

        // test default value
        String error = "property value does not match expected default value";
        assertThat(error, spec.getSoftMinEvictableIdleTimeMillis(),
                is(equalTo(PoolSpec.DEFAULT_SOFT_MIN_EVICTABLE_IDLE_TIME_MILLIS)));

        // test setter and getter
        error = "property value does not match expected value";
        spec.setSoftMinEvictableIdleTimeMillis(42);
        assertThat(error, spec.getSoftMinEvictableIdleTimeMillis(), is(equalTo(42L)));

        // test copy constructor
        PoolSpec spec2 = new PoolSpec(spec);
        error = "copy constructor does not copy field";
        assertThat(error, spec2.getSoftMinEvictableIdleTimeMillis(), is(equalTo(42L)));
    }

    /**
     * Eviction Policy Class Name test
     */
    @Test
    public void evictionPolicyClassNameTest() {

        PoolSpec spec = new PoolSpec();

        // test default value
        String error = "property value does not match expected default value";
        assertThat(error, spec.getEvictionPolicyClassName(),
                is(equalTo("org.apache.commons.pool2.impl.DefaultEvictionPolicy")));

        // test setter and getter
        error = "property value does not match expected value";
        spec.setEvictionPolicyClassName("42");
        assertThat(error, spec.getEvictionPolicyClassName(), is(equalTo("42")));

        // test copy constructor
        PoolSpec spec2 = new PoolSpec(spec);
        error = "copy constructor does not copy field";
        assertThat(error, spec2.getEvictionPolicyClassName(), is(equalTo("42")));
    }

    /**
     * Lifo test
     */
    @Test
    public void lifoTest() {

        PoolSpec spec = new PoolSpec();

        // test default value
        String error = "property value does not match expected default value";
        assertThat(error, spec.isLifo(),
                is(equalTo(PoolSpec.DEFAULT_LIFO)));

        // test setter and getter
        error = "property value does not match expected value";
        spec.setLifo(!PoolSpec.DEFAULT_LIFO);
        assertThat(error, spec.isLifo(), is(equalTo(!PoolSpec.DEFAULT_LIFO)));

        // test copy constructor
        PoolSpec spec2 = new PoolSpec(spec);
        error = "copy constructor does not copy field";
        assertThat(error, spec2.isLifo(), is(equalTo(!PoolSpec.DEFAULT_LIFO)));
    }

    /**
     * Fairness test
     */
    @Test
    public void fairnessTest() {

        PoolSpec spec = new PoolSpec();

        // test default value
        String error = "property value does not match expected default value";
        assertThat(error, spec.isFairness(),
                is(equalTo(PoolSpec.DEFAULT_FAIRNESS)));

        // test setter and getter
        error = "property value does not match expected value";
        spec.setFairness(!PoolSpec.DEFAULT_FAIRNESS);
        assertThat(error, spec.isFairness(), is(equalTo(!PoolSpec.DEFAULT_FAIRNESS)));

        // test copy constructor
        PoolSpec spec2 = new PoolSpec(spec);
        error = "copy constructor does not copy field";
        assertThat(error, spec2.isFairness(), is(equalTo(!PoolSpec.DEFAULT_FAIRNESS)));
    }

    /**
     * Block When Exhausted test
     */
    @Test
    public void blockWhenExhaustedTest() {

        PoolSpec spec = new PoolSpec();

        // test default value
        String error = "property value does not match expected default value";
        assertThat(error, spec.isBlockWhenExhausted(),
                is(equalTo(PoolSpec.DEFAULT_BLOCK_WHEN_EXHAUSTED)));

        // test setter and getter
        error = "property value does not match expected value";
        spec.setBlockWhenExhausted(!PoolSpec.DEFAULT_BLOCK_WHEN_EXHAUSTED);
        assertThat(error, spec.isBlockWhenExhausted(), is(equalTo(!PoolSpec.DEFAULT_BLOCK_WHEN_EXHAUSTED)));

        // test copy constructor
        PoolSpec spec2 = new PoolSpec(spec);
        error = "copy constructor does not copy field";
        assertThat(error, spec2.isBlockWhenExhausted(), is(equalTo(!PoolSpec.DEFAULT_BLOCK_WHEN_EXHAUSTED)));
    }

    /**
     * Jmx Enabled test
     */
    @Test
    public void jmxEnabledTest() {

        PoolSpec spec = new PoolSpec();

        // test default value
        String error = "property value does not match expected default value";
        assertThat(error, spec.isJmxEnabled(),
                is(equalTo(PoolSpec.DEFAULT_JMX_ENABLED)));

        // test setter and getter
        error = "property value does not match expected value";
        spec.setJmxEnabled(!PoolSpec.DEFAULT_JMX_ENABLED);
        assertThat(error, spec.isJmxEnabled(), is(equalTo(!PoolSpec.DEFAULT_JMX_ENABLED)));

        // test copy constructor
        PoolSpec spec2 = new PoolSpec(spec);
        error = "copy constructor does not copy field";
        assertThat(error, spec2.isJmxEnabled(), is(equalTo(!PoolSpec.DEFAULT_JMX_ENABLED)));
    }

    /**
     * Jmx Prefix test
     */
    @Test
    public void jmxPrefixTest() {

        PoolSpec spec = new PoolSpec();

        // test default value
        String error = "property value does not match expected default value";
        assertThat(error, spec.getJmxNamePrefix(),
                is(equalTo(PoolSpec.DEFAULT_JMX_NAME_PREFIX)));

        // test setter and getter
        error = "property value does not match expected value";
        spec.setJmxNamePrefix("42");
        assertThat(error, spec.getJmxNamePrefix(), is(equalTo("42")));

        // test copy constructor
        PoolSpec spec2 = new PoolSpec(spec);
        error = "copy constructor does not copy field";
        assertThat(error, spec2.getJmxNamePrefix(), is(equalTo("42")));
    }

    /**
     * Jmx Base test
     */
    @Test
    public void jmxBaseTest() {

        PoolSpec spec = new PoolSpec();

        // test default value
        String error = "property value does not match expected default value";
        assertThat(error, spec.getJmxNameBase(),
                is(equalTo(PoolSpec.DEFAULT_JMX_NAME_BASE)));

        // test setter and getter
        error = "property value does not match expected value";
        spec.setJmxNameBase("42");
        assertThat(error, spec.getJmxNameBase(), is(equalTo("42")));

        // test copy constructor
        PoolSpec spec2 = new PoolSpec(spec);
        error = "copy constructor does not copy field";
        assertThat(error, spec2.getJmxNameBase(), is(equalTo("42")));
    }

    ///////////////////////////////////////////////////////////////////////////
    // Additional (unnamed) Properties Tests
    ///////////////////////////////////////////////////////////////////////////

    /**
     * Make some of the private fields in the spec class accessible.
     * <p>
     * This is executed before every test to ensure consistency even if one of the tests mock with field accessibility.
     */
    @Before
    public void makeAdditionalPropertiesPrivateFieldsAccessible() {

        // make private fields accessible as needed
        try {
            field_additionalProperties = PoolSpec.class.getDeclaredField("additionalProperties");
        } catch (NoSuchFieldException e) {
            AssertionError ae = new AssertionError("An expected private field does not exist");
            ae.initCause(e);
            throw ae;
        }
        field_additionalProperties.setAccessible(true);
    }

    /**
     * Test that the additional properties are never <code>null</code>
     */
    @Test
    public void additionalPropertiesAreNeverNullTest() {

        String key = "some property";
        String value = "some value";

        Map<String, String> originalMap = new HashMap<>();

        originalMap.put(key, value);
        PoolSpec spec = new PoolSpec();

        String error = "The additional properties are null after create";
        try {
            Map<String, String> mapInObject = (Map<String, String>) field_additionalProperties.get(spec);
            assertThat(error, mapInObject, is(not(nullValue())));
        } catch (IllegalAccessException e) {
            AssertionError ae = new AssertionError("Cannot access private field");
            ae.initCause(e);
            throw ae;
        }

        spec = new PoolSpec();
        error = "The additional properties are null after null put";
        spec.setAdditionalProperties(null);
        try {
            Map<String, String> mapInObject = (Map<String, String>) field_additionalProperties.get(spec);
            assertThat(error, mapInObject, is(not(nullValue())));
        } catch (IllegalAccessException e) {
            AssertionError ae = new AssertionError("Cannot access private field");
            ae.initCause(e);
            throw ae;
        }

        spec = new PoolSpec();
        error = "The additional properties are null at get";
        Map<String, String> mapInObject = spec.getAdditionalProperties();
        assertThat(error, mapInObject, is(not(nullValue())));
    }

    /**
     * Test that the additional properties are copied inbound
     */
    @Test
    public void additionalPropertiesInboundDefensiveCopyTest() {

        String key = "some property";
        String value = "some value";

        Map<String, String> originalMap = new HashMap<>();

        originalMap.put(key, value);
        PoolSpec spec = new PoolSpec();
        spec.setAdditionalProperties(originalMap);

        String error = "The properties POJO does not create an inbound defensive copy";
        try {
            Map<String, String> mapInObject = (Map<String, String>) field_additionalProperties.get(spec);
            assertThat(error, mapInObject, is(not(sameInstance(originalMap))));
        } catch (IllegalAccessException e) {
            AssertionError ae = new AssertionError("Cannot access private field");
            ae.initCause(e);
            throw ae;
        }
    }

    /**
     * Test that the additional properties are copied outbound
     */
    @Test
    public void additionalPropertiesOutboundDefensiveCopyTest() {

        PoolSpec spec = new PoolSpec();

        String error = "The properties POJO does not create an outbound defensive copy";
        try {
            Map<String, String> mapInObject = (Map<String, String>) field_additionalProperties.get(spec);
            assertThat(error, mapInObject, is(not(sameInstance(spec.getAdditionalProperties()))));
        } catch (IllegalAccessException e) {
            AssertionError ae = new AssertionError("Cannot access private field");
            ae.initCause(e);
            throw ae;
        }
    }
}
