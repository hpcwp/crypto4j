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
package org.beiter.michael.crypto4j.primitives.spec;

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

public class MessageDigestSpecTest {

    private java.lang.reflect.Field field_additionalProperties;

    ///////////////////////////////////////////////////////////////////////////
    // Copy Constructor Tests
    ///////////////////////////////////////////////////////////////////////////

    /**
     * Test that the copy constructor creates a new object instance
     */
    @Test
    public void copyConstructorTest() {

        MessageDigestSpec spec1 = new MessageDigestSpec();
        MessageDigestSpec spec2 = new MessageDigestSpec(spec1);

        String error = "The copy constructor does not create a new object instance";
        assertThat(error, spec1, is(not(sameInstance(spec2))));
    }

    ///////////////////////////////////////////////////////////////////////////
    // Named Properties Tests
    ///////////////////////////////////////////////////////////////////////////

    /**
     * MD Provider Name test
     */
    @Test
    public void providerNameTest() {

        MessageDigestSpec spec = new MessageDigestSpec();

        // test default value
        String error = "property value does not match expected default value";
        assertThat(error, spec.getProviderName(),
                is(equalTo(MessageDigestSpec.DEFAULT_MD_PROVIDER_NAME)));

        // test setter and getter
        error = "property value does not match expected value";
        spec.setProviderName("42");
        assertThat(error, spec.getProviderName(), is(equalTo("42")));

        // test copy constructor
        MessageDigestSpec spec2 = new MessageDigestSpec(spec);
        error = "copy constructor does not copy field";
        assertThat(error, spec2.getProviderName(), is(equalTo("42")));
    }

    /**
     * MD Algorithm Name test
     */
    @Test
    public void algorithmNameTest() {

        MessageDigestSpec spec = new MessageDigestSpec();

        // test default value
        String error = "property value does not match expected default value";
        assertThat(error, spec.getAlgorithmName(),
                is(equalTo(MessageDigestSpec.DEFAULT_MD_ALGORITHM_NAME)));

        // test setter and getter
        error = "property value does not match expected value";
        spec.setAlgorithmName("42");
        assertThat(error, spec.getAlgorithmName(), is(equalTo("42")));

        // test copy constructor
        MessageDigestSpec spec2 = new MessageDigestSpec(spec);
        error = "copy constructor does not copy field";
        assertThat(error, spec2.getAlgorithmName(), is(equalTo("42")));
    }

    /**
     * MD Algorithm Name (empty value) test
     */
    @Test(expected = IllegalArgumentException.class)
    public void algorithmNameEmptyTest() {

        MessageDigestSpec spec = new MessageDigestSpec();

        // set an empty value, expect IllegalArgumentException
        spec.setAlgorithmName("");
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
            field_additionalProperties = MessageDigestSpec.class.getDeclaredField("additionalProperties");
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
        MessageDigestSpec spec = new MessageDigestSpec();

        String error = "The additional properties are null after create";
        try {
            Map<String, String> mapInObject = (Map<String, String>) field_additionalProperties.get(spec);
            assertThat(error, mapInObject, is(not(nullValue())));
        } catch (IllegalAccessException e) {
            AssertionError ae = new AssertionError("Cannot access private field");
            ae.initCause(e);
            throw ae;
        }

        spec = new MessageDigestSpec();
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

        spec = new MessageDigestSpec();
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
        MessageDigestSpec spec = new MessageDigestSpec();
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

        MessageDigestSpec spec = new MessageDigestSpec();

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
