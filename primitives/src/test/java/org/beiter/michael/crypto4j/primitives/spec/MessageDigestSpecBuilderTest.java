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

import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.Assert.assertThat;

public class MessageDigestSpecBuilderTest {

    ///////////////////////////////////////////////////////////////////////////
    // Named Properties Tests
    //   (test the explicitly named properties)
    ///////////////////////////////////////////////////////////////////////////

    /**
     * MD Provider Name test
     */
    @Test
    public void providerNameTest() {

        Map<String, String> map = new HashMap<>();

        // test that a missing value in the map results in the default value being set in the spec
        MessageDigestSpec spec = MessageDigestSpecBuilder.build(map);
        String error = "spec value does not match expected default value";
        assertThat(error, spec.getProviderName(),
                is(equalTo(MessageDigestSpec.DEFAULT_MD_PROVIDER_NAME)));

        // test that a null value in the map results in the default value being set in the spec
        map.put(MessageDigestSpecBuilder.KEY_PROVIDER_NAME, null);
        spec = MessageDigestSpecBuilder.build(map);
        error = "spec value does not match expected default value";
        assertThat(error, spec.getProviderName(),
                is(equalTo(MessageDigestSpec.DEFAULT_MD_PROVIDER_NAME)));

        // test that a value in the map is correctly set in the spec
        map.put(MessageDigestSpecBuilder.KEY_PROVIDER_NAME, "42");
        spec = MessageDigestSpecBuilder.build(map);
        error = "spec value does not match expected value";
        assertThat(error, spec.getProviderName(), is(equalTo("42")));
    }

    /**
     * MD Algorithm Name test
     */
    @Test
    public void algorithmNameTest() {

        Map<String, String> map = new HashMap<>();

        // test that a missing value in the map results in the default value being set in the spec
        MessageDigestSpec spec = MessageDigestSpecBuilder.build(map);
        String error = "spec value does not match expected default value";
        assertThat(error, spec.getAlgorithmName(),
                is(equalTo(MessageDigestSpec.DEFAULT_MD_ALGORITHM_NAME)));

        // test that a null value in the map results in the default value being set in the spec
        map.put(MessageDigestSpecBuilder.KEY_ALGORITHM_NAME, null);
        spec = MessageDigestSpecBuilder.build(map);
        error = "spec value does not match expected default value";
        assertThat(error, spec.getAlgorithmName(),
                is(equalTo(MessageDigestSpec.DEFAULT_MD_ALGORITHM_NAME)));

        // test that a value in the map is correctly set in the spec
        map.put(MessageDigestSpecBuilder.KEY_ALGORITHM_NAME, "42");
        spec = MessageDigestSpecBuilder.build(map);
        error = "spec value does not match expected value";
        assertThat(error, spec.getAlgorithmName(), is(equalTo("42")));
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
        MessageDigestSpec spec = MessageDigestSpecBuilder.build(map);

        String error = "The properties builder returns a singleton";
        assertThat(error, map, is(not(sameInstance(spec.getAdditionalProperties()))));
    }
}
