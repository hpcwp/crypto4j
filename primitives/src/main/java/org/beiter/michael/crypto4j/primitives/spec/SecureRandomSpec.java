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

import org.apache.commons.lang3.Validate;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * This class specifies properties to define a {@code SecureRandom} instance.
 */
// CHECKSTYLE:OFF
// this is flagged in checkstyle with a missing whitespace before '}', which is a bug in checkstyle
// suppress warnings about the long variable names
// suppress CPD Warnings for this class
@SuppressWarnings({"CPD-START", "PMD.LongVariable"})
// CHECKSTYLE:ON
public class SecureRandomSpec {

    // #################
    // # Default values
    // #################

    /**
     * @see SecureRandomSpec#setProviderName(String)
     */
    public static final String DEFAULT_PRNG_PROVIDER_NAME = null;

    /**
     * @see SecureRandomSpec#setAlgorithmName(String)
     */
    public static final String DEFAULT_PRNG_ALGORITHM_NAME = null;

    // ===================================================================

    /**
     * @see SecureRandomSpec#setProviderName(String)
     */
    private String providerName = DEFAULT_PRNG_PROVIDER_NAME;

    /**
     * @see SecureRandomSpec#setAlgorithmName(String)
     */
    private String algorithmName = DEFAULT_PRNG_ALGORITHM_NAME;

    /**
     * @see SecureRandomSpec#setAdditionalProperties(Map<String, String>)
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
    public SecureRandomSpec() {

        // no code here, constructor just for java docs
    }

    /**
     * Creates a spec from an existing spec, making a defensive copy.
     *
     * @param spec The set of spec to copy
     * @throws NullPointerException When {@code spec} is {@code null}
     * @see SecureRandomSpec#SecureRandomSpec()
     */
    public SecureRandomSpec(final SecureRandomSpec spec) {

        this();

        Validate.notNull(spec, "The validated object 'spec' is null");

        setProviderName(spec.getProviderName());
        setAlgorithmName(spec.getAlgorithmName());
        setAdditionalProperties(spec.getAdditionalProperties());
    }

    /**
     * @return The provider to be used when instantiating a SecureRandom PRNG
     * @see SecureRandomSpec#setProviderName(String)
     */
    public final String getProviderName() {

        // no need for defensive copies of String

        return providerName;
    }

    /**
     * Set the provider to be used when instantiating a SecureRandom PRNG. When set to {@code null}, then the
     * {@link org.beiter.michael.crypto4j.primitives.SecureRandomFactory} traverses the list of registered security
     * {@code Providers}, starting with the most preferred {@code  Provider}. In this case, a {@code SecureRandom}
     * object encapsulating the {@code SecureRandomSpi} implementation from the first {@code Provider} that supports
     * the configured PRNG algorithm is returned.
     *
     * @param providerName The provider to be used when instantiating a SecureRandom PRNG
     * @throws IllegalArgumentException When the provided value of {@code providerName} is empty (null is allowed)
     */
    public final void setProviderName(final String providerName) {

        // null is allowed!
        if (providerName != null && providerName.isEmpty()) {
            throw new IllegalArgumentException("The validated object 'providerName' is empty");
        }

        // no need for defensive copies of String

        this.providerName = providerName;
    }

    /**
     * @return The name of the PRNG algorithm, as defined in the JCA Standard Algorithm Name Documentation
     * @see SecureRandomSpec#setAlgorithmName(String)
     */
    public final String getAlgorithmName() {

        // no need for defensive copies of String

        return algorithmName;
    }

    /**
     * Set the Random Number Generator (RNG) algorithm to be used when instantiating a {@code SecureRandom} PRNG.
     * When set to {@code null}, then the platform-default PRNG algorithm (as configured in the JCA subsystem) is used.
     *
     * @param algorithmName The name of the PRNG algorithm, as defined in the JCA Standard Algorithm Name Docs
     * @throws IllegalArgumentException When the provided value of {@code algorithmName} is empty (null is allowed)
     */
    public final void setAlgorithmName(final String algorithmName) {

        // null is allowed!
        if (algorithmName != null && algorithmName.isEmpty()) {
            throw new IllegalArgumentException("The validated object 'algorithmName' is empty");
        }

        // no need for defensive copies of String

        this.algorithmName = algorithmName;
    }

    /**
     * @return Any additional properties stored in this object that have not explicitly been parsed
     * @see SecureRandomSpec#setAdditionalProperties(Map)
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
