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
package org.beiter.michael.crypto4j.primitives.poolable;

import org.apache.commons.lang3.Validate;
import org.apache.commons.pool2.BasePooledObjectFactory;
import org.apache.commons.pool2.PooledObject;
import org.apache.commons.pool2.impl.DefaultPooledObject;
import org.beiter.michael.crypto4j.primitives.spec.SecureRandomSpec;
import org.beiter.michael.crypto4j.primitives.SecureRandomFactory;

import java.security.SecureRandom;

/**
 * This class provides a pool factory implementation for classes managed in this library to be used with the
 * Apache Commons Pool, Version 2.
 * <p>
 * This class is for internal use of the library, and is not meant for public consumption. <b>Do not use this class
 * outside of this library</b>, as it is not part of the library's public interface, and may be dropped / modified
 * without warning in future releases.
 */
public class SecureRandomPoolFactory
        extends BasePooledObjectFactory<SecureRandom> {

    /**
     * The object spec that this factory will use to generate objects.
     */
    private final SecureRandomSpec spec;

    /**
     * Creates a factory and initializes it from an existing spec, making a defensive copy.
     *
     * @param spec The spec to use when creating new instances of the objects handled by this factory.
     * @throws NullPointerException When {@code spec} is {@code null}
     */
    public SecureRandomPoolFactory(final SecureRandomSpec spec) {

        super();

        Validate.notNull(spec, "The validated object 'spec' is null");

        // create a defensive copy
        this.spec = new SecureRandomSpec(spec);
    }

    @Override
    // Not our API - cannot fix...
    @SuppressWarnings("PMD.SignatureDeclareThrowsException")
    public final SecureRandom create()
            throws Exception {

        return SecureRandomFactory.getInstance(spec);
    }

    @Override
    public final PooledObject<SecureRandom> wrap(final SecureRandom value) {

        return new DefaultPooledObject<>(value);
    }
}
