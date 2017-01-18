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

/**
 * This class holds statistics about a pool
 */
// suppress warnings about the long variable names
@SuppressWarnings("PMD.LongVariable")
public class PoolStats {

    /**
     * @see PoolStats#getNumActive()
     */
    private final int numActive;

    /**
     * @see PoolStats#getNumIdle()
     */
    private final int numIdle;

    /**
     * @see PoolStats#getNumWaiters()
     */
    private final int numWaiters;

    /**
     * @see PoolStats#getCountBorrowed()
     */
    private final long countBorrowed;

    /**
     * @see PoolStats#getCountCreated()
     */
    private final long countCreated;

    /**
     * @see PoolStats#getCountDestroyed()
     */
    private final long countDestroyed;

    /**
     * @see PoolStats#getCountDestroyedByBorrowValidation()
     */
    private final long countDestroyedByBorrowValidation;

    /**
     * @see PoolStats#getCountDestroyedByEvictor()
     */
    private final long countDestroyedByEvictor;

    /**
     * @see PoolStats#getCountReturned()
     */
    private final long countReturned;

    /**
     * @see PoolStats#getMeanActiveTimeMillis()
     */
    private final long meanActiveTimeMillis;

    /**
     * @see PoolStats#getMeanBorrowWaitTimeMillis()
     */
    private final long meanBorrowWaitTimeMillis;

    /**
     * @see PoolStats#getMeanIdleTimeMillis()
     */
    private final long meanIdleTimeMillis;

    /**
     * Constructs an pool stat object.
     *
     * @param numActive                        The number of instances currently borrowed from this pool
     * @param numIdle                          The number of instances currently idle in this pool
     * @param numWaiters                       An estimate of the number of threads currently blocked waiting
     * @param countBorrowed                    The total number of objects successfully borrowed from this pool
     * @param countCreated                     The total number of objects created for this pool
     * @param countDestroyed                   The total number of objects destroyed by this pool
     * @param countDestroyedByBorrowValidation The total number of objects destroyed due to borrowing check failures
     * @param countDestroyedByEvictor          The total number of objects destroyed by this pool's evictor
     * @param countReturned                    The total number of objects returned to this pool
     * @param meanActiveTimeMillis             The mean time objects are active for (based on a rolling window)
     * @param meanBorrowWaitTimeMillis         The mean time threads wait to borrow an object
     * @param meanIdleTimeMillis               The mean time objects are idle for (based on a rolling window)
     */
    //CHECKSTYLE:OFF: checkstyle:parameternumber
    // The parameter list could be replaced with a handful of setters, but that does seem to be more clumsy than helpful
    @SuppressWarnings("PMD.ExcessiveParameterList")
    public PoolStats(final int numActive,
                     final int numIdle,
                     final int numWaiters,
                     final long countBorrowed,
                     final long countCreated,
                     final long countDestroyed,
                     final long countDestroyedByBorrowValidation,
                     final long countDestroyedByEvictor,
                     final long countReturned,
                     final long meanActiveTimeMillis,
                     final long meanBorrowWaitTimeMillis,
                     final long meanIdleTimeMillis) {
        //CHECKSTYLE:ON: checkstyle:parameternumber

        // no validation, as none of the primitives can be null or have invalid values

        this.numActive = numActive;
        this.numIdle = numIdle;
        this.numWaiters = numWaiters;
        this.countBorrowed = countBorrowed;
        this.countCreated = countCreated;
        this.countDestroyedByBorrowValidation = countDestroyedByBorrowValidation;
        this.countDestroyedByEvictor = countDestroyedByEvictor;
        this.countDestroyed = countDestroyed;
        this.countReturned = countReturned;
        this.meanActiveTimeMillis = meanActiveTimeMillis;
        this.meanBorrowWaitTimeMillis = meanBorrowWaitTimeMillis;
        this.meanIdleTimeMillis = meanIdleTimeMillis;
    }


    /**
     * @return The number of instances currently borrowed from this pool
     */
    public final int getNumActive() {
        return numActive;
    }

    /**
     * @return The number of instances currently idle in this pool
     */
    public final int getNumIdle() {
        return numIdle;
    }

    /**
     * @return An estimate of the number of threads currently blocked waiting for an object from the pool
     */
    public final int getNumWaiters() {
        return numWaiters;
    }

    /**
     * @return The total number of objects successfully borrowed from this pool over the lifetime of the pool
     */
    public final long getCountBorrowed() {
        return countBorrowed;
    }

    /**
     * @return The total number of objects created for this pool over the lifetime of the pool
     */
    public final long getCountCreated() {
        return countCreated;
    }

    /**
     * @return The total number of objects destroyed by this pool over the lifetime of the pool
     */
    public final long getCountDestroyed() {
        return countDestroyed;
    }

    /**
     * Returns the total number of objects destroyed by this pool over the lifetime of the pool as a result of failing
     * validation during borrowing.
     *
     * @return The total number of objects destroyed due to validation failures at borrowing
     */
    public final long getCountDestroyedByBorrowValidation() {
        return countDestroyedByBorrowValidation;
    }

    /**
     * @return The total number of objects destroyed by this pool's evictor over the lifetime of the pool
     */
    public final long getCountDestroyedByEvictor() {
        return countDestroyedByEvictor;
    }

    /**
     * @return The total number of objects returned to this pool over the lifetime of the pool
     */
    public final long getCountReturned() {
        return countReturned;
    }

    /**
     * @return The mean time objects are active for (based on a rolling window of objects returned to the pool)
     */
    public final long getMeanActiveTimeMillis() {
        return meanActiveTimeMillis;
    }

    /**
     * Returns the mean time threads wait to borrow an object (based on a rolling window of objects borrowed from the
     * pool).
     *
     * @return The mean time threads wait to borrow an object
     */
    public final long getMeanBorrowWaitTimeMillis() {
        return meanBorrowWaitTimeMillis;
    }

    /**
     * @return The mean time objects are idle for (based on a rolling window of objects borrowed from the pool).
     */
    public final long getMeanIdleTimeMillis() {
        return meanIdleTimeMillis;
    }

    /**
     * @return A String representation of the pool stats
     */
    // The repeated appends are somewhat slower, but the code is a lot easier to read that way
    @SuppressWarnings("PMD.ConsecutiveLiteralAppends")
    public final String toString() {

        final StringBuilder result = new StringBuilder(1024);

        result.append("Pool statistics:\n")
                .append("\tnumActive: ").append(numActive).append('\n')
                .append("\tnumIdle: ").append(numIdle).append('\n')
                .append("\tnumWaiters: ").append(numWaiters).append('\n')
                .append("\tcountBorrowed: ").append(countBorrowed).append('\n')
                .append("\tcountCreated: ").append(countCreated).append('\n')
                .append("\tcountDestroyed: ").append(countDestroyed).append('\n')
                .append("\tcountDestroyedByBorrowValidation: ").append(countDestroyedByBorrowValidation).append('\n')
                .append("\tcountDestroyedByEvictor: ").append(countDestroyedByEvictor).append('\n')
                .append("\tcountReturned: ").append(countReturned).append('\n')
                .append("\tmeanActiveTimeMillis: ").append(meanActiveTimeMillis).append('\n')
                .append("\tmeanBorrowWaitTimeMillis: ").append(meanBorrowWaitTimeMillis).append('\n')
                .append("\tmeanIdleTimeMillis: ").append(meanIdleTimeMillis).append('\n');

        return result.toString();
    }
}
