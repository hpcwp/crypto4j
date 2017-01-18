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

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

public class PoolStatsTest {

    /**
     * Test that the getters return the correct values
     */
    @Test
    public void gettersTest() {

        PoolStats poolStats = getTestObject();

        // test all the getters
        String error = "The returned value does not meet the expected value";
        assertThat(error, poolStats.getNumActive(), is(equalTo(11)));
        assertThat(error, poolStats.getNumIdle(), is(equalTo(12)));
        assertThat(error, poolStats.getNumWaiters(), is(equalTo(13)));
        assertThat(error, poolStats.getCountBorrowed(), is(equalTo(14L)));
        assertThat(error, poolStats.getCountCreated(), is(equalTo(15L)));
        assertThat(error, poolStats.getCountDestroyed(), is(equalTo(16L)));
        assertThat(error, poolStats.getCountDestroyedByBorrowValidation(), is(equalTo(17L)));
        assertThat(error, poolStats.getCountDestroyedByEvictor(), is(equalTo(18L)));
        assertThat(error, poolStats.getCountReturned(), is(equalTo(19L)));
        assertThat(error, poolStats.getMeanActiveTimeMillis(), is(equalTo(20L)));
        assertThat(error, poolStats.getMeanBorrowWaitTimeMillis(), is(equalTo(21L)));
        assertThat(error, poolStats.getMeanIdleTimeMillis(), is(equalTo(22L)));
    }

    /**
     * Test that the toString() method produces a correctly formatted String representation
     */
    @Test
    public void stringTest() {

        PoolStats poolStats = getTestObject();

        StringBuilder expected = new StringBuilder();

        expected.append("Pool statistics:").append("\n")
                .append("\tnumActive: ").append(11).append("\n")
                .append("\tnumIdle: ").append(12).append("\n")
                .append("\tnumWaiters: ").append(13).append("\n")
                .append("\tcountBorrowed: ").append(14).append("\n")
                .append("\tcountCreated: ").append(15).append("\n")
                .append("\tcountDestroyed: ").append(16).append("\n")
                .append("\tcountDestroyedByBorrowValidation: ").append(17).append("\n")
                .append("\tcountDestroyedByEvictor: ").append(18).append("\n")
                .append("\tcountReturned: ").append(19).append("\n")
                .append("\tmeanActiveTimeMillis: ").append(20).append("\n")
                .append("\tmeanBorrowWaitTimeMillis: ").append(21).append("\n")
                .append("\tmeanIdleTimeMillis: ").append(22).append("\n");

        String error = "The returned value does not meet the expected value";
        assertThat(error, poolStats.toString(), is(equalTo(expected.toString())));
    }

    /**
     * A private method that creates a test object
     */
    private static PoolStats getTestObject() {

        return new PoolStats(
                11, // numActive
                12, // numIdle
                13, // numWaiters
                14, // countBorrowed
                15, // countCreated
                16, // countDestroyed
                17, // countDestroyedByBorrowValidation
                18, // countDestroyedByEvictor
                19, // countReturned
                20, // meanActiveTimeMillis
                21, // meanBorrowWaitTimeMillis
                22  // meanIdleTimeMillis
        );
    }
}
