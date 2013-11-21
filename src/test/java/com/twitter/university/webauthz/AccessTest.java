package com.twitter.university.webauthz;

import org.junit.Assert;
import org.junit.Test;

public class AccessTest {

    @Test
    public void testFromByteZero() {
        Assert.assertEquals(Access.NONE, Access.fromByte((byte) 0));
    }

    @Test
    public void testFromByteOne() {
        Assert.assertEquals(Access.READ_ONLY, Access.fromByte((byte) 1));
    }

    @Test
    public void testFromByteTwo() {
        Assert.assertEquals(Access.WRITE_ONLY, Access.fromByte((byte) 2));
    }

    @Test
    public void testFromByteThree() {
        Assert.assertEquals(Access.READ_WRITE, Access.fromByte((byte) 3));
    }

    @Test
    public void testNoneToByte() {
        Assert.assertEquals((byte) 0, Access.toByte(Access.NONE));
    }

    @Test
    public void testReadOnlyToByte() {
        Assert.assertEquals((byte) 1, Access.toByte(Access.READ_ONLY));
    }

    @Test
    public void testWriteOnlyToByte() {
        Assert.assertEquals((byte) 2, Access.toByte(Access.WRITE_ONLY));
    }

    @Test
    public void testReadWriteToByte() {
        Assert.assertEquals((byte) 3, Access.toByte(Access.READ_WRITE));
    }
}
