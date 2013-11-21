package com.twitter.university.webauthz;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Arrays;

import junit.framework.Assert;

import org.junit.Test;

public class UtilTest {

    private static DataInputStream asDataInputStream(byte... a) {
        return new DataInputStream(new ByteArrayInputStream(a));
    }

    @Test
    public void testReadZeroOrLongWithZeroAndEight() throws IOException {
        DataInputStream in = asDataInputStream((byte) 0x00);
        Assert.assertEquals(0, Util.readZeroOrLong(in, 8));
        Assert.assertEquals(0, in.available());
    }

    @Test
    public void testReadZeroOrLongWithOneAndEight() throws IOException {
        DataInputStream in = asDataInputStream((byte) 0x80, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x01);
        Assert.assertEquals(1, Util.readZeroOrLong(in, 8));
        Assert.assertEquals(0, in.available());
    }

    @Test
    public void testReadZeroOrLongWithFFAndEight() throws IOException {
        DataInputStream in = asDataInputStream((byte) 0x80, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0xFF);
        Assert.assertEquals(255, Util.readZeroOrLong(in, 8));
        Assert.assertEquals(0, in.available());
    }

    @Test
    public void testReadZeroOrLongWithFFFFAndEight() throws IOException {
        DataInputStream in = asDataInputStream((byte) 0x80, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0xFF, (byte) 0xFF);
        Assert.assertEquals(65535, Util.readZeroOrLong(in, 8));
        Assert.assertEquals(0, in.available());
    }

    @Test
    public void testReadZeroOrLongWithMaxAndEight() throws IOException {
        DataInputStream in = asDataInputStream((byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF, (byte) 0xFF);
        Assert.assertEquals(9223372036854775807L, Util.readZeroOrLong(in, 8));
        Assert.assertEquals(0, in.available());
    }

    @Test
    public void testReadZeroOrLongWithOneAndFive() throws IOException {
        DataInputStream in = asDataInputStream((byte) 0x80, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x01);
        Assert.assertEquals(1, Util.readZeroOrLong(in, 5));
        Assert.assertEquals(0, in.available());
    }

    @Test
    public void testReadZeroOrLongWithLargeAndFive() throws IOException {
        DataInputStream in = asDataInputStream((byte) 0x80, (byte) 0x12,
                (byte) 0x34, (byte) 0x56, (byte) 0x78);
        Assert.assertEquals(305419896, Util.readZeroOrLong(in, 5));
        Assert.assertEquals(0, in.available());
    }

    @Test
    public void testReadZeroOrLongWithMaxAndFive() throws IOException {
        DataInputStream in = asDataInputStream((byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF);
        Assert.assertEquals(549755813887L, Util.readZeroOrLong(in, 5));
        Assert.assertEquals(0, in.available());
    }

    private static void assertWriteZeroOrLong(long value, int maxBytes,
            byte... expected) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Util.writeZeroOrLong(value, new DataOutputStream(out), maxBytes);
        byte[] actual = out.toByteArray();
        if (!Arrays.equals(expected, actual)) {
            Assert.fail("Expected " + Arrays.toString(expected) + " but got "
                    + Arrays.toString(actual));
        }
    }

    @Test
    public void testWriteZeroOrLongWithZeroAnd5() throws IOException {
        assertWriteZeroOrLong(0, 5, (byte) 0x00);
    }

    @Test
    public void testWriteZeroOrLongWithZeroAnd8() throws IOException {
        assertWriteZeroOrLong(0, 8, (byte) 0x00);
    }

    @Test
    public void testWriteZeroOrLongWithOneAnd5() throws IOException {
        assertWriteZeroOrLong(1, 5, (byte) 0x80, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x01);
    }

    @Test
    public void testWriteZeroOrLongWithOneAnd6() throws IOException {
        assertWriteZeroOrLong(1, 6, (byte) 0x80, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x01);
    }

    @Test
    public void testWriteZeroOrLongWithOneAnd7() throws IOException {
        assertWriteZeroOrLong(1, 7, (byte) 0x80, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01);
    }

    @Test
    public void testWriteZeroOrLongWithOneAnd8() throws IOException {
        assertWriteZeroOrLong(1, 8, (byte) 0x80, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01);
    }

    @Test
    public void testWriteZeroOrLongWithLargeAnd5() throws IOException {
        assertWriteZeroOrLong(4886718345L, 5, (byte) 0x81, (byte) 0x23,
                (byte) 0x45, (byte) 0x67, (byte) 0x89);
    }

    @Test
    public void testWriteZeroOrLongWithLargeAnd8() throws IOException {
        assertWriteZeroOrLong(81985529205302085L, 8, (byte) 0x81, (byte) 0x23,
                (byte) 0x45, (byte) 0x67, (byte) 0x89, (byte) 0x01,
                (byte) 0x23, (byte) 0x45);
    }

    @Test
    public void testWriteZeroOrLongWithMaxAnd5() throws IOException {
        assertWriteZeroOrLong(549755813887L, 5, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF);
    }

    @Test
    public void testWriteZeroOrLongWithMaxAnd8() throws IOException {
        assertWriteZeroOrLong(9223372036854775807L, 8, (byte) 0xFF,
                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF);
    }
}
