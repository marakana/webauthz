package com.twitter.university.webauthz;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

import javax.xml.bind.DatatypeConverter;

final class Util {
    private Util() {

    }

    static String urlSafeBase64Encode(byte[] in) {
        String base64 = DatatypeConverter.printBase64Binary(in);
        base64 = base64.replace('+', '-');
        base64 = base64.replace('/', '_');
        return base64;
    }

    static byte[] urlSafeBase64Decode(String in) {
        in = in.replace('-', '+');
        in = in.replace('_', '/');
        return DatatypeConverter.parseBase64Binary(in);
    }

    static long readZeroOrLong(DataInputStream in, int maxBytes)
            throws IOException {
        int b = (int) in.readByte();
        if ((b & 0x80) == 0) {
            return 0;
        } else {
            long result = ((long) (b & 0x7f) << (8 * (maxBytes - 1)));
            for (int i = maxBytes - 1; i > 0; i--) {
                result += ((long) (in.readByte() & 0xff) << (8 * (i - 1)));
            }
            return result;
        }
    }

    static void writeZeroOrLong(long value, DataOutputStream out, int maxBytes)
            throws IOException {
        if (value == 0) {
            out.writeByte(0);
        } else {
            out.writeByte(0x80 | (int) (value >>> (8 * (maxBytes - 1)) & 0xff));
            for (int i = maxBytes - 1; i > 0; i--) {
                out.writeByte((int) (value >>> (8 * (i - 1)) & 0xff));
            }
        }
    }

    static String emptyOnNull(String s) {
        return s == null ? "" : s;
    }

    static String nullOnEmpty(String s) {
        return "".equals(s) ? null : s;
    }
}
