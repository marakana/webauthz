package com.twitter.university.webauthz;

import static com.twitter.university.webauthz.Util.emptyOnNull;
import static com.twitter.university.webauthz.Util.nullOnEmpty;
import static com.twitter.university.webauthz.Util.readZeroOrLong;
import static com.twitter.university.webauthz.Util.urlSafeBase64Decode;
import static com.twitter.university.webauthz.Util.urlSafeBase64Encode;
import static com.twitter.university.webauthz.Util.writeZeroOrLong;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Set;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Represents authorization to a particular base-path on a remote server.
 * 
 * Encoded webauthz is in the following format, encoded as modified-base64:
 * 
 * <ul>
 * <li>version - 1 byte</li>
 * <li>SHA1 signature of what follows - 20 bytes</li>
 * <li>nonce - 8 bytes</li>
 * <li>access - 1 byte (0=none, 1=read-only, 2=write-only, 3=read-write)</li>
 * <li>expiry (millis since Jan 1st, 1970 00:00:00 UTC) - 1-8 bytes (if the
 * first bit of the first byte is 0, then expiry is zero; otherwise the expiry
 * is set to the remaining 7 bits from the first byte plus 7 more bytes
 * (unsigned, network byte order)</li>
 * <li>base-path - 2 bytes for the length + actual string</li>
 * <li>description - 2 bytes for the length + actual string</li>
 * <li>quota - 1-5 bytes (if the first bit of the first byte is 0, then quota is
 * zero; otherwise the quota is set to the remaining 7 bits from the first byte
 * plus 4 more bytes (unsigned, network byte order)</li>
 * <li>user id - 1-8 bytes (if the first bit of the first byte is 0, then user
 * id is zero; otherwise the quota is set to the remaining 7 bits from the first
 * byte plus 7 more bytes (unsigned, network byte order)</li>
 * <li>user description - 2 bytes for the length + actual string (optional)</li>
 * <li>padding - 0, 1, or 2 bytes for the total that's divisible by 3</li>
 * </ul>
 * 
 * Note that strings are encoded in UTF-8 and that the 2-byte string length
 * encodes the number of bytes (not necessarily characters)
 * 
 * @author sasa
 * @verison 1.0
 */
public final class WebAuthz {

    private static final int VERSION = 2;
    private static final int[] SUPPORTED_VERSIONS = { 1, VERSION };
    private static final Charset CHARSET = Charset.forName("UTF-8");
    private static final String HMAC_ALGORITHM = "HmacSHA1";

    private static final int VERSION_OFFSET = 0;
    private static final int VERSION_LENGTH = 1;
    private static final int SIGNATURE_OFFSET = VERSION_OFFSET + VERSION_LENGTH;
    private static final int SIGNATURE_LENGTH = 20;
    private static final int PAYLOAD_OFFSET = SIGNATURE_OFFSET
            + SIGNATURE_LENGTH;
    private static final int NONCE_LENGTH = 8;
    private static final int ACTUAL_PAYLOAD_OFFSET = PAYLOAD_OFFSET
            + NONCE_LENGTH;
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final long MIN_LONG = 0;
    private static final long MAX_5_LONG = 0x7f_ff_ff_ff_ffL;
    private static final long MAX_8_LONG = 0x7f_ff_ff_ff_ff_ff_ff_ffL;

    public static Key generateKey(String key) {
        return generateKey(key.getBytes(CHARSET));
    }

    public static Key generateKey(byte[] key) {
        return new SecretKeySpec(key, HMAC_ALGORITHM);
    }

    private static boolean isSupportedVersion(int version) {
        for (int v : SUPPORTED_VERSIONS) {
            if (v == version) {
                return true;
            }
        }
        return false;
    }

    public static WebAuthz decode(String input, Key key) {
        if (input == null) {
            throw new NullPointerException("Cannot parse null");
        } else {
            try {
                final byte[] data = urlSafeBase64Decode(input);
                final int version = data[VERSION_OFFSET];
                if (!isSupportedVersion(version)) {
                    throw new IllegalArgumentException("Cannot parse [" + input
                            + "]. Unsupported version: " + version);
                }

                final Mac mac = Mac.getInstance(HMAC_ALGORITHM);
                mac.init(key);
                mac.update(data, PAYLOAD_OFFSET, data.length - PAYLOAD_OFFSET);
                final byte[] actualSignature = mac.doFinal();
                for (int i = 0; i < actualSignature.length; i++) {
                    if (data[i + SIGNATURE_OFFSET] != actualSignature[i]) {
                        throw new IllegalArgumentException("Cannot parse ["
                                + input + "]. The signature does not match");
                    }
                }

                final DataInputStream in = new DataInputStream(
                        new ByteArrayInputStream(data, ACTUAL_PAYLOAD_OFFSET,
                                data.length - ACTUAL_PAYLOAD_OFFSET));

                final Set<Access> accessSet = Access
                        .fromByte((byte) (version == 1 ? in.readInt() : in
                                .readByte()));
                final long expiry = version == 1 ? in.readLong()
                        : readZeroOrLong(in, 8);
                final String basePath = in.readUTF();
                final String description = in.readUTF();
                final long quota = readZeroOrLong(in, 5);
                final long userId = version == 1 ? in.readLong()
                        : readZeroOrLong(in, 8);
                final String userDescription = in.readUTF();
                // ignore the padding
                return new WebAuthz(basePath, nullOnEmpty(description), quota,
                        accessSet, expiry, userId, nullOnEmpty(userDescription));
            } catch (InvalidKeyException | NoSuchAlgorithmException e) {
                throw new RuntimeException("Cannot parse [" + input
                        + "]. Failed to validate signatures", e);
            } catch (IOException e) {
                throw new RuntimeException("Cannot parse [" + input
                        + "]. Error while reading data", e);
            }
        }
    }

    private static byte[] generateNonce() {
        byte[] nonce = new byte[NONCE_LENGTH];
        RANDOM.nextBytes(nonce);
        return nonce;
    }

    private static long checkLongSafe(long value, long max, String what) {
        if (value < MIN_LONG || value > max) {
            throw new IllegalArgumentException(what + " out of ranage ["
                    + MIN_LONG + ", " + max + "]: " + value);
        }
        return value;
    }

    private final String basePath;
    private final String description;
    private final long quota;
    private final Set<Access> access;
    private final long expiry;
    private final long userId;
    private final String userDescription;

    public WebAuthz(String basePath, String description, long quota,
            Set<Access> access, long expiry, long userId, String userDescription) {
        if (basePath == null) {
            throw new NullPointerException("Base path must not be null");
        }
        this.basePath = basePath;
        this.description = description;
        this.quota = checkLongSafe(quota, MAX_5_LONG, "Quota");
        if (access == null) {
            throw new NullPointerException("Access must not be null");
        }
        this.access = access;
        this.expiry = checkLongSafe(expiry, MAX_8_LONG, "Expiry");
        this.userId = checkLongSafe(userId, MAX_8_LONG, "User ID");
        this.userDescription = userDescription;
    }

    public String getBasePath() {
        return basePath;
    }

    public String getDescription() {
        return description;
    }

    public long getQuota() {
        return quota;
    }

    public Set<Access> getAccess() {
        return access;
    }

    public long getExpiry() {
        return expiry;
    }

    public boolean isExpired() {
        return this.getExpiry() > 0
                && System.currentTimeMillis() > this.getExpiry();
    }

    public long getMaxAgeInMillis() {
        return this.getExpiry() - System.currentTimeMillis();
    }

    public int getMaxAgeInSeconds() {
        long maxAgeInSeconds = (this.getMaxAgeInMillis() / 1000);
        return maxAgeInSeconds > Integer.MAX_VALUE ? Integer.MAX_VALUE
                : (int) maxAgeInSeconds;
    }

    public long getUserId() {
        return userId;
    }

    public String getUserDescription() {
        return userDescription;
    }

    public String encode(Key key) {
        try {
            ByteArrayOutputStream payloadOut = new ByteArrayOutputStream(256);
            payloadOut.write(generateNonce());
            DataOutputStream dataPayloadOut = new DataOutputStream(payloadOut);
            dataPayloadOut.writeByte(Access.toByte(this.getAccess()));
            writeZeroOrLong(this.getExpiry(), dataPayloadOut, 8);
            dataPayloadOut.writeUTF(this.getBasePath());
            dataPayloadOut.writeUTF(emptyOnNull(this.getDescription()));
            writeZeroOrLong(this.getQuota(), dataPayloadOut, 5);
            writeZeroOrLong(this.getUserId(), dataPayloadOut, 8);
            dataPayloadOut.writeUTF(emptyOnNull(this.getUserDescription()));
            while ((payloadOut.size() + PAYLOAD_OFFSET) % 3 != 0) {
                payloadOut.write(0); // padding
            }
            byte[] payload = payloadOut.toByteArray();
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(key);
            mac.update(payload);
            byte[] signature = mac.doFinal();
            if (signature.length != SIGNATURE_LENGTH) {
                throw new AssertionError("Expecting signature of "
                        + SIGNATURE_LENGTH + " bytes but got "
                        + signature.length);
            }
            byte[] data = new byte[PAYLOAD_OFFSET + payload.length];
            data[0] = VERSION;
            System.arraycopy(signature, 0, data, SIGNATURE_OFFSET,
                    signature.length);
            System.arraycopy(payload, 0, data, PAYLOAD_OFFSET, payload.length);
            return urlSafeBase64Encode(data);
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            throw new RuntimeException("Cannot print [" + this
                    + "]. Failed to generate signature", e);
        } catch (IOException e) {
            throw new RuntimeException("Cannot print [" + this
                    + "]. Failed to write data", e);
        }
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((access == null) ? 0 : access.hashCode());
        result = prime * result
                + ((basePath == null) ? 0 : basePath.hashCode());
        result = prime * result
                + ((description == null) ? 0 : description.hashCode());
        result = prime * result + (int) (expiry ^ (expiry >>> 32));
        result = prime * result + (int) (quota ^ (quota >>> 32));
        result = prime * result
                + ((userDescription == null) ? 0 : userDescription.hashCode());
        result = prime * result + (int) (userId ^ (userId >>> 32));
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        WebAuthz other = (WebAuthz) obj;
        if (access == null) {
            if (other.access != null) {
                return false;
            }
        } else if (!access.equals(other.access)) {
            return false;
        }
        if (basePath == null) {
            if (other.basePath != null) {
                return false;
            }
        } else if (!basePath.equals(other.basePath)) {
            return false;
        }
        if (description == null) {
            if (other.description != null) {
                return false;
            }
        } else if (!description.equals(other.description)) {
            return false;
        }
        if (expiry != other.expiry) {
            return false;
        }
        if (quota != other.quota) {
            return false;
        }
        if (userDescription == null) {
            if (other.userDescription != null) {
                return false;
            }
        } else if (!userDescription.equals(other.userDescription)) {
            return false;
        }
        if (userId != other.userId) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "WebAuthz [basePath=" + basePath + ", description="
                + description + ", quota=" + quota + ", access=" + access
                + ", expiry=" + expiry + ", userId=" + userId
                + ", userDescription=" + userDescription + "]";
    }
}
