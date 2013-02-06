package com.marakana.webauthz;

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
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

/**
 * 
 * @author sasa
 * 
 */
public class WebAuthz {
	// modifiedBase64(<version:1><signature:20><nonce:8><access:1><expiry:8><len:2><base-path:len><id:8><len:2><first-name:len><len:2><email:len><padding>)
	private static final int SUPPORTED_VERSION = 1;
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

	public static enum Access {
		READ, WRITE;

		public static final Set<Access> NONE = Collections.emptySet();

		public static final Set<Access> READ_ONLY = Collections
				.unmodifiableSet(EnumSet.of(Access.READ));

		public static final Set<Access> WRITE_ONLY = Collections
				.unmodifiableSet(EnumSet.of(Access.READ));

		public static final Set<Access> READ_WRITE = Collections
				.unmodifiableSet(EnumSet.of(Access.READ, Access.WRITE));

		public static Set<Access> fromBooleans(boolean read, boolean write) {
			if (read && write) {
				return READ_WRITE;
			} else if (read) {
				return READ_ONLY;
			} else if (write) {
				return WRITE_ONLY;
			} else {
				return NONE;
			}
		}

		public static Set<Access> notNull(Set<Access> set) {
			return set == null ? NONE : set;
		}

		public static Set<Access> combine(Set<Access> set1, Set<Access> set2) {
			set1 = notNull(set1);
			set2 = notNull(set2);
			return fromBooleans(set1.contains(READ) || set2.contains(READ),
					set1.contains(WRITE) || set2.contains(WRITE));
		}
	}

	public static Key generateKey(String key) {
		return generateKey(key.getBytes(CHARSET));
	}

	public static Key generateKey(byte[] key) {
		return new SecretKeySpec(key, HMAC_ALGORITHM);
	}

	public static WebAuthz decode(String input, Key key) {
		if (input == null) {
			throw new NullPointerException("Cannot parse null");
		} else {
			try {
				byte[] data = urlSafeBase64Decode(input);
				int version = data[VERSION_OFFSET];
				if (version != SUPPORTED_VERSION) {
					throw new IllegalArgumentException("Cannot parse [" + input
							+ "]. Unsupported version: " + version);
				}

				Mac mac = Mac.getInstance(HMAC_ALGORITHM);
				mac.init(key);
				mac.update(data, PAYLOAD_OFFSET, data.length - PAYLOAD_OFFSET);
				byte[] actualSignature = mac.doFinal();
				for (int i = 0; i < actualSignature.length; i++) {
					if (data[i + SIGNATURE_OFFSET] != actualSignature[i]) {
						throw new IllegalArgumentException("Cannot parse ["
								+ input + "]. The signature does not match");
					}
				}

				DataInputStream in = new DataInputStream(
						new ByteArrayInputStream(data, ACTUAL_PAYLOAD_OFFSET,
								data.length - ACTUAL_PAYLOAD_OFFSET));

				EnumSet<Access> accessSet = parseAccess(in.readInt());
				long expiry = in.readLong();
				String basePath = in.readUTF();
				long id = in.readLong();
				String firstName = in.readUTF();
				String lastName = in.readUTF();
				String email = in.readUTF();
				// ignore the padding
				return new WebAuthz(basePath, accessSet, expiry, id, firstName,
						lastName, email);
			} catch (InvalidKeyException | NoSuchAlgorithmException e) {
				throw new RuntimeException("Cannot parse [" + input
						+ "]. Failed to validate signatures", e);
			} catch (IOException e) {
				throw new RuntimeException("Cannot parse [" + input
						+ "]. Error while reading data", e);
			}
		}
	}

	static EnumSet<Access> parseAccess(int in) {
		EnumSet<Access> accessSet = EnumSet.noneOf(Access.class);
		for (Access access : Access.values()) {
			if ((in & (1 << access.ordinal())) != 0) {
				accessSet.add(access);
			}
		}
		return accessSet;
	}

	static int printAccess(EnumSet<Access> accessSet) {
		int out = 0;
		for (Access access : Access.values()) {
			if (accessSet.contains(access)) {
				out |= (1 << access.ordinal());
			}
		}
		return out;
	}

	private static byte[] generateNonce() {
		SecureRandom random = new SecureRandom();
		byte[] nonce = new byte[NONCE_LENGTH];
		random.nextBytes(nonce);
		return nonce;
	}

	private static String urlSafeBase64Encode(byte[] in) {
		String base64 = DatatypeConverter.printBase64Binary(in);
		base64 = base64.replace('+', '-');
		base64 = base64.replace('/', '_');
		return base64;
	}

	private static byte[] urlSafeBase64Decode(String in) {
		in = in.replace('-', '+');
		in = in.replace('_', '/');
		return DatatypeConverter.parseBase64Binary(in);
	}

	private final String basePath;
	private final EnumSet<Access> access;
	private final long expiry;
	private final long id;
	private final String firstName;
	private final String lastName;
	private final String email;

	public WebAuthz(String basePath, EnumSet<Access> access, long expiry,
			long id, String firstName, String lastName, String email) {
		this.basePath = basePath;
		this.access = access;
		this.expiry = expiry;
		this.id = id;
		this.firstName = firstName;
		this.lastName = lastName;
		this.email = email;
	}

	public String getBasePath() {
		return basePath;
	}

	public EnumSet<Access> getAccess() {
		return access;
	}

	public long getExpiry() {
		return expiry;
	}

	public boolean isExpired() {
		return System.currentTimeMillis() > this.getExpiry();
	}

	public long getMaxAgeInMillis() {
		return this.getExpiry() - System.currentTimeMillis();
	}

	public int getMaxAgeInSeconds() {
		long maxAgeInSeconds = (this.getMaxAgeInMillis() / 1000);
		return maxAgeInSeconds > Integer.MAX_VALUE ? Integer.MAX_VALUE
				: (int) maxAgeInSeconds;
	}

	public long getId() {
		return id;
	}

	public String getFirstName() {
		return firstName;
	}

	public String getLastName() {
		return lastName;
	}

	public String getEmail() {
		return email;
	}

	public String encode(Key key) {
		try {
			ByteArrayOutputStream payloadOut = new ByteArrayOutputStream(256);
			payloadOut.write(generateNonce());
			DataOutputStream dataPayloadOut = new DataOutputStream(payloadOut);
			dataPayloadOut.writeInt(printAccess(this.getAccess()));
			dataPayloadOut.writeLong(this.getExpiry());
			dataPayloadOut.writeUTF(this.getBasePath());
			dataPayloadOut.writeLong(this.getId());
			dataPayloadOut.writeUTF(this.getFirstName());
			dataPayloadOut.writeUTF(this.getLastName());
			dataPayloadOut.writeUTF(this.getEmail());
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
			data[0] = SUPPORTED_VERSION;
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
		result = prime * result + ((email == null) ? 0 : email.hashCode());
		result = prime * result + (int) (expiry ^ (expiry >>> 32));
		result = prime * result
				+ ((firstName == null) ? 0 : firstName.hashCode());
		result = prime * result + (int) (id ^ (id >>> 32));
		result = prime * result
				+ ((lastName == null) ? 0 : lastName.hashCode());
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
		if (email == null) {
			if (other.email != null) {
				return false;
			}
		} else if (!email.equals(other.email)) {
			return false;
		}
		if (expiry != other.expiry) {
			return false;
		}
		if (firstName == null) {
			if (other.firstName != null) {
				return false;
			}
		} else if (!firstName.equals(other.firstName)) {
			return false;
		}
		if (id != other.id) {
			return false;
		}
		if (lastName == null) {
			if (other.lastName != null) {
				return false;
			}
		} else if (!lastName.equals(other.lastName)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		return "Auth [basePath=" + basePath + ", access=" + access
				+ ", expiry=" + expiry + ", id=" + id + ", firstName="
				+ firstName + ", lastName=" + lastName + ", email=" + email
				+ "]";
	}
}
