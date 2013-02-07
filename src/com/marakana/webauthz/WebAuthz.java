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
import java.util.Set;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

/**
 * Represents authorization to a particular base-path on a remote server.
 * 
 * Encoded webauthz is in the following format, encoded as modified-base64:
 * 
 * <ul>
 * <li>version - 1 byte</li>
 * <li>SHA1 signature of what follows - 20 bytes</li>
 * <li>nonce - 8 bytes</li>
 * <li>access - 1 byte</li>
 * <li>expiry - 8 bytes</li>
 * <li>base-path - 2 bytes for the length + actual string</li>
 * <li>description - 2 bytes for the length + actual string</li>
 * <li>id - 8 bytes</li>
 * <li>first-name - 2 bytes for the length + actual string</li>
 * <li>last-name - 2 bytes for the length + actual string</li>
 * <li>email - 2 bytes for the length + actual string</li>
 * <li>padding - 1 or 2 bytes for the total that's divisable by 3</li>
 * </ul>
 * 
 * 
 * @author sasa
 * @verison 1.0
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

				Set<Access> accessSet = Access.fromInt(in.readInt());
				long expiry = in.readLong();
				String basePath = in.readUTF();
				String description = in.readUTF();
				long id = in.readLong();
				String firstName = in.readUTF();
				String lastName = in.readUTF();
				String email = in.readUTF();
				// ignore the padding
				return new WebAuthz(basePath, "".equals(description) ? null
						: description, accessSet, expiry, id, firstName,
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
	private final String description;
	private final Set<Access> access;
	private final long expiry;
	private final long id;
	private final String firstName;
	private final String lastName;
	private final String email;

	public WebAuthz(String basePath, String description, Set<Access> access,
			long expiry, long id, String firstName, String lastName,
			String email) {
		this.basePath = basePath;
		this.description = description;
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

	public String getDescription() {
		return description;
	}

	public Set<Access> getAccess() {
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
			dataPayloadOut.writeInt(Access.toInt(this.getAccess()));
			dataPayloadOut.writeLong(this.getExpiry());
			dataPayloadOut.writeUTF(this.getBasePath());
			dataPayloadOut.writeUTF(this.getDescription() == null ? "" : this
					.getDescription());
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
