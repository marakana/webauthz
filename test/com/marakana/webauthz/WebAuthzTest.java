package com.marakana.webauthz;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.Key;
import java.util.EnumSet;

import org.junit.Assert;
import org.junit.Test;

import com.marakana.webauthz.WebAuthz;

public class WebAuthzTest {

	private WebAuthz auth = new WebAuthz("/class/12345/files", EnumSet.of(
			Access.READ, Access.WRITE),
			System.currentTimeMillis() + 60 * 60 * 1000, 123, "John", "Smith",
			"john@smith.com");
	private Key key = WebAuthz.generateKey("abcd1234");

	@Test
	public void testUrlSafeEncode() throws UnsupportedEncodingException {
		String s = auth.encode(key);
		Assert.assertEquals(s, URLEncoder.encode(s, "UTF-8"));
	}

	@Test
	public void testEncodeDecode() {
		Assert.assertEquals(auth, WebAuthz.decode(auth.encode(key), key));
	}

	@Test(expected = IllegalArgumentException.class)
	public void testInvalidKey() {
		WebAuthz.decode(auth.encode(key), WebAuthz.generateKey("abc 1234"));
	}
}
