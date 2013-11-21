package com.twitter.university.webauthz;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.Key;
import java.util.Set;

import org.junit.Assert;
import org.junit.Test;

public class WebAuthzTest {

    private static final String BASE_PATH = "/class/12345/files/";
    private static final String DESCRIPTION = "Test Class";
    private static final long QUOTA = 1234567890;
    private static Set<Access> ACCESS = Access.READ_WRITE;
    private static final long EXPIRY = System.currentTimeMillis() + 60 * 60 * 1000;
    private static final long USER_ID = 123;
    private static final String USER_DESCRIPTION = "John Smith";
    private static final Key KEY = WebAuthz.generateKey("abcd1234");

    private static final WebAuthz AUTH = new WebAuthz(BASE_PATH, DESCRIPTION,
            QUOTA, ACCESS, EXPIRY, USER_ID, USER_DESCRIPTION);

    @Test
    public void testUrlSafeEncode() throws UnsupportedEncodingException {
        String s = AUTH.encode(KEY);
        Assert.assertEquals(s, URLEncoder.encode(s, "UTF-8"));
    }

    private static void assertEncodeDecode(WebAuthz auth) {
        Assert.assertEquals(auth, WebAuthz.decode(auth.encode(KEY), KEY));
    }

    @Test
    public void testEncodeDecodeMinimal() {
        assertEncodeDecode(new WebAuthz(BASE_PATH, null, 0, Access.READ_ONLY,
                0, 0, null));
    }

    @Test
    public void testEncodeDecodeWithDescription() {
        assertEncodeDecode(new WebAuthz(BASE_PATH, DESCRIPTION, 0,
                Access.READ_ONLY, 0, 0, null));
    }

    @Test
    public void testEncodeDecodeWithQuota() {
        assertEncodeDecode(new WebAuthz(BASE_PATH, null, QUOTA,
                Access.READ_ONLY, 0, 0, null));
    }

    @Test
    public void testEncodeDecodeWithExpiry() {
        assertEncodeDecode(new WebAuthz(BASE_PATH, null, 0, Access.READ_ONLY,
                EXPIRY, 0, null));
    }

    @Test
    public void testEncodeDecodeWithUserId() {
        assertEncodeDecode(new WebAuthz(BASE_PATH, null, 0, Access.READ_ONLY,
                0, USER_ID, null));
    }

    @Test
    public void testEncodeDecodeWithUserDescription() {
        assertEncodeDecode(new WebAuthz(BASE_PATH, null, 0, Access.READ_ONLY,
                0, 0, USER_DESCRIPTION));
    }

    @Test
    public void testEncodeDecode() {
        assertEncodeDecode(AUTH);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testInvalidKey() {
        WebAuthz.decode(AUTH.encode(KEY), WebAuthz.generateKey("abc 1234"));
    }
}
