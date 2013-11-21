package com.twitter.university.webauthz;

import java.security.Key;
import java.util.Set;

public class Main {
    public static void main(String[] args) throws Exception {
        if (args.length == 2) {
            System.out.println(WebAuthz.decode(args[1],
                    WebAuthz.generateKey(args[0])));
        } else if (args.length >= 7) {
            Key key = WebAuthz.generateKey(args[0]);
            String basePath = args[1];
            String description = args[2];
            long quota = Long.parseLong(args[3]);
            Set<Access> access = Access.fromByte(Byte.parseByte(args[4]));
            long expiry = Long.parseLong(args[5]);
            if (args[5].charAt(0) == '+') {
                expiry += System.currentTimeMillis();
            }
            long userId = Long.parseLong(args[6]);
            String userDescription = args.length >= 8 ? args[7] : null;
            WebAuthz auth = new WebAuthz(basePath, description, quota, access,
                    expiry, userId, userDescription);
            System.out.println(auth.encode(key));
        } else {
            System.err
                    .println("USAGE: Auth <key> (<auth-token> | <base-path> <description> <quota> <access> <expiry> <user-id> [user-description])");
        }
    }
}
