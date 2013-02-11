package com.marakana.webauthz;

import java.security.Key;
import java.util.Set;

public class Main {
	public static void main(String[] args) throws Exception {
		if (args.length == 2) {
			System.out.println(WebAuthz.decode(args[1],
					WebAuthz.generateKey(args[0])));
		} else if (args.length >= 6) {
			Key key = WebAuthz.generateKey(args[0]);
			String basePath = args[1];
			String description = args[2];
			Set<Access> access = Access.fromInt(Integer.parseInt(args[3]));
			long expiry = Long.parseLong(args[4]);
			if (args[4].charAt(0) == '+') {
				expiry += System.currentTimeMillis();
			}
			long userId = Long.parseLong(args[5]);
			String userDescription = args.length >= 7 ? args[6] : null;
			WebAuthz auth = new WebAuthz(basePath, description, access, expiry,
					userId, userDescription);
			System.out.println(auth.encode(key));
		} else {
			System.err
					.println("USAGE: Auth <key> (<auth-token> | <base-path> <description> <access> <expiry> <user-id> [user-description])");
		}
	}
}
