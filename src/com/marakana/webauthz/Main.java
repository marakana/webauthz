package com.marakana.webauthz;

import java.security.Key;

public class Main {
	public static void main(String[] args) throws Exception {
		if (args.length == 2) {
			System.out.println(WebAuthz.decode(args[1],
					WebAuthz.generateKey(args[0])));
		} else if (args.length == 9) {
			Key key = WebAuthz.generateKey(args[0]);
			WebAuthz auth = new WebAuthz(args[1], args[2],
					Access.fromInt(Integer.parseInt(args[3])),
					Long.parseLong(args[4]), Long.parseLong(args[5]), args[6],
					args[7], args[8]);
			System.out.println(auth.encode(key));
		} else {
			System.err
					.println("USAGE: Auth <key> (<auth-token> | <base-path> <description> <access> <expiry> <id> <first-name> <last-name> <email>)");
		}
	}
}
