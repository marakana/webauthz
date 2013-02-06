package com.marakana.webauthz;

import java.security.Key;

public class Main {
	public static void main(String[] args) throws Exception {
		if (args.length == 2) {
			System.out.println(WebAuthz.decode(args[1],
					WebAuthz.generateKey(args[0])));
		} else if (args.length == 8) {
			Key key = WebAuthz.generateKey(args[0]);
			WebAuthz auth = new WebAuthz(args[1], Access.fromInt(Integer
					.parseInt(args[2])), Long.parseLong(args[3]),
					Long.parseLong(args[4]), args[5], args[6], args[7]);
			System.out.println(auth.encode(key));
		} else {
			System.err
					.println("USAGE: Auth <key> (<auth-token> | <base-path> <access> <expiry> <id> <first-name> <last-name> <email>)");
		}
	}
}
