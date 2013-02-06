package com.marakana.webauthz;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

public enum Access {
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

	public static Set<Access> fromInt(int in) {
		EnumSet<Access> accessSet = EnumSet.noneOf(Access.class);
		for (Access access : Access.values()) {
			if ((in & (1 << access.ordinal())) != 0) {
				accessSet.add(access);
			}
		}
		return accessSet;
	}

	public static int toInt(Set<Access> accessSet) {
		int out = 0;
		for (Access access : Access.values()) {
			if (accessSet.contains(access)) {
				out |= (1 << access.ordinal());
			}
		}
		return out;
	}
}