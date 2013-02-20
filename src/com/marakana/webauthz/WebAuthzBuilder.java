package com.marakana.webauthz;

import java.util.Set;

public class WebAuthzBuilder {

	private String basePath = "/";
	private String description = null;
	private long quota = 0;
	private final Set<Access> access;
	private final long expiry;
	private long userId = 0;
	private String userDescription = null;

	public WebAuthzBuilder(Set<Access> access, long expiry) {
		this.access = access;
		this.expiry = expiry;
	}

	public WebAuthzBuilder withBasePath(String basePath) {
		this.basePath = basePath;
		return this;
	}

	public WebAuthzBuilder withDescription(String description) {
		this.description = description;
		return this;
	}

	public WebAuthzBuilder withQuota(long quota) {
		this.quota = quota;
		return this;
	}

	public WebAuthzBuilder witUserId(long userId) {
		this.userId = userId;
		return this;
	}

	public WebAuthzBuilder withUserDescription(String userDescription) {
		this.userDescription = userDescription;
		return this;
	}

	public WebAuthz build() {
		return new WebAuthz(basePath, description, quota, access, expiry,
				userId, userDescription);
	}
}
