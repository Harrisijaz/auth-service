package com.smartInvoice.auth_service.web;

import jakarta.servlet.http.HttpServletRequest;

public record RequestMetadata(String ipAddress, String userAgent) {
	public static RequestMetadata from(HttpServletRequest request) {
		String forwardedFor = request.getHeader("X-Forwarded-For");
		String ip = forwardedFor != null && !forwardedFor.isBlank()
				? forwardedFor.split(",")[0].trim()
				: request.getRemoteAddr();
		String userAgent = request.getHeader("User-Agent");
		return new RequestMetadata(ip, userAgent == null ? "" : userAgent);
	}
}
