package com.smartInvoice.auth_service.web;

import java.time.Instant;
import java.util.Map;

public record ApiError(String code, String message, Instant timestamp, Map<String, String> fieldErrors) {
	public static ApiError of(String code, String message) {
		return new ApiError(code, message, Instant.now(), Map.of());
	}
}
