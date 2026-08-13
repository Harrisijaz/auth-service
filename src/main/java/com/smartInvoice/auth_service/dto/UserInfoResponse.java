package com.smartInvoice.auth_service.dto;

public record UserInfoResponse(
		String userId,
		String name,
		String email,
		String role,
		String status,
		boolean emailVerified) {
}
