package com.smartInvoice.auth_service.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record AuthResponse(String message, String accessToken, String refreshToken, boolean emailVerified,
		UserInfoResponse userInfo) {
}
