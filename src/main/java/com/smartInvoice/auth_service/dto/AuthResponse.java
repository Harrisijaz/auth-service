package com.smartInvoice.auth_service.dto;

public record AuthResponse(String message, String accessToken, boolean emailVerified, UserInfoResponse userInfo) {
}
