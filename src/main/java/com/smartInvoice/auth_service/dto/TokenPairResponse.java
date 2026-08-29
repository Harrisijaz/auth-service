package com.smartInvoice.auth_service.dto;

public record TokenPairResponse(String message, String accessToken, String refreshToken, UserInfoResponse userInfo) {
}
