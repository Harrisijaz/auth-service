package com.smartInvoice.auth_service.dto;

public record Login2FaResponse(String message, String temporaryToken, String devCode, UserInfoResponse userInfo) {
}
