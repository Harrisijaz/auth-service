package com.smartInvoice.auth_service.dto;

public record MessageResponse(String message, String devToken) {
	public static MessageResponse of(String message) {
		return new MessageResponse(message, null);
	}
}
