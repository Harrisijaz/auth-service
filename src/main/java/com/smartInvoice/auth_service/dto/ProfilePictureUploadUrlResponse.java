package com.smartInvoice.auth_service.dto;

import java.time.Instant;

public record ProfilePictureUploadUrlResponse(String uploadUrl, String objectKey, String publicUrl,
		String method, Instant expiresAt) {
}
