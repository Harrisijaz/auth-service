package com.smartInvoice.auth_service.dto;

import java.time.Instant;

public record ProfileResponse(String userId, String displayName, String email, String profilePictureUrl,
		Instant createdAt) {
}
