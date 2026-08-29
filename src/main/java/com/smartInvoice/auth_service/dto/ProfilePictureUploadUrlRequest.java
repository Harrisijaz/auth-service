package com.smartInvoice.auth_service.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;

public record ProfilePictureUploadUrlRequest(
		@NotBlank String fileName,
		@NotBlank String contentType,
		@Positive long sizeBytes) {
}
