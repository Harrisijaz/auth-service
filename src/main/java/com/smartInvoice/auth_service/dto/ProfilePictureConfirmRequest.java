package com.smartInvoice.auth_service.dto;

import jakarta.validation.constraints.NotBlank;

public record ProfilePictureConfirmRequest(@NotBlank String objectKey) {
}
