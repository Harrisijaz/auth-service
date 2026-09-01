package com.smartInvoice.auth_service.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ContactUsRequest(
		@NotBlank @Size(max = 150) String name,
		@NotBlank @Email @Size(max = 254) String email,
		@Size(max = 80) String topic,
		@NotBlank @Size(max = 2000) String message) {
}
