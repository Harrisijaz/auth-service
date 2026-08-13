package com.smartInvoice.auth_service.dto;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record SignupRequest(
		@NotBlank @Email @Size(max = 254) String email,
		@NotBlank String password,
		@NotBlank @Size(max = 100) String fullName,
		@NotNull @AssertTrue(message = "Terms and Conditions must be accepted") Boolean termsAccepted) {
}
