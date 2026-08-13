package com.smartInvoice.auth_service.service;

import com.smartInvoice.auth_service.web.ApiException;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Locale;
import java.util.regex.Pattern;

@Service
public class ValidationService {
	private static final Pattern FULL_NAME = Pattern.compile("^[\\p{L} '-]{1,100}$");
	private static final Pattern UPPER = Pattern.compile("[A-Z]");
	private static final Pattern LOWER = Pattern.compile("[a-z]");
	private static final Pattern DIGIT = Pattern.compile("\\d");
	private static final Pattern SPECIAL = Pattern.compile("[^A-Za-z0-9]");

	public String normalizeEmail(String email) {
		if (email == null) {
			throw validation("email", "Email is required");
		}
		return email.trim().toLowerCase(Locale.ROOT);
	}

	public void validateFullName(String fullName) {
		if (fullName == null || !FULL_NAME.matcher(fullName.trim()).matches()) {
			throw validation("fullName", "Full name must be 1-100 characters and contain only letters, spaces, hyphens, or apostrophes");
		}
	}

	public void validatePassword(String password, String normalizedEmail) {
		if (password == null || password.length() < 8
				|| !UPPER.matcher(password).find()
				|| !LOWER.matcher(password).find()
				|| !DIGIT.matcher(password).find()
				|| !SPECIAL.matcher(password).find()) {
			throw validation("password", "Password must be at least 8 characters and include uppercase, lowercase, digit, and special character");
		}
		String lowerPassword = password.toLowerCase(Locale.ROOT);
		if (normalizedEmail != null && (lowerPassword.equals(normalizedEmail) || lowerPassword.contains(normalizedEmail))) {
			throw validation("password", "Password must not equal or contain the email address");
		}
	}

	public void validateNewPassword(String newPassword, String normalizedEmail, String currentHash, PasswordEncoder encoder) {
		validatePassword(newPassword, normalizedEmail);
		if (encoder.matches(newPassword, currentHash)) {
			throw validation("newPassword", "New password must be different from the current password");
		}
	}

	private ApiException validation(String field, String message) {
		return new ApiException(HttpStatus.BAD_REQUEST, "VALIDATION_ERROR", message);
	}
}
