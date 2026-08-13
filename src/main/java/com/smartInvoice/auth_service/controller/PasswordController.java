package com.smartInvoice.auth_service.controller;

import com.smartInvoice.auth_service.dto.ChangePasswordRequest;
import com.smartInvoice.auth_service.dto.EmailRequest;
import com.smartInvoice.auth_service.dto.MessageResponse;
import com.smartInvoice.auth_service.dto.ResetPasswordRequest;
import com.smartInvoice.auth_service.service.AuthService;
import com.smartInvoice.auth_service.web.RequestMetadata;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class PasswordController {
	private final AuthService authService;

	public PasswordController(AuthService authService) {
		this.authService = authService;
	}

	@PostMapping("/forgot-password")
	public MessageResponse forgotPassword(@Valid @RequestBody EmailRequest request, HttpServletRequest servletRequest) {
		return authService.forgotPassword(request, RequestMetadata.from(servletRequest));
	}

	@PostMapping("/reset-password")
	public MessageResponse resetPassword(@Valid @RequestBody ResetPasswordRequest request, HttpServletRequest servletRequest) {
		return authService.resetPassword(request, RequestMetadata.from(servletRequest));
	}

	@PostMapping("/change-password")
	public MessageResponse changePassword(@RequestHeader("Authorization") String authorization,
			@Valid @RequestBody ChangePasswordRequest request,
			HttpServletRequest servletRequest) {
		return authService.changePassword(authorization, request, RequestMetadata.from(servletRequest));
	}
}
