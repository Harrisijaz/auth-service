package com.smartInvoice.auth_service.controller;

import com.smartInvoice.auth_service.dto.AuthResponse;
import com.smartInvoice.auth_service.dto.EmailRequest;
import com.smartInvoice.auth_service.dto.LoginRequest;
import com.smartInvoice.auth_service.dto.MessageResponse;
import com.smartInvoice.auth_service.dto.SignupRequest;
import com.smartInvoice.auth_service.dto.VerifyEmailRequest;
import com.smartInvoice.auth_service.service.AuthService;
import com.smartInvoice.auth_service.web.RequestMetadata;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/user/auth")
public class PublicAuthController {
	private final AuthService authService;

	public PublicAuthController(AuthService authService) {
		this.authService = authService;
	}

	@PostMapping("/signup")
	public MessageResponse signup(@Valid @RequestBody SignupRequest request, HttpServletRequest servletRequest) {
		return authService.signup(request, RequestMetadata.from(servletRequest));
	}

	@PostMapping("/verify-email")
	public MessageResponse verifyEmail(@Valid @RequestBody VerifyEmailRequest request, HttpServletRequest servletRequest) {
		return authService.verifyEmail(request, RequestMetadata.from(servletRequest));
	}

	@PostMapping("/resend-verification")
	public MessageResponse resendVerification(@Valid @RequestBody EmailRequest request, HttpServletRequest servletRequest) {
		return authService.resendVerification(request, RequestMetadata.from(servletRequest));
	}

	@PostMapping("/login")
	public AuthResponse login(@Valid @RequestBody LoginRequest request, HttpServletRequest servletRequest) {
		return authService.login(request, RequestMetadata.from(servletRequest));
	}
}
