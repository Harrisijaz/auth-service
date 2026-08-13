package com.smartInvoice.auth_service.controller;

import com.smartInvoice.auth_service.dto.AuthResponse;
import com.smartInvoice.auth_service.dto.EmailRequest;
import com.smartInvoice.auth_service.dto.Login2FaResponse;
import com.smartInvoice.auth_service.dto.LoginRequest;
import com.smartInvoice.auth_service.dto.MessageResponse;
import com.smartInvoice.auth_service.dto.SignupRequest;
import com.smartInvoice.auth_service.dto.Verify2FaRequest;
import com.smartInvoice.auth_service.service.AuthService;
import com.smartInvoice.auth_service.web.RequestMetadata;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
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

	@GetMapping("/verify-email")
	public MessageResponse verifyEmail(@RequestParam String token, HttpServletRequest servletRequest) {
		return authService.verifyEmail(token, RequestMetadata.from(servletRequest));
	}

	@PostMapping("/resend-verification")
	public MessageResponse resendVerification(@Valid @RequestBody EmailRequest request, HttpServletRequest servletRequest) {
		return authService.resendVerification(request, RequestMetadata.from(servletRequest));
	}

	@PostMapping("/login")
	public Login2FaResponse login(@Valid @RequestBody LoginRequest request, HttpServletRequest servletRequest) {
		return authService.login(request, RequestMetadata.from(servletRequest));
	}

	@PostMapping("/verify-2fa")
	public AuthResponse verify2Fa(@Valid @RequestBody Verify2FaRequest request, HttpServletRequest servletRequest) {
		return authService.verifyUser2Fa(request.temporaryToken(), request.code(), RequestMetadata.from(servletRequest));
	}
}
