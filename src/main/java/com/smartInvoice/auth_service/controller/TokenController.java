package com.smartInvoice.auth_service.controller;

import com.smartInvoice.auth_service.dto.RefreshTokenRequest;
import com.smartInvoice.auth_service.dto.MessageResponse;
import com.smartInvoice.auth_service.dto.TokenPairResponse;
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
public class TokenController {
	private final AuthService authService;

	public TokenController(AuthService authService) {
		this.authService = authService;
	}

	@PostMapping("/logout")
	public MessageResponse logout(@RequestHeader("Authorization") String authorization,
			@RequestBody(required = false) RefreshTokenRequest request,
			HttpServletRequest servletRequest) {
		return authService.logout(authorization, request, RequestMetadata.from(servletRequest));
	}

	@PostMapping("/refresh")
	public TokenPairResponse refresh(@Valid @RequestBody RefreshTokenRequest request,
			HttpServletRequest servletRequest) {
		return authService.refresh(request, RequestMetadata.from(servletRequest));
	}

	@PostMapping("/logout-all")
	public MessageResponse logoutAll(@RequestHeader("Authorization") String authorization,
			HttpServletRequest servletRequest) {
		return authService.logoutAll(authorization, RequestMetadata.from(servletRequest));
	}
}
