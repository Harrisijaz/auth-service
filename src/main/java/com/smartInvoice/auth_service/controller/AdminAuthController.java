package com.smartInvoice.auth_service.controller;

import com.smartInvoice.auth_service.dto.AuthResponse;
import com.smartInvoice.auth_service.dto.LoginRequest;
import com.smartInvoice.auth_service.service.AuthService;
import com.smartInvoice.auth_service.web.RequestMetadata;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/admin/auth")
public class AdminAuthController {
	private static final String ADMIN_EMAIL = "adminHaris@yopmail.com";
	private static final String ADMIN_PASSWORD = "Admin@@123";

	private final AuthService authService;

	public AdminAuthController(AuthService authService) {
		this.authService = authService;
	}

	@PostMapping("/login")
	public AuthResponse login(@Valid @RequestBody LoginRequest request, HttpServletRequest servletRequest) {
		return authService.fixedAdminLogin(request, ADMIN_EMAIL, ADMIN_PASSWORD, RequestMetadata.from(servletRequest));
	}
}
