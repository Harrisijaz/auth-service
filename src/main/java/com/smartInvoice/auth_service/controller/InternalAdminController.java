package com.smartInvoice.auth_service.controller;

import com.smartInvoice.auth_service.dto.MessageResponse;
import com.smartInvoice.auth_service.service.AuthService;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/internal/admin")
public class InternalAdminController {
	private final AuthService authService;

	public InternalAdminController(AuthService authService) {
		this.authService = authService;
	}

	@PostMapping("/users/{userId}/sessions/invalidate")
	public MessageResponse invalidateUserSessions(@PathVariable String userId) {
		return authService.invalidateUserSessions(userId);
	}
}
