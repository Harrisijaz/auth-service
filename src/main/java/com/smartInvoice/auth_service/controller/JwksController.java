package com.smartInvoice.auth_service.controller;

import com.smartInvoice.auth_service.service.JwtService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/auth")
public class JwksController {
	private final JwtService jwtService;

	public JwksController(JwtService jwtService) {
		this.jwtService = jwtService;
	}

	@GetMapping("/.well-known/jwks.json")
	public Map<String, Object> jwks() {
		return jwtService.jwks();
	}
}
