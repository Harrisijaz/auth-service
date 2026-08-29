package com.smartInvoice.auth_service.controller;

import com.smartInvoice.auth_service.dto.MessageResponse;
import com.smartInvoice.auth_service.dto.ProfilePictureConfirmRequest;
import com.smartInvoice.auth_service.dto.ProfilePictureUploadUrlRequest;
import com.smartInvoice.auth_service.dto.ProfilePictureUploadUrlResponse;
import com.smartInvoice.auth_service.dto.ProfileResponse;
import com.smartInvoice.auth_service.dto.ProfileUpdateRequest;
import com.smartInvoice.auth_service.service.AuthService;
import com.smartInvoice.auth_service.web.RequestMetadata;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/profile")
public class ProfileController {
	private final AuthService authService;

	public ProfileController(AuthService authService) {
		this.authService = authService;
	}

	@GetMapping
	public ProfileResponse profile(@RequestHeader("Authorization") String authorization) {
		return authService.profile(authorization);
	}

	@PutMapping
	public ProfileResponse update(@RequestHeader("Authorization") String authorization,
			@Valid @RequestBody ProfileUpdateRequest request,
			HttpServletRequest servletRequest) {
		return authService.updateProfile(authorization, request, RequestMetadata.from(servletRequest));
	}

	@PostMapping("/picture/upload-url")
	public ProfilePictureUploadUrlResponse uploadUrl(@RequestHeader("Authorization") String authorization,
			@Valid @RequestBody ProfilePictureUploadUrlRequest request,
			HttpServletRequest servletRequest) {
		return authService.profilePictureUploadUrl(authorization, request, RequestMetadata.from(servletRequest));
	}

	@PostMapping("/picture/confirm")
	public ProfileResponse confirmPicture(@RequestHeader("Authorization") String authorization,
			@Valid @RequestBody ProfilePictureConfirmRequest request,
			HttpServletRequest servletRequest) {
		return authService.confirmProfilePicture(authorization, request, RequestMetadata.from(servletRequest));
	}

	@DeleteMapping("/picture")
	public ProfileResponse removePicture(@RequestHeader("Authorization") String authorization,
			HttpServletRequest servletRequest) {
		return authService.removeProfilePicture(authorization, RequestMetadata.from(servletRequest));
	}
}
