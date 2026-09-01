package com.smartInvoice.auth_service.controller;

import com.smartInvoice.auth_service.dto.ContactUsRequest;
import com.smartInvoice.auth_service.dto.MessageResponse;
import com.smartInvoice.auth_service.service.EmailDispatchService;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ContactController {
	private final EmailDispatchService emails;

	public ContactController(EmailDispatchService emails) {
		this.emails = emails;
	}

	@PostMapping("/contact-us")
	MessageResponse contactUs(@Valid @RequestBody ContactUsRequest request) {
		emails.sendContactMessage(request);
		return MessageResponse.of("Message submitted.");
	}
}
