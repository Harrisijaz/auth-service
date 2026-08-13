package com.smartInvoice.auth_service.service;

import com.smartInvoice.auth_service.domain.AuthEventLog;
import com.smartInvoice.auth_service.domain.AuthEventType;
import com.smartInvoice.auth_service.repo.AuthEventLogRepository;
import com.smartInvoice.auth_service.web.RequestMetadata;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class AuthEventService {
	private static final Logger log = LoggerFactory.getLogger(AuthEventService.class);
	private final AuthEventLogRepository repository;

	public AuthEventService(AuthEventLogRepository repository) {
		this.repository = repository;
	}

	public void log(String userId, AuthEventType eventType, RequestMetadata metadata) {
		try {
			AuthEventLog event = new AuthEventLog();
			event.setUserId(userId);
			event.setEventType(eventType);
			event.setIpAddress(metadata == null ? "" : metadata.ipAddress());
			event.setUserAgent(metadata == null ? "" : metadata.userAgent());
			repository.save(event);
		} catch (RuntimeException ex) {
			log.warn("Unable to write auth event {} for user {}: {}", eventType, userId, ex.getMessage());
		}
	}
}
