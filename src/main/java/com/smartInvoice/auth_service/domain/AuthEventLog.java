package com.smartInvoice.auth_service.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;

import java.time.Instant;

@Entity
@Table(name = "auth_event_logs")
public class AuthEventLog {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	private String userId;

	@Enumerated(EnumType.STRING)
	@Column(nullable = false, length = 50)
	private AuthEventType eventType;

	@Column(length = 64)
	private String ipAddress;

	@Column(length = 512)
	private String userAgent;

	@Column(nullable = false, updatable = false)
	private Instant createdAt;

	@PrePersist
	void prePersist() {
		if (createdAt == null) {
			createdAt = Instant.now();
		}
	}

	public Long getId() { return id; }
	public String getUserId() { return userId; }
	public void setUserId(String userId) { this.userId = userId; }
	public AuthEventType getEventType() { return eventType; }
	public void setEventType(AuthEventType eventType) { this.eventType = eventType; }
	public String getIpAddress() { return ipAddress; }
	public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }
	public String getUserAgent() { return userAgent; }
	public void setUserAgent(String userAgent) { this.userAgent = userAgent; }
	public Instant getCreatedAt() { return createdAt; }
}
