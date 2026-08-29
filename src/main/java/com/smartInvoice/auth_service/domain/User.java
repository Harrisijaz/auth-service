package com.smartInvoice.auth_service.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "users", indexes = {
		@Index(name = "idx_users_email_normalized", columnList = "email_normalized", unique = true)
})
public class User {
	@Id
	private String id;

	@Column(nullable = false, length = 254)
	private String email;

	@Column(name = "email_normalized", nullable = false, length = 254, unique = true)
	private String emailNormalized;

	@Column(nullable = false)
	private String passwordHash;

	@Column(nullable = false, length = 100)
	private String fullName;

	@Enumerated(EnumType.STRING)
	@Column(nullable = false, length = 20)
	private UserRole role = UserRole.USER;

	@Enumerated(EnumType.STRING)
	@Column(nullable = false, length = 20)
	private UserStatus status = UserStatus.UNVERIFIED;

	@Column(nullable = false)
	private boolean emailVerified;

	@Column(length = 1024)
	private String profilePictureUrl;

	@Column(nullable = false)
	private boolean trusted;

	@Column(nullable = false, updatable = false)
	private Instant createdAt;

	private Instant deletedAt;

	@PrePersist
	void prePersist() {
		if (id == null) {
			id = "usr_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
		}
		if (createdAt == null) {
			createdAt = Instant.now();
		}
	}

	public String getId() { return id; }
	public void setId(String id) { this.id = id; }
	public String getEmail() { return email; }
	public void setEmail(String email) { this.email = email; }
	public String getEmailNormalized() { return emailNormalized; }
	public void setEmailNormalized(String emailNormalized) { this.emailNormalized = emailNormalized; }
	public String getPasswordHash() { return passwordHash; }
	public void setPasswordHash(String passwordHash) { this.passwordHash = passwordHash; }
	public String getFullName() { return fullName; }
	public void setFullName(String fullName) { this.fullName = fullName; }
	public UserRole getRole() { return role; }
	public void setRole(UserRole role) { this.role = role; }
	public UserStatus getStatus() { return status; }
	public void setStatus(UserStatus status) { this.status = status; }
	public boolean isEmailVerified() { return emailVerified; }
	public void setEmailVerified(boolean emailVerified) { this.emailVerified = emailVerified; }
	public String getProfilePictureUrl() { return profilePictureUrl; }
	public void setProfilePictureUrl(String profilePictureUrl) { this.profilePictureUrl = profilePictureUrl; }
	public boolean isTrusted() { return trusted; }
	public void setTrusted(boolean trusted) { this.trusted = trusted; }
	public Instant getCreatedAt() { return createdAt; }
	public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
	public Instant getDeletedAt() { return deletedAt; }
	public void setDeletedAt(Instant deletedAt) { this.deletedAt = deletedAt; }
}
