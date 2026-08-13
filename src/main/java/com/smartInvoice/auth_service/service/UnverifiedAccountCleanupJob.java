package com.smartInvoice.auth_service.service;

import com.smartInvoice.auth_service.domain.User;
import com.smartInvoice.auth_service.domain.UserStatus;
import com.smartInvoice.auth_service.repo.UserRepository;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;

@Service
public class UnverifiedAccountCleanupJob {
	private final UserRepository users;

	public UnverifiedAccountCleanupJob(UserRepository users) {
		this.users = users;
	}

	@Transactional
	@Scheduled(cron = "0 0 2 * * *", zone = "UTC")
	public void softDeactivateOldUnverifiedAccounts() {
		Instant cutoff = Instant.now().minus(Duration.ofDays(30));
		for (User user : users.findByStatusAndEmailVerifiedFalseAndCreatedAtBefore(UserStatus.UNVERIFIED, cutoff)) {
			user.setStatus(UserStatus.DELETED);
			user.setDeletedAt(Instant.now());
		}
	}
}
