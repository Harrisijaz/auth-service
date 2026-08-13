package com.smartInvoice.auth_service.repo;

import com.smartInvoice.auth_service.domain.User;
import com.smartInvoice.auth_service.domain.UserRole;
import com.smartInvoice.auth_service.domain.UserStatus;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, String> {
	Optional<User> findByEmailNormalized(String emailNormalized);
	boolean existsByEmailNormalizedAndStatusNot(String emailNormalized, UserStatus status);
	List<User> findByStatusAndEmailVerifiedFalseAndCreatedAtBefore(UserStatus status, Instant cutoff);
	Optional<User> findFirstByRole(UserRole role);
}
