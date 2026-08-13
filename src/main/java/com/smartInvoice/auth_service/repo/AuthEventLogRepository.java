package com.smartInvoice.auth_service.repo;

import com.smartInvoice.auth_service.domain.AuthEventLog;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuthEventLogRepository extends JpaRepository<AuthEventLog, Long> {
}
