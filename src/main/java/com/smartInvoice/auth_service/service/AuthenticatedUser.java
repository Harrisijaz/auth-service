package com.smartInvoice.auth_service.service;

import com.smartInvoice.auth_service.domain.UserRole;

public record AuthenticatedUser(String userId, String email, UserRole role, String jti, String tokenType) {
}
