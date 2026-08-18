package com.smartInvoice.auth_service.service;

import com.smartInvoice.auth_service.config.AuthProperties;
import com.smartInvoice.auth_service.domain.AuthEventType;
import com.smartInvoice.auth_service.domain.User;
import com.smartInvoice.auth_service.domain.UserRole;
import com.smartInvoice.auth_service.domain.UserStatus;
import com.smartInvoice.auth_service.dto.AuthResponse;
import com.smartInvoice.auth_service.dto.ChangePasswordRequest;
import com.smartInvoice.auth_service.dto.EmailRequest;
import com.smartInvoice.auth_service.dto.Login2FaResponse;
import com.smartInvoice.auth_service.dto.LoginRequest;
import com.smartInvoice.auth_service.dto.MessageResponse;
import com.smartInvoice.auth_service.dto.ResetPasswordRequest;
import com.smartInvoice.auth_service.dto.SignupRequest;
import com.smartInvoice.auth_service.dto.UserInfoResponse;
import com.smartInvoice.auth_service.repo.UserRepository;
import com.smartInvoice.auth_service.web.ApiException;
import com.smartInvoice.auth_service.web.RequestMetadata;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

@Service
public class AuthService {
	private static final String GENERIC_LOGIN_ERROR = "Invalid email or password";
	private static final Duration USER_LOCK_TTL = Duration.ofMinutes(15);
	private static final Duration ADMIN_LOCK_TTL = Duration.ofMinutes(15);
	private static final SecureRandom RANDOM = new SecureRandom();

	private final UserRepository users;
	private final PasswordEncoder passwordEncoder;
	private final ValidationService validation;
	private final RedisStoreService redis;
	private final JwtService jwtService;
	private final AuthProperties properties;
	private final EmailDispatchService emailDispatch;
	private final AuthEventService events;

	public AuthService(UserRepository users, PasswordEncoder passwordEncoder, ValidationService validation,
			RedisStoreService redis, JwtService jwtService, AuthProperties properties,
			EmailDispatchService emailDispatch, AuthEventService events) {
		this.users = users;
		this.passwordEncoder = passwordEncoder;
		this.validation = validation;
		this.redis = redis;
		this.jwtService = jwtService;
		this.properties = properties;
		this.emailDispatch = emailDispatch;
		this.events = events;
	}

	@Transactional
	public MessageResponse signup(SignupRequest request, RequestMetadata metadata) {
		String email = validation.normalizeEmail(request.email());
		validation.validateFullName(request.fullName());
		validation.validatePassword(request.password(), email);
		checkSignupRate(metadata);
		prepareEmailForSignup(email);

		User user = new User();
		user.setEmail(email);
		user.setEmailNormalized(email);
		user.setFullName(request.fullName().trim());
		user.setPasswordHash(passwordEncoder.encode(request.password()));
		user.setRole(UserRole.USER);
		user.setStatus(UserStatus.UNVERIFIED);
		user.setEmailVerified(false);
		try {
			users.saveAndFlush(user);
		} catch (DataIntegrityViolationException ex) {
			throw conflict("Email already registered");
		}
		String token = issueEmailVerification(user, metadata);
		events.log(user.getId(), AuthEventType.SIGNUP, metadata);
		return new MessageResponse("Signup successful. Please verify your email.", devToken(token));
	}

	@Transactional
	public MessageResponse verifyEmail(String token, RequestMetadata metadata) {
		if (token == null || token.isBlank()) {
			throw badRequest("Verification token is required");
		}
		String userId = redis.get("otp:verify-token:" + token)
				.orElseThrow(() -> new ApiException(HttpStatus.BAD_REQUEST, "TOKEN_EXPIRED", "This link has expired"));
		User user = users.findById(userId).orElseThrow(() -> badRequest("Invalid verification token"));
		if (user.isEmailVerified()) {
			return MessageResponse.of("Your email is already verified.");
		}
		String currentToken = redis.get("otp:verify:" + user.getId()).orElse("");
		if (!token.equals(currentToken)) {
			throw badRequest("Invalid verification token");
		}
		user.setEmailVerified(true);
		user.setStatus(UserStatus.ACTIVE);
		users.save(user);
		redis.delete("otp:verify:" + user.getId());
		redis.delete("otp:verify-token:" + token);
		events.log(user.getId(), AuthEventType.EMAIL_VERIFIED, metadata);
		return MessageResponse.of("Your email has been verified.");
	}

	public MessageResponse resendVerification(EmailRequest request, RequestMetadata metadata) {
		String email = validation.normalizeEmail(request.email());
		User user = users.findByEmailNormalized(email)
				.orElseThrow(() -> notFound("Account not found"));
		if (user.isEmailVerified()) {
			return MessageResponse.of("Your email is already verified.");
		}
		long attempts = redis.increment("ratelimit:verify:" + user.getId(), Duration.ofHours(1));
		if (attempts > 3) {
			throw tooMany("Too many verification requests. Try again later.");
		}
		String token = issueEmailVerification(user, metadata);
		return new MessageResponse("Verification email sent.", devToken(token));
	}

	public Login2FaResponse login(LoginRequest request, RequestMetadata metadata) {
		String email = validation.normalizeEmail(request.email());
		String ip = metadata.ipAddress();
		enforceLock(email, ip, false);
		User user = users.findByEmailNormalized(email).orElse(null);
		if (user == null || user.getRole() != UserRole.USER || !passwordEncoder.matches(request.password(), user.getPasswordHash())) {
			recordFailedLogin(null, email, ip, false, metadata);
			throw unauthorized(GENERIC_LOGIN_ERROR);
		}
		assertLoginAllowed(user);
		clearLoginCounters(email, ip);
		String jti = UUID.randomUUID().toString();
		String code = redis.randomDigits(6);
		redis.put("otp:2fa:" + jti, user.getId() + "|" + code + "|0",
				Duration.ofMinutes(properties.getTemporaryTokenMinutes()));
		String temporaryToken = jwtService.issueLoginTemporaryToken(user, jti);
		emailDispatch.sendUser2FaCode(user.getEmailNormalized(), code);
		events.log(user.getId(), AuthEventType.USER_2FA_SENT, metadata);
		return new Login2FaResponse("2FA code sent.", temporaryToken, properties.isDevReturnTokens() ? code : null, userInfo(user));
	}

	public AuthResponse adminLogin(LoginRequest request, RequestMetadata metadata) {
		String email = validation.normalizeEmail(request.email());
		String ip = metadata.ipAddress();
		enforceLock(email, ip, true);
		User user = users.findByEmailNormalized(email).orElse(null);
		if (user == null || user.getRole() != UserRole.ADMIN || !passwordEncoder.matches(request.password(), user.getPasswordHash())) {
			recordFailedLogin(null, email, ip, true, metadata);
			throw unauthorized(GENERIC_LOGIN_ERROR);
		}
		assertLoginAllowed(user);
		clearLoginCounters(email, ip);
		events.log(user.getId(), AuthEventType.ADMIN_LOGIN_PASSWORD_OK, metadata);
		events.log(user.getId(), AuthEventType.LOGIN_SUCCESS, metadata);
		return authResponse("Login successful.", user);
	}

	@Transactional
	public AuthResponse fixedAdminLogin(LoginRequest request, String fixedEmail, String fixedPassword, RequestMetadata metadata) {
		String email = validation.normalizeEmail(request.email());
		String configuredEmail = validation.normalizeEmail(fixedEmail);
		String ip = metadata.ipAddress();
		enforceLock(configuredEmail, ip, true);
		if (!configuredEmail.equals(email) || !fixedPassword.equals(request.password())) {
			recordFailedLogin(null, configuredEmail, ip, true, metadata);
			throw unauthorized(GENERIC_LOGIN_ERROR);
		}
		User admin = users.findByEmailNormalized(configuredEmail).orElseGet(User::new);
		admin.setEmail(configuredEmail);
		admin.setEmailNormalized(configuredEmail);
		admin.setFullName("Admin Haris");
		admin.setRole(UserRole.ADMIN);
		admin.setStatus(UserStatus.ACTIVE);
		admin.setEmailVerified(true);
		if (admin.getPasswordHash() == null || !passwordEncoder.matches(fixedPassword, admin.getPasswordHash())) {
			admin.setPasswordHash(passwordEncoder.encode(fixedPassword));
		}
		users.saveAndFlush(admin);
		clearLoginCounters(configuredEmail, ip);
		events.log(admin.getId(), AuthEventType.ADMIN_LOGIN_PASSWORD_OK, metadata);
		events.log(admin.getId(), AuthEventType.LOGIN_SUCCESS, metadata);
		return authResponse("Login successful.", admin);
	}

	public AuthResponse verifyUser2Fa(String temporaryToken, String code, RequestMetadata metadata) {
		AuthenticatedUser principal = jwtService.verify(temporaryToken, JwtService.TYPE_LOGIN_2FA);
		String key = "otp:2fa:" + principal.jti();
		String stored = redis.get(key).orElseThrow(() -> unauthorized("2FA session expired. Please log in again."));
		String[] parts = stored.split("\\|");
		int attempts = Integer.parseInt(parts[2]);
		if (attempts >= 5) {
			redis.delete(key);
			throw tooMany("Too many 2FA attempts. Please log in again.");
		}
		if (!parts[1].equals(code)) {
			redis.put(key, parts[0] + "|" + parts[1] + "|" + (attempts + 1), Duration.ofMinutes(properties.getTemporaryTokenMinutes()));
			events.log(parts[0], AuthEventType.USER_2FA_FAILURE, metadata);
			throw unauthorized("Invalid 2FA code");
		}
		redis.delete(key);
		User user = users.findById(parts[0]).orElseThrow(() -> unauthorized("Invalid 2FA session"));
		if (user.getRole() != UserRole.USER) {
			throw unauthorized("Invalid 2FA session");
		}
		assertLoginAllowed(user);
		events.log(user.getId(), AuthEventType.USER_2FA_SUCCESS, metadata);
		events.log(user.getId(), AuthEventType.LOGIN_SUCCESS, metadata);
		return authResponse("2FA verified.", user);
	}

	public MessageResponse logout(String accessToken, RequestMetadata metadata) {
		AuthenticatedUser principal = requireAccess(accessToken);
		events.log(principal.userId(), AuthEventType.LOGOUT, metadata);
		return MessageResponse.of("Logged out.");
	}

	public MessageResponse logoutAll(String accessToken, RequestMetadata metadata) {
		AuthenticatedUser principal = requireAccess(accessToken);
		revokeAllSessions(principal.userId());
		events.log(principal.userId(), AuthEventType.LOGOUT_ALL, metadata);
		return MessageResponse.of("Logged out from all devices.");
	}

	public MessageResponse forgotPassword(EmailRequest request, RequestMetadata metadata) {
		String email = validation.normalizeEmail(request.email());
		User user = users.findByEmailNormalized(email).orElse(null);
		if (user == null || user.getStatus() == UserStatus.BLOCKED || user.getStatus() == UserStatus.DELETED) {
			return MessageResponse.of("If this account exists, a reset link has been sent.");
		}
		long attempts = redis.increment("ratelimit:reset:" + user.getId(), Duration.ofHours(1));
		if (attempts > 3) {
			return MessageResponse.of("If this account exists, a reset link has been sent.");
		}
		String token = randomToken();
		replaceSingleUseToken("otp:reset", user.getId(), token, Duration.ofMinutes(properties.getResetTokenMinutes()));
		emailDispatch.sendPasswordReset(user.getEmailNormalized(), token);
		events.log(user.getId(), AuthEventType.PASSWORD_RESET_REQUEST, metadata);
		return new MessageResponse("If this account exists, a reset link has been sent.", devToken(token));
	}

	@Transactional
	public MessageResponse resetPassword(ResetPasswordRequest request, RequestMetadata metadata) {
		String userId = redis.get("otp:reset-token:" + request.token())
				.orElseThrow(() -> new ApiException(HttpStatus.BAD_REQUEST, "TOKEN_EXPIRED", "Reset link is invalid or expired"));
		User user = users.findById(userId).orElseThrow(() -> badRequest("Invalid reset token"));
		if (user.getStatus() == UserStatus.BLOCKED || user.getStatus() == UserStatus.DELETED) {
			throw badRequest("Invalid reset token");
		}
		validation.validateNewPassword(request.newPassword(), user.getEmailNormalized(), user.getPasswordHash(), passwordEncoder);
		user.setPasswordHash(passwordEncoder.encode(request.newPassword()));
		users.save(user);
		redis.delete("otp:reset:" + user.getId());
		redis.delete("otp:reset-token:" + request.token());
		revokeAllSessions(user.getId());
		emailDispatch.sendPasswordResetSuccess(user.getEmailNormalized());
		events.log(user.getId(), AuthEventType.PASSWORD_RESET_SUCCESS, metadata);
		return MessageResponse.of("Password has been reset. Please log in again.");
	}

	@Transactional
	public MessageResponse changePassword(String accessToken, ChangePasswordRequest request, RequestMetadata metadata) {
		AuthenticatedUser principal = requireAccess(accessToken);
		User user = users.findById(principal.userId()).orElseThrow(() -> unauthorized("Invalid token"));
		if (!passwordEncoder.matches(request.currentPassword(), user.getPasswordHash())) {
			recordFailedLogin(user.getId(), user.getEmailNormalized(), metadata.ipAddress(), user.getRole() == UserRole.ADMIN, metadata);
			throw unauthorized("Current password is incorrect");
		}
		validation.validateNewPassword(request.newPassword(), user.getEmailNormalized(), user.getPasswordHash(), passwordEncoder);
		user.setPasswordHash(passwordEncoder.encode(request.newPassword()));
		users.save(user);
		revokeAllSessions(user.getId());
		emailDispatch.sendPasswordChanged(user.getEmailNormalized());
		events.log(user.getId(), AuthEventType.PASSWORD_CHANGE_SUCCESS, metadata);
		return MessageResponse.of("Password changed. Please log in again.");
	}

	public AuthenticatedUser requireAccess(String bearerToken) {
		if (bearerToken == null || !bearerToken.startsWith("Bearer ")) {
			throw unauthorized("Access token is required");
		}
		AuthenticatedUser principal = jwtService.verify(bearerToken.substring(7), JwtService.TYPE_ACCESS);
		if (redis.get("blacklist:user:" + principal.userId()).isPresent()) {
			throw new ApiException(HttpStatus.UNAUTHORIZED, "USER_REVOKED", "User access has been revoked");
		}
		return principal;
	}

	public MessageResponse blacklistUser(String userId) {
		redis.put("blacklist:user:" + userId, "blocked", Duration.ofHours(24));
		return MessageResponse.of("User access revoked.");
	}

	public MessageResponse invalidateUserSessions(String userId) {
		revokeAllSessions(userId);
		redis.put("blacklist:user:" + userId, "blocked", Duration.ofHours(24));
		return MessageResponse.of("User sessions invalidated.");
	}

	private AuthResponse authResponse(String message, User user) {
		return new AuthResponse(message, jwtService.issueAccessToken(user), user.isEmailVerified(), userInfo(user));
	}

	private UserInfoResponse userInfo(User user) {
		return new UserInfoResponse(
				user.getId(),
				user.getFullName(),
				user.getEmailNormalized(),
				user.getRole().name(),
				user.getStatus().name(),
				user.isEmailVerified());
	}

	private String issueEmailVerification(User user, RequestMetadata metadata) {
		String token = randomToken();
		replaceSingleUseToken("otp:verify", user.getId(), token, Duration.ofHours(properties.getEmailTokenHours()));
		emailDispatch.sendVerification(user.getEmailNormalized(), token);
		events.log(user.getId(), AuthEventType.EMAIL_VERIFICATION_SENT, metadata);
		return token;
	}

	private void replaceSingleUseToken(String prefix, String userId, String token, Duration ttl) {
		redis.get(prefix + ":" + userId).ifPresent(old -> redis.delete(prefix + "-token:" + old));
		redis.put(prefix + ":" + userId, token, ttl);
		redis.put(prefix + "-token:" + token, userId, ttl);
	}

	private void revokeAllSessions(String userId) {
		List<String> refreshIds = redis.members("refresh-index:" + userId);
		redis.deleteKeys(refreshIds.stream().map(jti -> "refresh:" + jti).toList());
		redis.delete("refresh-index:" + userId);
	}

	private void checkSignupRate(RequestMetadata metadata) {
		long attempts = redis.increment("ratelimit:signup:" + metadata.ipAddress(), Duration.ofHours(1));
		if (attempts > 5) {
			throw tooMany("Too many signup attempts. Try again later.");
		}
	}

	private void prepareEmailForSignup(String email) {
		User existing = users.findByEmailNormalized(email).orElse(null);
		if (existing == null) {
			return;
		}
		if (existing.getStatus() == UserStatus.DELETED && existing.getDeletedAt() != null
				&& existing.getDeletedAt().isBefore(Instant.now().minus(Duration.ofDays(30)))) {
			existing.setEmailNormalized("deleted:" + existing.getId() + ":" + existing.getEmailNormalized());
			users.saveAndFlush(existing);
			return;
		}
		throw conflict("Email already registered");
	}

	private void enforceLock(String email, String ip, boolean admin) {
		if (redis.get(lockKey(email, ip, admin)).isPresent()) {
			throw new ApiException(HttpStatus.TOO_MANY_REQUESTS, "ACCOUNT_LOCKED",
					"Account is locked for 15 minutes. Try again later.");
		}
	}

	private void recordFailedLogin(String userId, String email, String ip, boolean admin, RequestMetadata metadata) {
		Duration ttl = admin ? ADMIN_LOCK_TTL : USER_LOCK_TTL;
		int threshold = 5;
		long failures = redis.increment(rateKey(email, ip, admin), ttl);
		redis.increment("ratelimit:login-ip:" + ip, ttl);
		if (failures >= threshold) {
			redis.put(lockKey(email, ip, admin), "locked", ttl);
		}
		events.log(userId, AuthEventType.LOGIN_FAILURE, metadata);
	}

	private void clearLoginCounters(String email, String ip) {
		redis.delete(rateKey(email, ip, false));
		redis.delete(rateKey(email, ip, true));
	}

	private String rateKey(String email, String ip, boolean admin) {
		return (admin ? "ratelimit:admin-login:" : "ratelimit:login:") + email + ":" + ip;
	}

	private String lockKey(String email, String ip, boolean admin) {
		return (admin ? "lock:admin-login:" : "lock:login:") + email + ":" + ip;
	}

	private void assertLoginAllowed(User user) {
		if (user.getStatus() == UserStatus.BLOCKED) {
			throw new ApiException(HttpStatus.FORBIDDEN, "ACCOUNT_SUSPENDED", "Your account has been suspended. Contact support.");
		}
		if (user.getStatus() == UserStatus.DELETED) {
			throw new ApiException(HttpStatus.UNAUTHORIZED, "ACCOUNT_DELETED", "This account no longer exists.");
		}
	}

	private String randomToken() {
		byte[] bytes = new byte[32];
		RANDOM.nextBytes(bytes);
		return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
	}

	private String devToken(String token) {
		return properties.isDevReturnTokens() ? token : null;
	}

	private ApiException conflict(String message) {
		return new ApiException(HttpStatus.CONFLICT, "CONFLICT", message);
	}

	private ApiException unauthorized(String message) {
		return new ApiException(HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", message);
	}

	private ApiException badRequest(String message) {
		return new ApiException(HttpStatus.BAD_REQUEST, "BAD_REQUEST", message);
	}

	private ApiException notFound(String message) {
		return new ApiException(HttpStatus.NOT_FOUND, "NOT_FOUND", message);
	}

	private ApiException tooMany(String message) {
		return new ApiException(HttpStatus.TOO_MANY_REQUESTS, "RATE_LIMITED", message);
	}
}
