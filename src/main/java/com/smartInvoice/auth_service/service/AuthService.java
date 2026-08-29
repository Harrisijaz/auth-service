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
import com.smartInvoice.auth_service.dto.ProfilePictureConfirmRequest;
import com.smartInvoice.auth_service.dto.ProfilePictureUploadUrlRequest;
import com.smartInvoice.auth_service.dto.ProfilePictureUploadUrlResponse;
import com.smartInvoice.auth_service.dto.ProfileResponse;
import com.smartInvoice.auth_service.dto.ProfileUpdateRequest;
import com.smartInvoice.auth_service.dto.RefreshTokenRequest;
import com.smartInvoice.auth_service.dto.ResetPasswordRequest;
import com.smartInvoice.auth_service.dto.SignupRequest;
import com.smartInvoice.auth_service.dto.TokenPairResponse;
import com.smartInvoice.auth_service.dto.UserInfoResponse;
import com.smartInvoice.auth_service.dto.VerifyEmailRequest;
import com.smartInvoice.auth_service.repo.UserRepository;
import com.smartInvoice.auth_service.web.ApiException;
import com.smartInvoice.auth_service.web.RequestMetadata;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
	private static final Logger log = LoggerFactory.getLogger(AuthService.class);
	private static final String GENERIC_LOGIN_ERROR = "Invalid email or password";
	private static final Duration USER_LOCK_TTL = Duration.ofMinutes(15);
	private static final Duration ADMIN_LOCK_TTL = Duration.ofMinutes(30);
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
			log.warn("Signup failed due to data integrity violation for email {}", email, ex);
			if (users.findByEmailNormalized(email).isPresent()) {
				throw conflict("Email already registered");
			}
			throw new ApiException(HttpStatus.CONFLICT, "SIGNUP_DATA_CONFLICT",
					"Signup failed because a database constraint was violated: " + rootCauseMessage(ex));
		}
		String code = issueEmailVerification(user, metadata);
		events.log(user.getId(), AuthEventType.SIGNUP, metadata);
		return new MessageResponse("Signup successful. Please verify your email.", devToken(code));
	}

	@Transactional
	public MessageResponse verifyEmail(VerifyEmailRequest request, RequestMetadata metadata) {
		String email = validation.normalizeEmail(request.email());
		User user = users.findByEmailNormalized(email).orElseThrow(() -> badRequest("Invalid verification code"));
		if (user.isEmailVerified()) {
			return MessageResponse.of("Your email is already verified.");
		}
		String key = "otp:verify:" + user.getId();
		String stored = redis.get(key)
				.orElseThrow(() -> new ApiException(HttpStatus.BAD_REQUEST, "TOKEN_EXPIRED", "This code has expired. Request a new one."));
		String[] parts = stored.split("\\|");
		int attempts = Integer.parseInt(parts[1]);
		if (!parts[0].equals(request.code())) {
			attempts++;
			if (attempts >= 5) {
				redis.delete(key);
				throw tooMany("Too many incorrect attempts. Request a new verification code.");
			}
			redis.put(key, parts[0] + "|" + attempts, Duration.ofMinutes(properties.getEmailCodeMinutes()));
			throw badRequest("Invalid verification code");
		}
		user.setEmailVerified(true);
		user.setStatus(UserStatus.ACTIVE);
		users.save(user);
		redis.delete(key);
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
		String code = issueEmailVerification(user, metadata);
		return new MessageResponse("Verification email sent.", devToken(code));
	}

	public AuthResponse login(LoginRequest request, RequestMetadata metadata) {
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
		events.log(user.getId(), AuthEventType.LOGIN_SUCCESS, metadata);
		return authResponse("Login successful.", user);
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

	public MessageResponse logout(String accessToken, RefreshTokenRequest request, RequestMetadata metadata) {
		AuthenticatedUser principal = requireAccess(accessToken);
		if (request != null && request.refreshToken() != null && !request.refreshToken().isBlank()) {
			revokeRefreshToken(request.refreshToken(), principal.userId());
		}
		events.log(principal.userId(), AuthEventType.LOGOUT, metadata);
		return MessageResponse.of("Logged out.");
	}

	public MessageResponse logout(String accessToken, RequestMetadata metadata) {
		return logout(accessToken, null, metadata);
	}

	public TokenPairResponse refresh(RefreshTokenRequest request, RequestMetadata metadata) {
		AuthenticatedUser principal = jwtService.verify(request.refreshToken(), JwtService.TYPE_REFRESH);
		String key = "refresh:" + principal.jti();
		String userId = redis.get(key).orElse(null);
		if (userId == null) {
			revokeAllSessions(principal.userId());
			events.log(principal.userId(), AuthEventType.REFRESH_REUSE_DETECTED, metadata);
			throw unauthorized("Refresh token is invalid. Please log in again.");
		}
		if (!principal.userId().equals(userId)) {
			revokeAllSessions(principal.userId());
			throw unauthorized("Refresh token is invalid. Please log in again.");
		}
		User user = users.findById(userId).orElseThrow(() -> unauthorized("Invalid refresh token"));
		assertLoginAllowed(user);
		redis.delete(key);
		TokenPair tokens = issueTokenPair(user);
		events.log(user.getId(), AuthEventType.TOKEN_REFRESH, metadata);
		return new TokenPairResponse("Token refreshed.", tokens.accessToken(), tokens.refreshToken(), userInfo(user));
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

	public ProfileResponse profile(String accessToken) {
		User user = currentUser(accessToken);
		return profileResponse(user);
	}

	@Transactional
	public ProfileResponse updateProfile(String accessToken, ProfileUpdateRequest request, RequestMetadata metadata) {
		validation.validateFullName(request.displayName());
		User user = currentUser(accessToken);
		user.setFullName(request.displayName().trim());
		users.save(user);
		events.log(user.getId(), AuthEventType.PROFILE_UPDATED, metadata);
		return profileResponse(user);
	}

	public ProfilePictureUploadUrlResponse profilePictureUploadUrl(String accessToken,
			ProfilePictureUploadUrlRequest request, RequestMetadata metadata) {
		User user = currentUser(accessToken);
		validateProfilePicture(request);
		long attempts = redis.increment("ratelimit:profile-picture:" + user.getId(), Duration.ofHours(1));
		if (attempts > 10) {
			throw tooMany("Too many profile picture upload requests. Try again later.");
		}
		String extension = extension(request.fileName());
		String objectKey = "profile-pictures/" + user.getId() + "/" + UUID.randomUUID() + "." + extension;
		String base = properties.getProfilePictureUploadBaseUrl().replaceAll("/+$", "");
		String publicUrl = base + "/" + objectKey;
		redis.put("profile-picture-upload:" + user.getId() + ":" + objectKey, publicUrl,
				Duration.ofMinutes(5));
		events.log(user.getId(), AuthEventType.PROFILE_PICTURE_UPLOAD_REQUESTED, metadata);
		return new ProfilePictureUploadUrlResponse(publicUrl, objectKey, publicUrl, "PUT",
				Instant.now().plus(Duration.ofMinutes(5)));
	}

	@Transactional
	public ProfileResponse confirmProfilePicture(String accessToken, ProfilePictureConfirmRequest request,
			RequestMetadata metadata) {
		User user = currentUser(accessToken);
		String key = "profile-picture-upload:" + user.getId() + ":" + request.objectKey();
		String publicUrl = redis.get(key).orElseThrow(() -> badRequest("Profile picture upload URL is expired or invalid"));
		user.setProfilePictureUrl(publicUrl);
		users.save(user);
		redis.delete(key);
		events.log(user.getId(), AuthEventType.PROFILE_PICTURE_UPDATED, metadata);
		return profileResponse(user);
	}

	@Transactional
	public ProfileResponse removeProfilePicture(String accessToken, RequestMetadata metadata) {
		User user = currentUser(accessToken);
		user.setProfilePictureUrl(null);
		users.save(user);
		events.log(user.getId(), AuthEventType.PROFILE_PICTURE_REMOVED, metadata);
		return profileResponse(user);
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
		return new AuthResponse(message, jwtService.issueAccessToken(user), null, user.isEmailVerified(), userInfo(user));
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
		String code = redis.randomDigits(6);
		redis.put("otp:verify:" + user.getId(), code + "|0", Duration.ofMinutes(properties.getEmailCodeMinutes()));
		emailDispatch.sendVerification(user.getEmailNormalized(), code);
		events.log(user.getId(), AuthEventType.EMAIL_VERIFICATION_SENT, metadata);
		return code;
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

	private void revokeRefreshToken(String refreshToken, String expectedUserId) {
		AuthenticatedUser principal = jwtService.verify(refreshToken, JwtService.TYPE_REFRESH);
		if (!expectedUserId.equals(principal.userId())) {
			throw unauthorized("Refresh token does not belong to this session");
		}
		redis.delete("refresh:" + principal.jti());
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
		if (existing.getStatus() == UserStatus.UNVERIFIED && !existing.isEmailVerified()
				&& existing.getCreatedAt() != null
				&& existing.getCreatedAt().isBefore(Instant.now().minus(Duration.ofDays(30)))) {
			freeEmail(existing, "stale-unverified");
			return;
		}
		if (existing.getStatus() == UserStatus.DELETED) {
			freeEmail(existing, "deleted");
			return;
		}
		if (existing.getStatus() == UserStatus.UNVERIFIED && !existing.isEmailVerified()) {
			throw conflict("Account already exists but is not verified. Please verify your email or resend the code.");
		}
		throw conflict("Email already registered");
	}

	private void freeEmail(User existing, String reason) {
		if (!existing.getEmailNormalized().startsWith(reason + ":")) {
			existing.setEmailNormalized(reason + ":" + existing.getId() + ":" + existing.getEmailNormalized());
			existing.setEmail(reason + ":" + existing.getId() + ":" + existing.getEmail());
			users.saveAndFlush(existing);
		}
	}

	private void enforceLock(String email, String ip, boolean admin) {
		if (redis.get(lockKey(email, ip, admin)).isPresent()) {
			throw new ApiException(HttpStatus.TOO_MANY_REQUESTS, "ACCOUNT_LOCKED",
					"Account is locked for 15 minutes. Try again later.");
		}
	}

	private void recordFailedLogin(String userId, String email, String ip, boolean admin, RequestMetadata metadata) {
		Duration ttl = admin ? ADMIN_LOCK_TTL : USER_LOCK_TTL;
		int threshold = admin ? 3 : 5;
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
		if (!user.isEmailVerified() || user.getStatus() == UserStatus.UNVERIFIED) {
			throw new ApiException(HttpStatus.FORBIDDEN, "EMAIL_NOT_VERIFIED", "Please verify your email before logging in.");
		}
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

	private String rootCauseMessage(Exception ex) {
		Throwable cause = ex;
		while (cause.getCause() != null) {
			cause = cause.getCause();
		}
		String message = cause.getMessage();
		return cause.getClass().getSimpleName() + (message == null || message.isBlank() ? "" : " - " + message);
	}

	private TokenPair issueTokenPair(User user) {
		String refreshJti = UUID.randomUUID().toString();
		String refreshToken = jwtService.issueRefreshToken(user, refreshJti);
		Duration ttl = Duration.ofDays(properties.getRefreshTokenDays());
		redis.put("refresh:" + refreshJti, user.getId(), ttl);
		redis.addToSet("refresh-index:" + user.getId(), refreshJti, ttl);
		return new TokenPair(jwtService.issueAccessToken(user), refreshToken);
	}

	private User currentUser(String accessToken) {
		AuthenticatedUser principal = requireAccess(accessToken);
		return users.findById(principal.userId()).orElseThrow(() -> unauthorized("Invalid token"));
	}

	private ProfileResponse profileResponse(User user) {
		return new ProfileResponse(user.getId(), user.getFullName(), user.getEmailNormalized(),
				user.getProfilePictureUrl(), user.getCreatedAt());
	}

	private void validateProfilePicture(ProfilePictureUploadUrlRequest request) {
		if (request.sizeBytes() > 2 * 1024 * 1024) {
			throw badRequest("Profile picture must be 2MB or smaller");
		}
		String contentType = request.contentType().toLowerCase();
		if (!List.of("image/png", "image/jpeg", "image/jpg", "image/webp").contains(contentType)) {
			throw badRequest("Profile picture must be PNG, JPG, JPEG, or WEBP");
		}
		String extension = extension(request.fileName());
		if (!List.of("png", "jpg", "jpeg", "webp").contains(extension)) {
			throw badRequest("Profile picture file extension must be png, jpg, jpeg, or webp");
		}
	}

	private String extension(String fileName) {
		int dot = fileName == null ? -1 : fileName.lastIndexOf('.');
		if (dot < 0 || dot == fileName.length() - 1) {
			throw badRequest("Profile picture file extension is required");
		}
		return fileName.substring(dot + 1).toLowerCase();
	}

	private record TokenPair(String accessToken, String refreshToken) {
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
