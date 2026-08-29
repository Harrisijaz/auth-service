package com.smartInvoice.auth_service;

import com.smartInvoice.auth_service.config.AuthProperties;
import com.smartInvoice.auth_service.domain.User;
import com.smartInvoice.auth_service.domain.UserRole;
import com.smartInvoice.auth_service.domain.UserStatus;
import com.smartInvoice.auth_service.dto.MessageResponse;
import com.smartInvoice.auth_service.dto.AuthResponse;
import com.smartInvoice.auth_service.dto.LoginRequest;
import com.smartInvoice.auth_service.dto.SignupRequest;
import com.smartInvoice.auth_service.repo.UserRepository;
import com.smartInvoice.auth_service.service.AuthEventService;
import com.smartInvoice.auth_service.service.AuthService;
import com.smartInvoice.auth_service.service.EmailDispatchService;
import com.smartInvoice.auth_service.service.JwtService;
import com.smartInvoice.auth_service.service.RedisStoreService;
import com.smartInvoice.auth_service.service.ValidationService;
import com.smartInvoice.auth_service.web.ApiException;
import com.smartInvoice.auth_service.web.RequestMetadata;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Duration;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AuthServiceSignupTests {
	private UserRepository users;
	private PasswordEncoder passwordEncoder;
	private RedisStoreService redis;
	private EmailDispatchService emailDispatch;
	private AuthEventService events;
	private JwtService jwtService;
	private AuthService authService;

	@BeforeEach
	void setUp() {
		users = mock(UserRepository.class);
		passwordEncoder = mock(PasswordEncoder.class);
		redis = mock(RedisStoreService.class);
		emailDispatch = mock(EmailDispatchService.class);
		events = mock(AuthEventService.class);
		jwtService = mock(JwtService.class);
		AuthProperties properties = new AuthProperties();
		properties.setDevReturnTokens(false);
		when(redis.increment(anyString(), any(Duration.class))).thenReturn(1L);
		when(redis.randomDigits(6)).thenReturn("123456");
		when(passwordEncoder.encode(anyString())).thenReturn("encoded-password");
		authService = new AuthService(users, passwordEncoder, new ValidationService(), redis, jwtService,
				properties, emailDispatch, events);
	}

	@Test
	void signupCreatesUnverifiedUserWhenEmailDoesNotExist() {
		when(users.findByEmailNormalized("new@example.com")).thenReturn(Optional.empty());
		SignupRequest request = new SignupRequest(" New@Example.COM ", "Password1!", "New User", true);

		MessageResponse response = authService.signup(request, metadata());

		assertThat(response.message()).isEqualTo("Signup successful. Please verify your email.");
		ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
		verify(users).saveAndFlush(userCaptor.capture());
		User saved = userCaptor.getValue();
		assertThat(saved.getEmailNormalized()).isEqualTo("new@example.com");
		assertThat(saved.getRole()).isEqualTo(UserRole.USER);
		assertThat(saved.getStatus()).isEqualTo(UserStatus.UNVERIFIED);
		assertThat(saved.isEmailVerified()).isFalse();
		assertThat(saved.isTrusted()).isFalse();
		verify(emailDispatch).sendVerification("new@example.com", "123456");
	}

	@Test
	void signupRejectsActiveExistingEmail() {
		User existing = new User();
		existing.setEmailNormalized("existing@example.com");
		existing.setStatus(UserStatus.ACTIVE);
		existing.setEmailVerified(true);
		when(users.findByEmailNormalized("existing@example.com")).thenReturn(Optional.of(existing));
		SignupRequest request = new SignupRequest("existing@example.com", "Password1!", "Existing User", true);

		assertThatThrownBy(() -> authService.signup(request, metadata()))
				.isInstanceOf(ApiException.class)
				.hasMessage("Email already registered");

		verify(users, never()).saveAndFlush(any(User.class));
	}

	@Test
	void signupRejectsRecentUnverifiedExistingEmailWithClearMessage() {
		User existing = new User();
		existing.setEmailNormalized("pending@example.com");
		existing.setStatus(UserStatus.UNVERIFIED);
		existing.setEmailVerified(false);
		when(users.findByEmailNormalized("pending@example.com")).thenReturn(Optional.of(existing));
		SignupRequest request = new SignupRequest("pending@example.com", "Password1!", "Pending User", true);

		assertThatThrownBy(() -> authService.signup(request, metadata()))
				.isInstanceOf(ApiException.class)
				.hasMessage("Account already exists but is not verified. Please verify your email or resend the code.");

		verify(users, never()).saveAndFlush(any(User.class));
	}

	@Test
	void loginReturnsAccessTokenWithoutRefreshToken() {
		User existing = new User();
		existing.setId("usr_123");
		existing.setEmailNormalized("user@example.com");
		existing.setFullName("Test User");
		existing.setPasswordHash("encoded-password");
		existing.setRole(UserRole.USER);
		existing.setStatus(UserStatus.ACTIVE);
		existing.setEmailVerified(true);
		when(users.findByEmailNormalized("user@example.com")).thenReturn(Optional.of(existing));
		when(passwordEncoder.matches("Password1!", "encoded-password")).thenReturn(true);
		when(jwtService.issueAccessToken(existing)).thenReturn("access-token");

		AuthResponse response = authService.login(new LoginRequest("user@example.com", "Password1!"), metadata());

		assertThat(response.accessToken()).isEqualTo("access-token");
		assertThat(response.refreshToken()).isNull();
	}

	private RequestMetadata metadata() {
		return new RequestMetadata("127.0.0.1", "JUnit");
	}
}
