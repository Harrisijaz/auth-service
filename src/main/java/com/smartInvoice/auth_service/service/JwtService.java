package com.smartInvoice.auth_service.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.smartInvoice.auth_service.config.AuthProperties;
import com.smartInvoice.auth_service.domain.User;
import com.smartInvoice.auth_service.domain.UserRole;
import com.smartInvoice.auth_service.web.ApiException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

@Service
public class JwtService {
	public static final String TYPE_ACCESS = "access";
	public static final String TYPE_LOGIN_2FA = "login_2fa";

	private final AuthProperties properties;
	private final RSAKey rsaKey;
	private final RSASSASigner signer;
	private final byte[] jweSecret;

	public JwtService(AuthProperties properties) {
		this.properties = properties;
		this.rsaKey = createKey(properties);
		this.jweSecret = createJweSecret(properties);
		try {
			this.signer = new RSASSASigner(rsaKey.toPrivateKey());
		} catch (JOSEException ex) {
			throw new IllegalStateException("Unable to create JWT signer", ex);
		}
	}

	public String issueAccessToken(User user) {
		int minutes = user.getRole() == UserRole.ADMIN
				? properties.getAdminAccessTokenMinutes()
				: properties.getAccessTokenMinutes();
		return issue(user, TYPE_ACCESS, Duration.ofMinutes(minutes), UUID.randomUUID().toString());
	}

	public String issueLoginTemporaryToken(User user, String jti) {
		return issue(user, TYPE_LOGIN_2FA, Duration.ofMinutes(properties.getTemporaryTokenMinutes()), jti);
	}

	public AuthenticatedUser verify(String token, String expectedType) {
		try {
			SignedJWT jwt = SignedJWT.parse(decryptIfNeeded(token));
			JWSHeader header = jwt.getHeader();
			if (!JWSAlgorithm.RS256.equals(header.getAlgorithm())) {
				throw invalid("Unsupported token algorithm");
			}
			if (!properties.getJwtKeyId().equals(header.getKeyID())) {
				throw invalid("Unrecognized signing key");
			}
			if (!jwt.verify(new RSASSAVerifier(rsaKey.toRSAPublicKey()))) {
				throw invalid("Invalid token signature");
			}
			JWTClaimsSet claims = jwt.getJWTClaimsSet();
			String tokenType = claims.getStringClaim("token_type");
			if (!expectedType.equals(tokenType)) {
				throw invalid("Invalid token type");
			}
			Instant now = Instant.now();
			Instant expires = claims.getExpirationTime().toInstant();
			if (expires.isBefore(now)) {
				throw new ApiException(HttpStatus.UNAUTHORIZED, "TOKEN_EXPIRED", "Session expired. Please login again.");
			}
			Date issuedAt = claims.getIssueTime();
			if (issuedAt != null && issuedAt.toInstant().minusSeconds(30).isAfter(now)) {
				throw invalid("Token issue time is in the future");
			}
			UserRole role = UserRole.valueOf(claims.getStringClaim("role"));
			return new AuthenticatedUser(
					claims.getSubject(),
					claims.getStringClaim("email"),
					role,
					claims.getJWTID(),
					tokenType);
		} catch (ApiException ex) {
			throw ex;
		} catch (Exception ex) {
			throw invalid("Invalid token");
		}
	}

	public Map<String, Object> jwks() {
		return new JWKSet(rsaKey.toPublicJWK()).toJSONObject();
	}

	private String issue(User user, String type, Duration ttl, String jti) {
		Instant now = Instant.now();
		JWTClaimsSet claims = new JWTClaimsSet.Builder()
				.issuer(properties.getIssuer())
				.subject(user.getId())
				.claim("email", user.getEmailNormalized())
				.claim("role", user.getRole().name())
				.claim("token_type", type)
				.jwtID(jti)
				.issueTime(Date.from(now))
				.expirationTime(Date.from(now.plus(ttl)))
				.build();
		SignedJWT jwt = new SignedJWT(
				new JWSHeader.Builder(JWSAlgorithm.RS256)
						.keyID(properties.getJwtKeyId())
						.type(JOSEObjectType.JWT)
						.build(),
				claims);
		try {
			jwt.sign(signer);
			return encryptIfNeeded(jwt.serialize());
		} catch (JOSEException ex) {
			throw new IllegalStateException("Unable to sign JWT", ex);
		}
	}

	private String encryptIfNeeded(String signedJwt) throws JOSEException {
		if (!properties.isTokenEncryptionEnabled()) {
			return signedJwt;
		}
		JWEObject jwe = new JWEObject(
				new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A256GCM)
						.contentType("JWT")
						.keyID(properties.getJwtKeyId())
						.build(),
				new Payload(signedJwt));
		jwe.encrypt(new DirectEncrypter(jweSecret));
		return jwe.serialize();
	}

	private String decryptIfNeeded(String token) throws Exception {
		if (!properties.isTokenEncryptionEnabled()) {
			return token;
		}
		JWEObject jwe = JWEObject.parse(token);
		if (!JWEAlgorithm.DIR.equals(jwe.getHeader().getAlgorithm())
				|| !EncryptionMethod.A256GCM.equals(jwe.getHeader().getEncryptionMethod())) {
			throw invalid("Unsupported token encryption");
		}
		if (!properties.getJwtKeyId().equals(jwe.getHeader().getKeyID())) {
			throw invalid("Unrecognized encryption key");
		}
		jwe.decrypt(new DirectDecrypter(jweSecret));
		return jwe.getPayload().toString();
	}

	private RSAKey createKey(AuthProperties properties) {
		try {
			KeyPair pair;
			if (properties.getJwtPrivateKey() == null || properties.getJwtPrivateKey().isBlank()) {
				KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
				generator.initialize(2048);
				pair = generator.generateKeyPair();
			} else {
				PrivateKey privateKey = parsePrivateKey(properties.getJwtPrivateKey());
				RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) privateKey;
				java.security.spec.RSAPublicKeySpec publicSpec =
						new java.security.spec.RSAPublicKeySpec(rsaPrivateKey.getModulus(), java.math.BigInteger.valueOf(65537));
				RSAPublicKey publicKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(publicSpec);
				pair = new KeyPair(publicKey, privateKey);
			}
			return new RSAKey.Builder((RSAPublicKey) pair.getPublic())
					.privateKey((RSAPrivateKey) pair.getPrivate())
					.keyUse(KeyUse.SIGNATURE)
					.keyID(properties.getJwtKeyId())
					.algorithm(JWSAlgorithm.RS256)
					.build();
		} catch (Exception ex) {
			throw new IllegalStateException("Unable to initialize RSA signing key", ex);
		}
	}

	private byte[] createJweSecret(AuthProperties properties) {
		String configured = properties.getJweSecret();
		if (configured == null || configured.isBlank()) {
			byte[] generated = new byte[32];
			new java.security.SecureRandom().nextBytes(generated);
			return generated;
		}
		byte[] decoded;
		try {
			decoded = Base64.getUrlDecoder().decode(configured);
		} catch (IllegalArgumentException ex) {
			decoded = Base64.getDecoder().decode(configured);
		}
		if (decoded.length != 32) {
			throw new IllegalStateException("AUTH_JWE_SECRET must be a Base64 encoded 32-byte AES key for A256GCM");
		}
		return decoded;
	}

	private PrivateKey parsePrivateKey(String configured) throws Exception {
		String pem = configured
				.replace("-----BEGIN PRIVATE KEY-----", "")
				.replace("-----END PRIVATE KEY-----", "")
				.replace("\\n", "")
				.replace("\n", "")
				.replace("\r", "")
				.replace(" ", "");
		byte[] decoded = Base64.getDecoder().decode(pem);
		return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decoded));
	}

	private ApiException invalid(String message) {
		return new ApiException(HttpStatus.UNAUTHORIZED, "INVALID_TOKEN", message);
	}
}
