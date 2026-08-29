package com.smartInvoice.auth_service.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "auth")
public class AuthProperties {
	private String issuer = "smart-invoice-auth";
	private String appBaseUrl = "http://localhost:3000";
	private String mailFrom = "no-reply@smartinvoice.local";
	private int accessTokenMinutes = 60;
	private int adminAccessTokenMinutes = 10;
	private int temporaryTokenMinutes = 5;
	private int emailCodeMinutes = 15;
	private int resetTokenMinutes = 15;
	private int refreshTokenDays = 7;
	private int bcryptStrength = 12;
	private String jwtKeyId = "smart-invoice-auth-key";
	private String jwtPrivateKey = "";
	private boolean tokenEncryptionEnabled = true;
	private String jweSecret = "";
	private boolean devReturnTokens = true;
	private String profilePictureUploadBaseUrl = "https://s3.amazonaws.com/smartinvoice-local";

	public String getIssuer() { return issuer; }
	public void setIssuer(String issuer) { this.issuer = issuer; }
	public String getAppBaseUrl() { return appBaseUrl; }
	public void setAppBaseUrl(String appBaseUrl) { this.appBaseUrl = appBaseUrl; }
	public String getMailFrom() { return mailFrom; }
	public void setMailFrom(String mailFrom) { this.mailFrom = mailFrom; }
	public int getAccessTokenMinutes() { return accessTokenMinutes; }
	public void setAccessTokenMinutes(int accessTokenMinutes) { this.accessTokenMinutes = accessTokenMinutes; }
	public int getAdminAccessTokenMinutes() { return adminAccessTokenMinutes; }
	public void setAdminAccessTokenMinutes(int adminAccessTokenMinutes) { this.adminAccessTokenMinutes = adminAccessTokenMinutes; }
	public int getTemporaryTokenMinutes() { return temporaryTokenMinutes; }
	public void setTemporaryTokenMinutes(int temporaryTokenMinutes) { this.temporaryTokenMinutes = temporaryTokenMinutes; }
	public int getEmailCodeMinutes() { return emailCodeMinutes; }
	public void setEmailCodeMinutes(int emailCodeMinutes) { this.emailCodeMinutes = emailCodeMinutes; }
	public int getResetTokenMinutes() { return resetTokenMinutes; }
	public void setResetTokenMinutes(int resetTokenMinutes) { this.resetTokenMinutes = resetTokenMinutes; }
	public int getRefreshTokenDays() { return refreshTokenDays; }
	public void setRefreshTokenDays(int refreshTokenDays) { this.refreshTokenDays = refreshTokenDays; }
	public int getBcryptStrength() { return bcryptStrength; }
	public void setBcryptStrength(int bcryptStrength) { this.bcryptStrength = bcryptStrength; }
	public String getJwtKeyId() { return jwtKeyId; }
	public void setJwtKeyId(String jwtKeyId) { this.jwtKeyId = jwtKeyId; }
	public String getJwtPrivateKey() { return jwtPrivateKey; }
	public void setJwtPrivateKey(String jwtPrivateKey) { this.jwtPrivateKey = jwtPrivateKey; }
	public boolean isTokenEncryptionEnabled() { return tokenEncryptionEnabled; }
	public void setTokenEncryptionEnabled(boolean tokenEncryptionEnabled) { this.tokenEncryptionEnabled = tokenEncryptionEnabled; }
	public String getJweSecret() { return jweSecret; }
	public void setJweSecret(String jweSecret) { this.jweSecret = jweSecret; }
	public boolean isDevReturnTokens() { return devReturnTokens; }
	public void setDevReturnTokens(boolean devReturnTokens) { this.devReturnTokens = devReturnTokens; }
	public String getProfilePictureUploadBaseUrl() { return profilePictureUploadBaseUrl; }
	public void setProfilePictureUploadBaseUrl(String profilePictureUploadBaseUrl) { this.profilePictureUploadBaseUrl = profilePictureUploadBaseUrl; }
}
