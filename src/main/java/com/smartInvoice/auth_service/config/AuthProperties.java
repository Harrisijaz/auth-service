package com.smartInvoice.auth_service.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "auth")
public class AuthProperties {
	private String issuer = "smart-invoice-auth";
	private String appBaseUrl = "http://localhost:3000";
	private String mailFrom = "no-reply@smartinvoice.local";
	private int accessTokenMinutes = 5;
	private int adminAccessTokenMinutes = 5;
	private int temporaryTokenMinutes = 5;
	private int emailTokenHours = 24;
	private int resetTokenMinutes = 15;
	private int bcryptStrength = 12;
	private String jwtKeyId = "smart-invoice-auth-key";
	private String jwtPrivateKey = "";
	private boolean tokenEncryptionEnabled = true;
	private String jweSecret = "";
	private boolean devReturnTokens = true;

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
	public int getEmailTokenHours() { return emailTokenHours; }
	public void setEmailTokenHours(int emailTokenHours) { this.emailTokenHours = emailTokenHours; }
	public int getResetTokenMinutes() { return resetTokenMinutes; }
	public void setResetTokenMinutes(int resetTokenMinutes) { this.resetTokenMinutes = resetTokenMinutes; }
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
}
