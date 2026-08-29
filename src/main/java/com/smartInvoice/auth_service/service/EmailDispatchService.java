package com.smartInvoice.auth_service.service;

import com.smartInvoice.auth_service.config.AuthProperties;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Year;
import java.util.Map;

@Service
public class EmailDispatchService {
	private static final Logger log = LoggerFactory.getLogger(EmailDispatchService.class);
	private static final String TEMPLATE_PATH = "templates/email/";
	private final JavaMailSender mailSender;
	private final AuthProperties authProperties;
	private final String mailUsername;

	public EmailDispatchService(JavaMailSender mailSender, AuthProperties authProperties,
			@Value("${spring.mail.username:}") String mailUsername) {
		this.mailSender = mailSender;
		this.authProperties = authProperties;
		this.mailUsername = mailUsername;
	}

	public void sendVerification(String email, String code) {
		sendTemplate(email, "Verify your SmartInvoice email", "email-verification.html", Map.of(
				"preheader", "Verify your email address to activate your SmartInvoice account.",
				"title", "Verify your email",
				"intro", "Thanks for creating your SmartInvoice account. Enter this code to finish setup.",
				"code", code,
				"expiry", authProperties.getEmailCodeMinutes() + " minutes"));
	}

	public void sendPasswordReset(String email, String token) {
		String link = authProperties.getAppBaseUrl() + "/reset-password?token=" + token;
		sendTemplate(email, "Reset your SmartInvoice password", "password-reset.html", Map.of(
				"preheader", "Use this secure link to reset your SmartInvoice password.",
				"title", "Reset your password",
				"intro", "We received a request to reset the password for your SmartInvoice account.",
				"buttonText", "Reset password",
				"actionUrl", link,
				"expiry", authProperties.getResetTokenMinutes() + " minutes"));
	}

	public void sendUser2FaCode(String email, String code) {
		sendTemplate(email, "Your SmartInvoice login code", "user-2fa-code.html", Map.of(
				"preheader", "Your SmartInvoice login verification code is " + code + ".",
				"title", "Login verification code",
				"intro", "Use this code to complete your SmartInvoice sign in.",
				"code", code,
				"expiry", authProperties.getTemporaryTokenMinutes() + " minutes"));
	}

	public void sendPasswordResetSuccess(String email) {
		sendTemplate(email, "Your SmartInvoice password was reset", "password-reset-success.html", Map.of(
				"preheader", "Your SmartInvoice password was reset successfully.",
				"title", "Password reset complete",
				"intro", "Your SmartInvoice password has been reset successfully. You can now sign in with your new password."));
	}

	public void sendPasswordChanged(String email) {
		sendTemplate(email, "Your SmartInvoice password was changed", "password-changed.html", Map.of(
				"preheader", "Your SmartInvoice password was changed successfully.",
				"title", "Password changed",
				"intro", "Your SmartInvoice password was changed successfully. For security, all existing sessions were signed out."));
	}

	private void sendTemplate(String to, String subject, String templateName, Map<String, String> values) {
		if (mailUsername == null || mailUsername.isBlank()) {
			log.warn("SMTP username is not configured. Skipping email '{}' to {}", subject, to);
			return;
		}
		try {
			String html = render(templateName, values);
			MimeMessage message = mailSender.createMimeMessage();
			MimeMessageHelper helper = new MimeMessageHelper(message, true, StandardCharsets.UTF_8.name());
			helper.setFrom(authProperties.getMailFrom());
			helper.setTo(to);
			helper.setSubject(subject);
			helper.setText(toPlainText(values), html);
			mailSender.send(message);
		} catch (MessagingException | IOException | RuntimeException ex) {
			log.warn("Unable to send email '{}' to {}: {}", subject, to, ex.getMessage());
		}
	}

	private String render(String templateName, Map<String, String> values) throws IOException {
		ClassPathResource resource = new ClassPathResource(TEMPLATE_PATH + templateName);
		String html = resource.getContentAsString(StandardCharsets.UTF_8);
		Map<String, String> defaults = Map.of(
				"appName", "SmartInvoice",
				"supportEmail", authProperties.getMailFrom(),
				"year", String.valueOf(Year.now().getValue()));
		for (Map.Entry<String, String> entry : defaults.entrySet()) {
			html = html.replace("{{" + entry.getKey() + "}}", escapeHtml(entry.getValue()));
		}
		for (Map.Entry<String, String> entry : values.entrySet()) {
			html = html.replace("{{" + entry.getKey() + "}}", escapeHtml(entry.getValue()));
		}
		return html;
	}

	private String toPlainText(Map<String, String> values) {
		StringBuilder text = new StringBuilder(values.getOrDefault("title", "SmartInvoice")).append("\n\n")
				.append(values.getOrDefault("intro", ""));
		if (values.containsKey("code")) {
			text.append("\n\nCode: ").append(values.get("code"));
		}
		if (values.containsKey("actionUrl")) {
			text.append("\n\n").append(values.get("buttonText")).append(": ").append(values.get("actionUrl"));
		}
		if (values.containsKey("expiry")) {
			text.append("\n\nExpires in ").append(values.get("expiry")).append(".");
		}
		return text.toString();
	}

	private String escapeHtml(String value) {
		if (value == null) {
			return "";
		}
		return value
				.replace("&", "&amp;")
				.replace("<", "&lt;")
				.replace(">", "&gt;")
				.replace("\"", "&quot;")
				.replace("'", "&#39;");
	}
}
