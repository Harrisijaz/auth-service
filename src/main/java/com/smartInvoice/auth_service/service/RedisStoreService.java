package com.smartInvoice.auth_service.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadLocalRandom;

@Service
public class RedisStoreService {
	private static final Logger log = LoggerFactory.getLogger(RedisStoreService.class);
	private final StringRedisTemplate redis;
	private final Map<String, ExpiringValue> fallback = new ConcurrentHashMap<>();

	public RedisStoreService(StringRedisTemplate redis) {
		this.redis = redis;
	}

	public void put(String key, String value, Duration ttl) {
		try {
			redis.opsForValue().set(key, value, ttl);
		} catch (RuntimeException ex) {
			log.warn("Redis unavailable for put {}; using in-memory fallback", key);
			fallback.put(key, new ExpiringValue(value, Instant.now().plus(ttl)));
		}
	}

	public Optional<String> get(String key) {
		try {
			return Optional.ofNullable(redis.opsForValue().get(key));
		} catch (RuntimeException ex) {
			return fallbackGet(key);
		}
	}

	public boolean delete(String key) {
		try {
			Boolean deleted = redis.delete(key);
			fallback.remove(key);
			return Boolean.TRUE.equals(deleted);
		} catch (RuntimeException ex) {
			return fallback.remove(key) != null;
		}
	}

	public long increment(String key, Duration ttl) {
		try {
			Long value = redis.opsForValue().increment(key);
			if (value != null && value == 1L) {
				redis.expire(key, ttl);
			}
			return value == null ? 0 : value;
		} catch (RuntimeException ex) {
			ExpiringValue current = fallback.get(key);
			if (current == null || current.isExpired()) {
				fallback.put(key, new ExpiringValue("1", Instant.now().plus(ttl)));
				return 1;
			}
			long next = Long.parseLong(current.value()) + 1;
			fallback.put(key, new ExpiringValue(Long.toString(next), current.expiresAt()));
			return next;
		}
	}

	public void addToSet(String key, String member, Duration ttl) {
		try {
			redis.opsForSet().add(key, member);
			redis.expire(key, ttl);
		} catch (RuntimeException ex) {
			String stored = fallbackGet(key).orElse("");
			String next = stored.isBlank() ? member : stored + "," + member;
			fallback.put(key, new ExpiringValue(next, Instant.now().plus(ttl)));
		}
	}

	public List<String> members(String key) {
		try {
			Set<String> members = redis.opsForSet().members(key);
			return members == null ? List.of() : new ArrayList<>(members);
		} catch (RuntimeException ex) {
			return fallbackGet(key).map(value -> List.of(value.split(","))).orElseGet(List::of);
		}
	}

	public void deleteKeys(List<String> keys) {
		if (keys.isEmpty()) {
			return;
		}
		try {
			redis.delete(keys);
		} catch (RuntimeException ex) {
			keys.forEach(fallback::remove);
		}
	}

	public String randomDigits(int length) {
		StringBuilder code = new StringBuilder();
		for (int i = 0; i < length; i++) {
			code.append(ThreadLocalRandom.current().nextInt(10));
		}
		return code.toString();
	}

	private Optional<String> fallbackGet(String key) {
		ExpiringValue value = fallback.get(key);
		if (value == null) {
			return Optional.empty();
		}
		if (value.isExpired()) {
			fallback.remove(key);
			return Optional.empty();
		}
		return Optional.of(value.value());
	}

	private record ExpiringValue(String value, Instant expiresAt) {
		boolean isExpired() {
			return Instant.now().isAfter(expiresAt);
		}
	}
}
