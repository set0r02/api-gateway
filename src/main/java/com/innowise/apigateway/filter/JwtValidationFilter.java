package com.innowise.apigateway.filter;

import com.innowise.apigateway.security.SecurityProperties;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

@Slf4j
@Component
public class JwtValidationFilter implements GlobalFilter, Ordered {

    private final SecretKey secretKey;
    private final SecurityProperties securityProperties;

    public JwtValidationFilter(@Value("${app.jwt.secret}") String secret, SecurityProperties securityProperties) {

        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.securityProperties = securityProperties;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        String path = exchange.getRequest().getURI().getPath();

        if (isWhitelisted(path)) {
            return chain.filter(exchange);
        }

        String authHeader = exchange.getRequest()
                .getHeaders()
                .getFirst(HttpHeaders.AUTHORIZATION);

        String token = extractToken(authHeader);

        if (token == null) {
            return denyAccess(exchange, "Missing Authorization header");
        }

        if (!isTokenValid(token)) {
            return denyAccess(exchange, "Invalid JWT token");
        }

        return chain.filter(exchange);
    }

    private Mono<Void> denyAccess(ServerWebExchange exchange, String reason) {
        log.warn("Request rejected to {}: {}",
                exchange.getRequest().getURI(),
                reason);

        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }

    private boolean isWhitelisted(String path) {
        return securityProperties.publicPaths()
                .stream()
                .anyMatch(path::startsWith);
    }

    private String extractToken(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return null;
        }
        return authHeader.substring(7);
    }

    private boolean isTokenValid(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            log.warn("JWT validation failed", e);
            return false;
        }
    }

    @Override
    public int getOrder() {
        return -1;
    }
}
