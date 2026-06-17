    package com.innowise.apigateway.filter;

    import io.jsonwebtoken.Jwts;
    import io.jsonwebtoken.security.Keys;
    import lombok.extern.slf4j.Slf4j;
    import org.springframework.beans.factory.annotation.Value;
    import org.springframework.http.HttpHeaders;
    import org.springframework.http.HttpStatus;
    import org.springframework.stereotype.Component;
    import org.springframework.web.server.ServerWebExchange;
    import org.springframework.web.server.WebFilter;
    import org.springframework.web.server.WebFilterChain;
    import reactor.core.publisher.Mono;

    import javax.crypto.SecretKey;
    import java.nio.charset.StandardCharsets;
    import java.util.List;

    @Slf4j
    @Component
    public class JwtValidationFilter implements WebFilter {

        private static final List<String> WHITE_LIST = List.of(
                "/api/auth/login",
                "/api/auth/register"
        );

        private final SecretKey secretKey;

        public JwtValidationFilter(@Value("${jwt.secret}") String secret){

            this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        }

        @Override
        public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {

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

            if (!isTokenValid(token, path)) {
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
            return WHITE_LIST.stream().anyMatch(path::startsWith);
        }

        private String extractToken(String authHeader) {
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return null;
            }
            return authHeader.substring(7);
        }

        private boolean isTokenValid(String token, String path) {
            try {
                Jwts.parserBuilder()
                        .setSigningKey(secretKey)
                        .build()
                        .parseClaimsJws(token);
                return true;
            } catch (Exception e) {
                log.warn("JWT validation failed for {}: {}", path, e.getMessage());
                return false;
            }
        }
    }
