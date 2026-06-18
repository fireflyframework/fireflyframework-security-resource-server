/*
 * Copyright 2024-2026 Firefly Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.fireflyframework.security.rs;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.fireflyframework.security.api.domain.Decision;
import org.fireflyframework.security.api.domain.SecurityPrincipal;
import org.fireflyframework.security.api.domain.SigningKey;
import org.fireflyframework.security.core.key.InMemoryKeyManagementAdapter;
import org.fireflyframework.security.core.policy.PolicyRule;
import org.fireflyframework.security.spi.KeyManagementPort;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.security.interfaces.RSAPrivateKey;
import java.time.Instant;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end proof of the secure-by-default resource server: a valid signed JWT is accepted, while
 * missing/forged/expired tokens are rejected, default-deny is enforced, ABAC policy denials map to
 * 403, and hardened security headers are present.
 */
@SpringBootTest(
        classes = ResourceServerIntegrationTest.TestApp.class,
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "firefly.security.resource-server.permit-matchers=/public/**",
                "spring.main.banner-mode=off"
        })
class ResourceServerIntegrationTest {

    @LocalServerPort
    int port;

    @Autowired
    KeyManagementPort keyManagementPort;

    private WebTestClient client;

    @BeforeEach
    void setUp() {
        client = WebTestClient.bindToServer().baseUrl("http://localhost:" + port).build();
    }

    private String signWith(SigningKey key, JWTClaimsSet claims) throws Exception {
        JWSSigner signer = new RSASSASigner((RSAPrivateKey) key.privateKey());
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.kid()).build(), claims);
        jwt.sign(signer);
        return jwt.serialize();
    }

    private JWTClaimsSet.Builder validClaims() {
        Instant now = Instant.now();
        return new JWTClaimsSet.Builder()
                .subject("alice")
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(300)))
                .claim("scope", "read write")
                .claim("roles", List.of("teller"));
    }

    @Test
    void publicRouteIsAccessibleWithoutToken() {
        client.get().uri("/public/ping").exchange().expectStatus().isOk().expectBody(String.class).isEqualTo("pong");
    }

    @Test
    void protectedRouteWithoutTokenIsUnauthorized() {
        client.get().uri("/api/me").exchange().expectStatus().isUnauthorized();
    }

    @Test
    void protectedRouteWithValidTokenIsAuthorized() throws Exception {
        String token = signWith(keyManagementPort.activeSigningKey().block(), validClaims().build());
        client.get().uri("/api/me")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class).isEqualTo("alice");
    }

    @Test
    void expiredTokenIsUnauthorized() throws Exception {
        Instant past = Instant.now().minusSeconds(3600);
        JWTClaimsSet expired = new JWTClaimsSet.Builder()
                .subject("alice")
                .issueTime(Date.from(past.minusSeconds(60)))
                .expirationTime(Date.from(past))
                .build();
        String token = signWith(keyManagementPort.activeSigningKey().block(), expired);
        client.get().uri("/api/me").header("Authorization", "Bearer " + token)
                .exchange().expectStatus().isUnauthorized();
    }

    @Test
    void forgedTokenSignedByUnknownKeyIsUnauthorized() throws Exception {
        SigningKey foreignKey = new InMemoryKeyManagementAdapter().activeSigningKey().block();
        String token = signWith(foreignKey, validClaims().build());
        client.get().uri("/api/me").header("Authorization", "Bearer " + token)
                .exchange().expectStatus().isUnauthorized();
    }

    @Test
    void policyDeniedRouteIsForbiddenEvenWithValidToken() throws Exception {
        String token = signWith(keyManagementPort.activeSigningKey().block(), validClaims().build());
        client.get().uri("/api/denied").header("Authorization", "Bearer " + token)
                .exchange().expectStatus().isForbidden();
    }

    @Test
    void hardenedSecurityHeadersArePresent() {
        client.get().uri("/public/ping").exchange()
                .expectStatus().isOk()
                .expectHeader().valueEquals("X-Frame-Options", "DENY")
                .expectHeader().valueEquals("Referrer-Policy", "no-referrer")
                .expectHeader().exists("Content-Security-Policy");
    }

    @SpringBootApplication
    static class TestApp {

        @Bean
        PolicyRule denyDeniedPath() {
            return (principal, action, resource, context) ->
                    "/api/denied".equals(resource)
                            ? Mono.just(Decision.deny("blocked by policy"))
                            : Mono.just(Decision.permit());
        }

        @RestController
        static class TestController {

            @GetMapping("/public/ping")
            Mono<String> ping() {
                return Mono.just("pong");
            }

            @GetMapping("/api/me")
            Mono<String> me(@AuthenticationPrincipal SecurityPrincipal principal) {
                return Mono.just(principal.subject());
            }

            @GetMapping("/api/denied")
            Mono<String> denied() {
                return Mono.just("secret");
            }
        }
    }
}
