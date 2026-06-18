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

import org.fireflyframework.security.api.domain.SigningKey;
import org.fireflyframework.security.core.authority.AuthorityMappingProperties;
import org.fireflyframework.security.core.authority.ConfigurableAuthorityMapper;
import org.fireflyframework.security.core.audit.LoggingAuditEventAdapter;
import org.fireflyframework.security.core.context.PrincipalFactory;
import org.fireflyframework.security.core.key.InMemoryKeyManagementAdapter;
import org.fireflyframework.security.core.policy.EmbeddedPolicyDecisionAdapter;
import org.fireflyframework.security.core.policy.PolicyRule;
import org.fireflyframework.security.spi.AuditEventPort;
import org.fireflyframework.security.spi.AuthorityMappingPort;
import org.fireflyframework.security.spi.KeyManagementPort;
import org.fireflyframework.security.spi.PolicyDecisionPort;
import org.fireflyframework.security.spi.SecurityContextPort;
import org.fireflyframework.security.webflux.authentication.FireflyAuthenticationToken;
import org.fireflyframework.security.webflux.authz.PolicyAuthorizationManager;
import org.fireflyframework.security.webflux.context.ReactorSecurityContextAdapter;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.header.ReferrerPolicyServerHttpHeadersWriter;
import org.springframework.security.web.server.header.XFrameOptionsServerHttpHeadersWriter;
import reactor.core.publisher.Mono;

import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Auto-configures a secure-by-default reactive OAuth2 resource server. Provides the full chain
 * (JWT decoder from {@link KeyManagementPort}, claim-to-authority mapping, a default-deny
 * {@link SecurityWebFilterChain}, hardened headers) and the framework's principal/audit/policy
 * defaults. Every bean is {@link ConditionalOnMissingBean} so applications can override any piece.
 */
@AutoConfiguration
@EnableWebFluxSecurity
@EnableConfigurationProperties(ResourceServerProperties.class)
public class ResourceServerAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public KeyManagementPort fireflyKeyManagementPort() {
        return new InMemoryKeyManagementAdapter();
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthorityMappingPort fireflyAuthorityMappingPort(ResourceServerProperties properties) {
        return new ConfigurableAuthorityMapper(new AuthorityMappingProperties(
                properties.getRoleClaimPaths(), properties.getScopeClaimPaths(), properties.getAuthorityPrefix()));
    }

    @Bean
    @ConditionalOnMissingBean
    public PrincipalFactory fireflyPrincipalFactory(AuthorityMappingPort authorityMappingPort) {
        return new PrincipalFactory(authorityMappingPort);
    }

    @Bean
    @ConditionalOnMissingBean
    public PolicyDecisionPort fireflyPolicyDecisionPort(ObjectProvider<PolicyRule> rules) {
        return new EmbeddedPolicyDecisionAdapter(rules.orderedStream().toList());
    }

    @Bean
    @ConditionalOnMissingBean
    public AuditEventPort fireflyAuditEventPort() {
        return new LoggingAuditEventAdapter();
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityContextPort fireflySecurityContextPort() {
        return new ReactorSecurityContextAdapter();
    }

    @Bean
    @ConditionalOnMissingBean
    public Converter<Jwt, Mono<AbstractAuthenticationToken>> fireflyJwtAuthenticationConverter(PrincipalFactory principalFactory) {
        return new JwtToFireflyPrincipalConverter(principalFactory);
    }

    @Bean
    @ConditionalOnMissingBean
    public ReactiveJwtDecoder fireflyReactiveJwtDecoder(KeyManagementPort keyManagementPort, ResourceServerProperties properties) {
        SigningKey active = keyManagementPort.activeSigningKey().block();
        if (active == null || !(active.publicKey() instanceof RSAPublicKey rsaPublicKey)) {
            throw new IllegalStateException("No RSA signing key available to build the JWT decoder");
        }
        NimbusReactiveJwtDecoder decoder = NimbusReactiveJwtDecoder
                .withPublicKey(rsaPublicKey)
                .signatureAlgorithm(SignatureAlgorithm.RS256)
                .build();

        List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();
        validators.add(new JwtTimestampValidator());
        if (properties.getIssuer() != null && !properties.getIssuer().isBlank()) {
            validators.add(new JwtIssuerValidator(properties.getIssuer()));
        }
        if (!properties.getAudiences().isEmpty()) {
            validators.add(audienceValidator(properties.getAudiences()));
        }
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(validators));
        return decoder;
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityWebFilterChain fireflySecurityWebFilterChain(
            ServerHttpSecurity http,
            ReactiveJwtDecoder jwtDecoder,
            Converter<Jwt, Mono<AbstractAuthenticationToken>> jwtAuthenticationConverter,
            PolicyDecisionPort policyDecisionPort,
            ResourceServerProperties properties) {

        PolicyAuthorizationManager policyManager = new PolicyAuthorizationManager(policyDecisionPort);

        http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .logout(ServerHttpSecurity.LogoutSpec::disable)
                .authorizeExchange(exchanges -> {
                    if (!properties.getPermitMatchers().isEmpty()) {
                        exchanges.pathMatchers(properties.getPermitMatchers().toArray(String[]::new)).permitAll();
                    }
                    exchanges.anyExchange().access(policyManager);
                })
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt
                                .jwtDecoder(jwtDecoder)
                                .jwtAuthenticationConverter(jwtAuthenticationConverter)))
                .headers(headers -> headers
                        .frameOptions(frame -> frame.mode(XFrameOptionsServerHttpHeadersWriter.Mode.DENY))
                        .referrerPolicy(referrer -> referrer.policy(ReferrerPolicyServerHttpHeadersWriter.ReferrerPolicy.NO_REFERRER))
                        .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'none'; frame-ancestors 'none'"))
                        .hsts(hsts -> hsts.includeSubdomains(true).maxAge(Duration.ofDays(365))));

        return http.build();
    }

    private static OAuth2TokenValidator<Jwt> audienceValidator(List<String> audiences) {
        return jwt -> jwt.getAudience() != null && jwt.getAudience().stream().anyMatch(audiences::contains)
                ? OAuth2TokenValidatorResult.success()
                : OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "Required audience is missing", null));
    }

    /** Marker so {@link FireflyAuthenticationToken} stays referenced for documentation/javadoc tooling. */
    static Class<?> principalTokenType() {
        return FireflyAuthenticationToken.class;
    }
}
