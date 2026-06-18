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

import org.fireflyframework.security.api.domain.SecurityPrincipal;
import org.fireflyframework.security.core.context.PrincipalFactory;
import org.fireflyframework.security.webflux.authentication.FireflyAuthenticationToken;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import reactor.core.publisher.Mono;

/**
 * Converts a signature-validated {@link Jwt} into a {@link FireflyAuthenticationToken} whose
 * principal is a {@link SecurityPrincipal} with normalized authorities/scopes. This replaces
 * Spring's default {@code JwtAuthenticationToken} so application code gets the rich principal.
 */
public class JwtToFireflyPrincipalConverter implements Converter<Jwt, Mono<AbstractAuthenticationToken>> {

    private final PrincipalFactory principalFactory;

    public JwtToFireflyPrincipalConverter(PrincipalFactory principalFactory) {
        this.principalFactory = principalFactory;
    }

    @Override
    public Mono<AbstractAuthenticationToken> convert(Jwt jwt) {
        String issuer = jwt.getIssuer() == null ? null : jwt.getIssuer().toString();
        SecurityPrincipal principal = principalFactory.fromClaims(jwt.getSubject(), issuer, jwt.getClaims());
        return Mono.just(new FireflyAuthenticationToken(principal));
    }
}
