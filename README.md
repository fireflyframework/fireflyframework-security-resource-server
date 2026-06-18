# Firefly Framework - Security Resource Server

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Java](https://img.shields.io/badge/Java-21%2B-orange.svg)](https://openjdk.org)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.x-green.svg)](https://spring.io/projects/spring-boot)
[![Spring Security](https://img.shields.io/badge/Spring%20Security-6.x-brightgreen.svg)](https://spring.io/projects/spring-security)

> Secure-by-default reactive OAuth2 resource server for Spring WebFlux. A single auto-configuration turns any Firefly web application into a JWT-validating resource server with a default-deny filter chain and hardened response headers — no security code required, and nothing to silently leak.

---

## Table of Contents

- [Overview](#overview)
- [Where it sits in the platform](#where-it-sits-in-the-platform)
- [What it provides](#what-it-provides)
- [Key types](#key-types)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Request flow](#request-flow)
- [Testing](#testing)
- [License](#license)

## Overview

This module is the **resource-server binding** of the Firefly hexagonal security platform. It wires Spring Security 6's reactive OAuth2 resource server onto the framework's ports so that every inbound request must present a **signature-validated** bearer token before it reaches a controller or handler.

It is deliberately product-agnostic. There is no `X-Party-Id` trusted-header shortcut, no business-role enum, and no fail-open switch. Identity comes only from a JWT whose signature, expiry, and (optionally) issuer and audience are verified in-process; authorization defaults to deny. This closes the historical gaps the platform refactor was designed to eliminate — unverified local token parsing, gateway-trusted headers, and Spring Boot's silently-leaked HTTP-Basic default chain.

The whole module is one `@AutoConfiguration` class (`ResourceServerAutoConfiguration`) plus a properties class and a JWT-to-principal converter. Every bean it contributes is `@ConditionalOnMissingBean`, so an application can override any single piece — the decoder, the authority mapping, the policy engine, the filter chain — without forking the module.

## Where it sits in the platform

The security platform is layered hexagonally; dependencies point inward, and providers attach as outboard adapters:

```
security-api  →  security-spi  →  security-core  →  security-webflux  →  security-resource-server  →  adapters
 (ports +         (driven           (neutral          (reactive             (this module:               (Vault, KMS,
  domain)          ports)            engine)            Spring Security        Spring Security 6           OPA, Keycloak,
                                                        bindings)              resource-server wiring)     internal-db, …)
```

- **`security-api`** defines the domain (`SecurityPrincipal`, `Decision`, `SigningKey`) and driving ports.
- **`security-spi`** defines the driven ports this module consumes: `KeyManagementPort`, `AuthorityMappingPort`, `PolicyDecisionPort`, `AuditEventPort`, `SecurityContextPort`.
- **`security-core`** supplies the framework-neutral default implementations (`InMemoryKeyManagementAdapter`, `ConfigurableAuthorityMapper`, `PrincipalFactory`, `EmbeddedPolicyDecisionAdapter`, `LoggingAuditEventAdapter`).
- **`security-webflux`** supplies the reactive Spring Security glue (`FireflyAuthenticationToken`, `PolicyAuthorizationManager`, `ReactorSecurityContextAdapter`).
- **This module** binds all of the above into a concrete `SecurityWebFilterChain` and is delivered to applications transitively via the application starter.
- **Adapters** (key management, policy, idp providers) replace the in-process defaults by simply contributing their own port beans.

This module depends only on `security-webflux` (which transitively brings `security-core`, `-spi`, `-api`) and the Spring Security OAuth2 resource-server / JOSE artifacts. It imports no vendor SDK.

## What it provides

`ResourceServerAutoConfiguration` contributes, each gated by `@ConditionalOnMissingBean`:

- **A verifying JWT decoder.** `NimbusReactiveJwtDecoder.withPublicKey(...)` built from the active RSA `SigningKey` resolved through `KeyManagementPort.activeSigningKey()`, pinned to `RS256`. If no RSA key resolves, the context fails to start (fail-closed) rather than booting an unprotected server.
- **A validator chain.** A `DelegatingOAuth2TokenValidator<Jwt>` always enforcing `JwtTimestampValidator` (exp/nbf with skew), plus `JwtIssuerValidator` when `issuer` is configured and a custom audience validator when `audiences` is non-empty.
- **Claim-to-authority mapping.** An `AuthorityMappingPort` (default `ConfigurableAuthorityMapper`) driven by configurable role/scope claim paths and authority prefix, normalizing provider-specific claims (Keycloak/Cognito/Entra) into a uniform authority/scope set.
- **A rich principal.** `JwtToFireflyPrincipalConverter` replaces Spring's default `JwtAuthenticationToken` with a `FireflyAuthenticationToken` whose principal is a `SecurityPrincipal` (built by `PrincipalFactory.fromClaims(...)`), so `@AuthenticationPrincipal SecurityPrincipal` works out of the box.
- **A default-deny filter chain.** `fireflySecurityWebFilterChain` disables CSRF, HTTP-Basic, form-login, and logout; permits only the explicitly configured `permitMatchers`; and routes `anyExchange()` through a `PolicyAuthorizationManager` backed by `PolicyDecisionPort`. Unconfigured routes are denied.
- **Hardened response headers** on every response: `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, a strict `Content-Security-Policy` (`default-src 'none'; frame-ancestors 'none'`), and HSTS (`includeSubDomains`, 365-day max-age).
- **Framework defaults** for the remaining ports — `EmbeddedPolicyDecisionAdapter` (collecting any `PolicyRule` beans), `LoggingAuditEventAdapter`, and `ReactorSecurityContextAdapter` — all overridable.

## Key types

| Type | Role |
| --- | --- |
| `ResourceServerAutoConfiguration` | `@AutoConfiguration @EnableWebFluxSecurity` entry point; builds the decoder, converter, and `SecurityWebFilterChain`. |
| `ResourceServerProperties` | `@ConfigurationProperties("firefly.security.resource-server")` — permit matchers, issuer, audiences, authority prefix, role/scope claim paths. |
| `JwtToFireflyPrincipalConverter` | `Converter<Jwt, Mono<AbstractAuthenticationToken>>` mapping a validated `Jwt` to a `FireflyAuthenticationToken` carrying a `SecurityPrincipal`. |

Ports consumed (from `security-spi`): `KeyManagementPort`, `AuthorityMappingPort`, `PolicyDecisionPort`, `AuditEventPort`, `SecurityContextPort`. Domain types (from `security-api`): `SecurityPrincipal`, `Decision`, `SigningKey`.

The auto-configuration is registered via `META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`.

## Requirements

- Java 21+
- Spring Boot 3.x, Spring Security 6.x
- A reactive web stack (Spring WebFlux)
- A `KeyManagementPort` that can resolve an active RSA signing key (the bundled `InMemoryKeyManagementAdapter` suffices for dev; production deployments contribute a Vault/AWS-KMS/Azure-Key-Vault adapter)

## Installation

The version is managed by the Firefly parent/BOM, so you can usually omit it. In a Firefly application this module is pulled in transitively by the application starter; depend on it directly only when binding a resource server standalone:

```xml
<dependency>
    <groupId>org.fireflyframework</groupId>
    <artifactId>fireflyframework-security-resource-server</artifactId>
</dependency>
```

If you are not inheriting the Firefly parent, pin the version explicitly:

```xml
<dependency>
    <groupId>org.fireflyframework</groupId>
    <artifactId>fireflyframework-security-resource-server</artifactId>
    <version>26.06.01</version>
</dependency>
```

## Quick Start

With the module on the classpath, the resource server is active with **zero code** — every route is locked down. Mark public routes explicitly and read the validated principal directly:

```yaml
firefly:
  security:
    resource-server:
      permit-matchers:
        - /actuator/health
        - /public/**
      issuer: https://idp.example.com/realms/firefly
      audiences:
        - firefly-api
```

```java
import org.fireflyframework.security.api.domain.SecurityPrincipal;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
class MeController {

    @GetMapping("/api/me")
    Mono<String> me(@AuthenticationPrincipal SecurityPrincipal principal) {
        return Mono.just(principal.subject());
    }
}
```

Add ABAC/ReBAC decisions by contributing one or more `PolicyRule` beans; they are collected by the default `EmbeddedPolicyDecisionAdapter` and consulted on every non-permitted exchange, fail-closed:

```java
@Bean
PolicyRule denyReports() {
    return (principal, action, resource, context) ->
            resource.startsWith("/api/reports") && !principal.scopes().contains("reports.read")
                    ? Mono.just(Decision.deny("reports.read scope required"))
                    : Mono.just(Decision.permit());
}
```

## Configuration

All keys live under `firefly.security.resource-server`:

| Property | Default | Description |
| --- | --- | --- |
| `permit-matchers` | _(empty)_ | Ant-style path patterns served without authentication. The **only** opt-out from default-deny. |
| `issuer` | _(none)_ | Expected `iss`; when set, a `JwtIssuerValidator` is enforced. |
| `audiences` | _(empty)_ | Acceptable `aud` values; when non-empty, an audience validator is enforced. |
| `authority-prefix` | `""` | Prefix applied to mapped authorities (e.g. `ROLE_`). |
| `role-claim-paths` | _(empty)_ | Dot-path claims inspected for roles/groups (defaults cover Keycloak/Cognito/Entra). |
| `scope-claim-paths` | _(empty)_ | Dot-path claims inspected for OAuth2 scopes. |

With no configuration at all, every route requires a validated bearer token and timestamp validation is always on.

## Request flow

```
Bearer token → fireflySecurityWebFilterChain
   → NimbusReactiveJwtDecoder (RS256, key from KeyManagementPort)
   → DelegatingOAuth2TokenValidator (timestamp [+ issuer] [+ audience])
   → JwtToFireflyPrincipalConverter → FireflyAuthenticationToken(SecurityPrincipal)
   → authorizeExchange: permitMatchers → permitAll, else PolicyAuthorizationManager (PolicyDecisionPort, default-deny)
   → controller / handler
```

A missing or malformed token, a failed signature, an expired token, or a wrong issuer/audience yields **401**. A validated token whose policy decision is DENY (or whose route is not permitted) yields **403**. Only a validated token on an allowed route reaches the handler with **200**.

## Testing

The module ships a `@SpringBootTest(webEnvironment = RANDOM_PORT)` integration test, `ResourceServerIntegrationTest`, that boots a real reactive server with the real auto-configuration and exercises the full filter chain over HTTP with `WebTestClient`. It signs JWTs in-test with Nimbus (`RSASSASigner`) using the active `SigningKey` from the wired `KeyManagementPort`, and asserts the secure-by-default behavior end to end:

- **200** — a public route (`/public/**`) is reachable without a token; a protected route returns the `SecurityPrincipal.subject()` for a valid signed JWT.
- **401** — a protected route with no token; an **expired** token; a **forged** token signed by an unknown key (a fresh `InMemoryKeyManagementAdapter` the server doesn't trust).
- **403** — a route a contributed `PolicyRule` denies, even with a valid token (proving default-deny / policy enforcement is independent of authentication).
- **Headers** — `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and `Content-Security-Policy` are present on responses.

These mirror the platform's negative-path verification strategy: expired, forged-signature-rejected, and denied-policy paths are proven, not assumed.

## License

Copyright 2024-2026 Firefly Software Foundation.

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
