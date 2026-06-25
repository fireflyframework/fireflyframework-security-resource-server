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

import org.fireflyframework.security.spi.KeyManagementPort;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Verifies decoder path selection. The in-memory (KeyManagementPort) path — the unchanged default — is
 * covered end-to-end by {@link ResourceServerIntegrationTest}; this asserts that configuring
 * {@code jwk-set-uri} switches to the external-JWKS decoder without touching the in-memory key.
 */
class ResourceServerDecoderSelectionTest {

    @Test
    void usesRemoteJwksAndSkipsKeyManagementPortWhenJwkSetUriConfigured() {
        KeyManagementPort keyManagementPort = mock(KeyManagementPort.class);
        ResourceServerProperties properties = new ResourceServerProperties();
        properties.setJwkSetUri("https://idp.test/realms/r/protocol/openid-connect/certs");

        NimbusReactiveJwtDecoder decoder = ResourceServerAutoConfiguration.buildDecoder(keyManagementPort, properties);

        assertThat(decoder).isNotNull();
        // The external-JWKS path must never consult the in-memory signing key.
        verifyNoInteractions(keyManagementPort);
    }
}
