/*
 * Copyright (c) 2021 the Eclipse Milo Authors
 *
 * This program and the accompanying materials are made
 * available under the terms of the Eclipse Public License 2.0
 * which is available at https://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 */

package com.ttulka.opcua.spring.boot.milo;

import com.google.common.collect.Sets;
import com.ttulka.opcua.spring.boot.OpcUaServerProperties;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.eclipse.milo.opcua.sdk.server.util.HostnameUtil;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.UaRuntimeException;
import org.eclipse.milo.opcua.stack.core.util.SelfSignedCertificateBuilder;
import org.eclipse.milo.opcua.stack.core.util.SelfSignedCertificateGenerator;
import org.eclipse.milo.opcua.stack.core.util.SelfSignedHttpsCertificateBuilder;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

@Getter
@Slf4j
class KeyStoreLoader {

    private static final Pattern IP_ADDR_PATTERN = Pattern.compile(
            "^(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.){3}([01]?\\d\\d?|2[0-4]\\d|25[0-5])$");

    private final X509Certificate[] serverCertificateChain;
    private final X509Certificate serverCertificate;
    private final KeyPair serverKeyPair;

    private final X509Certificate httpsCertificate;
    private final KeyPair httpsKeyPair;

    public KeyStoreLoader(OpcUaServerProperties properties) throws Exception {
        Path path = Paths.get(properties.getKeyStore().getPath());
        char[] pass = properties.getKeyStore().getPassword().toCharArray();
        String serverAlias = properties.getKeyStore().getServerAlias();
        String httpsAlias = properties.getKeyStore().getHttpsAlias();

        log.info("Loading Key Store at {}", path);

        KeyStore keyStore = KeyStore.getInstance(properties.getKeyStore().getType());

        if (!Files.exists(path)) {
            if (!properties.getKeyStore().isGenerate()) {
                throw new UaRuntimeException(StatusCodes.Bad_ConfigurationError, "Key Store does not exist!");
            }
            Files.createDirectories(path.getParent());

            keyStore.load(null, pass);

            KeyPair keyPair = SelfSignedCertificateGenerator.generateRsaKeyPair(2048);

            String applicationUri = properties.getProductUri() + ":" + UUID.randomUUID();

            SelfSignedCertificateBuilder builder = new SelfSignedCertificateBuilder(keyPair)
                    .setCommonName(properties.getApplicationName())
                    .setApplicationUri(applicationUri);

            // Get as many hostnames and IP addresses as we can listed in the certificate.
            Set<String> hostnames = Sets.union(
                    Sets.newHashSet(HostnameUtil.getHostname()),
                    HostnameUtil.getHostnames("0.0.0.0", false)
            );

            for (String hostname : hostnames) {
                if (IP_ADDR_PATTERN.matcher(hostname).matches()) {
                    builder.addIpAddress(hostname);
                } else {
                    builder.addDnsName(hostname);
                }
            }

            X509Certificate certificate = builder.build();

            keyStore.setKeyEntry(serverAlias, keyPair.getPrivate(), pass, new X509Certificate[]{certificate});

            // HTTPS certificate
            if (properties.getHttps().isEnabled()) {
                KeyPair httpsKeyPair = SelfSignedCertificateGenerator.generateRsaKeyPair(2048);

                SelfSignedHttpsCertificateBuilder httpsCertificateBuilder = new SelfSignedHttpsCertificateBuilder(httpsKeyPair);
                httpsCertificateBuilder.setCommonName(HostnameUtil.getHostname());
                HostnameUtil.getHostnames("0.0.0.0").forEach(httpsCertificateBuilder::addDnsName);
                X509Certificate httpsCertificate = httpsCertificateBuilder.build();

                keyStore.setKeyEntry(httpsAlias, httpsKeyPair.getPrivate(), pass, new X509Certificate[]{httpsCertificate});
            }

            keyStore.store(Files.newOutputStream(path), pass);
        } else {
            keyStore.load(Files.newInputStream(path), pass);
        }

        Key serverPrivateKey = keyStore.getKey(serverAlias, pass);

        if (!(serverPrivateKey instanceof PrivateKey)) {
            throw new RuntimeException("Key is not of type PrivateKey");
        }

        serverCertificate = (X509Certificate) keyStore.getCertificate(serverAlias);

        serverCertificateChain = Arrays.stream(keyStore.getCertificateChain(serverAlias))
            .map(X509Certificate.class::cast)
            .toArray(X509Certificate[]::new);

        PublicKey serverPublicKey = serverCertificate.getPublicKey();
        serverKeyPair = new KeyPair(serverPublicKey, (PrivateKey) serverPrivateKey);

        if (properties.getHttps().isEnabled()) {
            Key httpPrivateKey = keyStore.getKey(httpsAlias, pass);
            if (!(httpPrivateKey instanceof PrivateKey)) {
                throw new RuntimeException("Key is not of type PrivateKey");
            }
            httpsCertificate = (X509Certificate) keyStore.getCertificate(httpsAlias);
            PublicKey httpPublicKey = httpsCertificate.getPublicKey();
            httpsKeyPair = new KeyPair(httpPublicKey, (PrivateKey) httpPrivateKey);

        } else {
            httpsCertificate = null;
            httpsKeyPair = null;
        }
    }
}
