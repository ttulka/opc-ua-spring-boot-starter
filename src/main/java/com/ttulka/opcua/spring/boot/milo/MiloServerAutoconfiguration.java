package com.ttulka.opcua.spring.boot.milo;

import com.ttulka.opcua.spring.boot.OpcUaServerProperties;
import lombok.RequiredArgsConstructor;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.eclipse.milo.opcua.sdk.server.OpcUaServer;
import org.eclipse.milo.opcua.sdk.server.api.config.OpcUaServerConfig;
import org.eclipse.milo.opcua.sdk.server.api.config.OpcUaServerConfigBuilder;
import org.eclipse.milo.opcua.sdk.server.identity.*;
import org.eclipse.milo.opcua.sdk.server.util.HostnameUtil;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.UaRuntimeException;
import org.eclipse.milo.opcua.stack.core.security.DefaultCertificateManager;
import org.eclipse.milo.opcua.stack.core.security.DefaultTrustListManager;
import org.eclipse.milo.opcua.stack.core.security.SecurityPolicy;
import org.eclipse.milo.opcua.stack.core.security.TrustListManager;
import org.eclipse.milo.opcua.stack.core.transport.TransportProfile;
import org.eclipse.milo.opcua.stack.core.types.builtin.LocalizedText;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.eclipse.milo.opcua.stack.core.types.structured.BuildInfo;
import org.eclipse.milo.opcua.stack.core.types.structured.UserTokenPolicy;
import org.eclipse.milo.opcua.stack.core.util.CertificateUtil;
import org.eclipse.milo.opcua.stack.core.util.NonceUtil;
import org.eclipse.milo.opcua.stack.server.EndpointConfiguration;
import org.eclipse.milo.opcua.stack.server.security.DefaultServerCertificateValidator;
import org.eclipse.milo.opcua.stack.server.security.ServerCertificateValidator;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static org.eclipse.milo.opcua.sdk.server.api.config.OpcUaServerConfig.*;

@Configuration
@ConditionalOnClass(OpcUaServer.class)
@RequiredArgsConstructor
public class MiloServerAutoconfiguration {

    private final OpcUaServerProperties properties;

    @Bean
    MiloServerStarter miloServerStarter(OpcUaServer opcUaServer) {
        return new MiloServerStarter(opcUaServer);
    }

    @Bean
    KeyStoreLoader keyStoreLoader() throws Exception {
        return new KeyStoreLoader(properties);
    }

    @Bean
    @ConditionalOnMissingBean
    TrustListManager trustListManager() throws IOException {
        Path path = Paths.get(properties.getTrustListManager().getPath());
        Files.createDirectories(path);
        return new DefaultTrustListManager(path.toFile());
    }

    @Bean
    @ConditionalOnMissingBean
    ServerCertificateValidator serverCertificateValidator(TrustListManager trustListManager) {
        return new DefaultServerCertificateValidator(trustListManager);
    }

    @Bean
    @ConditionalOnMissingBean
    AnonymousIdentityValidator anonymousIdentityValidator() {
        return new AnonymousIdentityValidator();
    }

    @Bean
    @ConditionalOnMissingBean
    UsernameIdentityValidator usernameIdentityValidator() {
        return new UsernameIdentityValidator(true, authChallenge -> true);
    }

    @Bean
    @ConditionalOnMissingBean
    X509IdentityValidator x509IdentityValidator() {
        return new X509IdentityValidator(x509Certificate -> true);
    }

    @Bean
    @ConditionalOnMissingBean
    OpcUaServer opcUaServer(
            TrustListManager trustListManager,
            KeyStoreLoader keyStoreLoader,
            ServerCertificateValidator serverCertificateValidator,
            List<IdentityValidator<?>> identityValidators) throws NoSuchAlgorithmException {
        X509Certificate serverCertificate = keyStoreLoader.getServerCertificate();

        String applicationUri = CertificateUtil
                .getSanUri(serverCertificate)
                .orElseThrow(() -> new UaRuntimeException(StatusCodes.Bad_ConfigurationError, "certificate is missing the application URI"));

        OpcUaServerConfigBuilder builder = OpcUaServerConfig.builder()
                .setApplicationUri(applicationUri)
                .setProductUri(properties.getProductUri())
                .setApplicationName(LocalizedText.english(properties.getApplicationName()))
                .setEndpoints(createEndpointConfigurations(serverCertificate))
                .setCertificateManager(new DefaultCertificateManager(keyStoreLoader.getServerKeyPair(), keyStoreLoader.getServerCertificateChain()))
                .setTrustListManager(trustListManager)
                .setCertificateValidator(serverCertificateValidator)
                .setBuildInfo(new BuildInfo(
                        properties.getBuildInfo().getProductUri(),
                        properties.getBuildInfo().getManufacturerName(),
                        properties.getBuildInfo().getProductName(),
                        properties.getBuildInfo().getSoftwareVersion(),
                        properties.getBuildInfo().getBuildNumber(),
                        properties.getBuildInfo().getBuildDate()));

        if (!identityValidators.isEmpty()) {
            builder.setIdentityValidator(identityValidators.size() > 1
                    ? new CompositeValidator(identityValidators)
                    : identityValidators.get(0));
        }

        if (properties.getHttps().isEnabled()) {
            X509Certificate httpsCertificate = keyStoreLoader.getHttpsCertificate();
            KeyPair httpsKeyPair = keyStoreLoader.getHttpsKeyPair();
            builder.setHttpsKeyPair(httpsKeyPair)
                    .setHttpsCertificateChain(new X509Certificate[]{httpsCertificate});
        }

        return new OpcUaServer(builder.build());
    }

    private Set<EndpointConfiguration> createEndpointConfigurations(X509Certificate certificate) {
        Set<EndpointConfiguration> endpointConfigurations = new LinkedHashSet<>();

        Set<String> hostnames = new LinkedHashSet<>();
        hostnames.add(HostnameUtil.getHostname());
        hostnames.addAll(HostnameUtil.getHostnames("0.0.0.0"));

        for (String hostname : hostnames) {
            EndpointConfiguration.Builder builder = EndpointConfiguration.newBuilder()
                    .setBindAddress("0.0.0.0")
                    .setHostname(hostname)
                    .setPath(properties.getPath())
                    .setCertificate(certificate)
                    .addTokenPolicies(from(properties.getAuthentication().getTokenPolicies()));

            // OPC UA TCP is mandatory
            endpointConfigurations.add(buildTcpEndpoint(builder.copy()
                    .setSecurityPolicy(from(properties.getSecurity().getPolicy()))
                    .setSecurityMode(fromTcp(properties.getSecurity().getMode()))));

            // It's required to provide a discovery-specific endpoint with no security.
            EndpointConfiguration.Builder discoveryBuilder = builder.copy()
                    .setPath(properties.getDiscoveryPath())
                    .setSecurityPolicy(SecurityPolicy.None)
                    .setSecurityMode(MessageSecurityMode.None);
            endpointConfigurations.add(buildTcpEndpoint(discoveryBuilder));

            if (properties.getHttps().isEnabled()) {
                endpointConfigurations.add(buildHttpsEndpoint(builder.copy()
                        .setSecurityPolicy(from(properties.getSecurity().getPolicy()))
                        .setSecurityMode(fromHttps(properties.getSecurity().getMode()))));

                endpointConfigurations.add(buildHttpsEndpoint(discoveryBuilder));
            }
        }

        return endpointConfigurations;
    }

    private EndpointConfiguration buildTcpEndpoint(EndpointConfiguration.Builder base) {
        return base.copy()
                .setTransportProfile(fromTcp(properties.getTcp().getEncoding()))
                .setBindPort(properties.getTcp().getPort())
                .build();
    }

    private EndpointConfiguration buildHttpsEndpoint(EndpointConfiguration.Builder base) {
        return base.copy()
                .setTransportProfile(fromHttps(properties.getHttps().getEncoding()))
                .setBindPort(properties.getHttps().getPort())
                .build();
    }

    private UserTokenPolicy[] from(List<OpcUaServerProperties.TokenPolicy> tokenPolicies) {
        return tokenPolicies.stream()
                .map(tp -> {
                    switch (tp) {
                        case anonymous:
                            return USER_TOKEN_POLICY_ANONYMOUS;
                        case username:
                            return USER_TOKEN_POLICY_USERNAME;
                        case x509:
                            return USER_TOKEN_POLICY_X509;
                        default:
                            throw new UaRuntimeException(StatusCodes.Bad_ConfigurationError, "Unknown Token Policy: " + tp);
                    }
                }).toArray(UserTokenPolicy[]::new);
    }

    private TransportProfile fromTcp(OpcUaServerProperties.Encoding encoding) {
        switch (encoding) {
            case binary:
                return TransportProfile.TCP_UASC_UABINARY;
            default:
                throw new UaRuntimeException(StatusCodes.Bad_ConfigurationError, "Unsupported encoding for OPC UA TCP: " + encoding);
        }
    }

    private TransportProfile fromHttps(OpcUaServerProperties.Encoding encoding) {
        switch (encoding) {
            case binary:
                return TransportProfile.HTTPS_UABINARY;
            case xml:
                return TransportProfile.HTTPS_UAXML;
            case json:
                return TransportProfile.HTTPS_UAJSON;
            default:
                throw new UaRuntimeException(StatusCodes.Bad_ConfigurationError, "Unsupported encoding for OPC UA HTTPS: " + encoding);
        }
    }

    private SecurityPolicy from(OpcUaServerProperties.SecurityPolicy securityPolicy) {
        switch (securityPolicy) {
            case None:
                return SecurityPolicy.None;
            case Basic128Rsa15:
                return SecurityPolicy.Basic128Rsa15;
            case Basic256Sha256:
                return SecurityPolicy.Basic256Sha256;
            default:
                throw new UaRuntimeException(StatusCodes.Bad_ConfigurationError, "Unsupported security policy: " + securityPolicy);
        }
    }

    private MessageSecurityMode fromTcp(OpcUaServerProperties.SecurityMode securityMode) {
        switch (securityMode) {
            case None:
                return MessageSecurityMode.None;
            case Sign:
                return MessageSecurityMode.Sign;
            case SignAndEncrypt:
                return MessageSecurityMode.SignAndEncrypt;
            default:
                throw new UaRuntimeException(StatusCodes.Bad_ConfigurationError, "Unsupported message security mode for OPC UA TCP: " + securityMode);
        }
    }

    private MessageSecurityMode fromHttps(OpcUaServerProperties.SecurityMode securityMode) {
        switch (securityMode) {
            case None:
                return MessageSecurityMode.None;
            case Sign:
            case SignAndEncrypt:    // SignAndEncrypt not allowed for HTTPS
                return MessageSecurityMode.Sign;
            default:
                throw new UaRuntimeException(StatusCodes.Bad_ConfigurationError, "Unsupported message security mode for OPC UA HTTPS: " + securityMode);
        }
    }

    static {
        // Required for SecurityPolicy.Aes256_Sha256_RsaPss
        Security.addProvider(new BouncyCastleProvider());
        try {
            NonceUtil.blockUntilSecureRandomSeeded(10, TimeUnit.SECONDS);
        } catch (ExecutionException | InterruptedException | TimeoutException e) {
            throw new UaRuntimeException(StatusCodes.Bad_ConfigurationError, "Cannot initialize secure random seed.");
        }
    }
}
