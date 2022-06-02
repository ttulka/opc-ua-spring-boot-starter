package com.ttulka.opcua.spring.boot;

import com.ttulka.opcua.spring.boot.auth.UsernameAuthenticator;
import com.ttulka.opcua.spring.boot.auth.X509Authenticator;
import com.ttulka.opcua.spring.boot.milo.MiloServerAutoconfiguration;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

@AutoConfiguration
@ConditionalOnProperty(value = "spring.opcua.server.enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(OpcUaServerProperties.class)
@Import({OpcUaAutoconfiguration.DefaultAuthenticatorsConfig.class, MiloServerAutoconfiguration.class})
public class OpcUaAutoconfiguration {

    @Configuration
    static class DefaultAuthenticatorsConfig {

        @Bean
        @ConditionalOnMissingBean
        UsernameAuthenticator usernameAuthenticatorDummy() {
            return credentials -> false;
        }

        @Bean
        @ConditionalOnMissingBean
        X509Authenticator x509AuthenticatorDummy() {
            return x509Certificate -> false;
        }
    }
}
