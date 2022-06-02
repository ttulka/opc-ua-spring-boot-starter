# Spring Boot Starter for OPC UA Server

Uses [Eclipse Milo](https://github.com/eclipse/milo) as the default implementation.

## Getting Started

### Maven
```xml
<dependency>
    <groupId>com.ttulka.opcua</groupId>
    <artifactId>opc-ua-spring-boot-starter</artifactId>
    <version>0.0.2</version>
</dependency>
```

### Gradle
```groovy
implementation "com.ttulka.opcua:opc-ua-spring-boot-starter:0.0.1"
```

See [examples](https://github.com/ttulka/opc-ua-spring-boot-starter/blob/main/examples) of the usage.

## Properties

| Property                                            | Default                | Description                              | Type                                             |
|-----------------------------------------------------|------------------------|------------------------------------------|--------------------------------------------------|
| `spring.opcua.server.enabled`                       | `true`                 | OPC UA Server is enabled                 | boolean                                          |
| `spring.opcua.server.autostart.enabled`             | `true`                 | Server starts automatically              | boolean                                          |
| `spring.opcua.server.product-uri`                   | `urn:spring:opcua`     | Product URI                              | string                                           |
| `spring.opcua.server.application-name`              | `Spring OPC UA Server` | Server Application name                  | string                                           |
| `spring.opcua.server.path`                          | `/`                    | Server Application path                  | string                                           |
| `spring.opcua.server.discovery-path`                | `/discovery`           | Server Application path                  | string                                           |
| `spring.opcua.server.tcp.encoding`                  | `binary`               | Encoding for OPC UA TCP protocol         | enum (`binary`)                                  |
| `spring.opcua.server.tcp.port`                      | `4840`                 | TCP port                                 | int                                              |
| `spring.opcua.server.https.enabled`                 | `false`                | OPC UA HTTPS protocol enabled            | boolean                                          |
| `spring.opcua.server.https.encoding`                | `binary`               | Encoding for OPC UA HTTPS protocol       | enum (`binary`, `xml`, `json`)                   |
| `spring.opcua.server.https.port`                    | `8443`                 | HTTPS port                               | int                                              |
| `spring.opcua.server.trust-list-manager.path`       | `security/pki`         | Path to the Trust List Manager directory | path                                             |
| `spring.opcua.server.key-store.path`                | `security/ks.p12`      | Path to the Key Store file               | path                                             |
| `spring.opcua.server.key-store.password`            | `changeit`             | Password to the Key Store file           | string                                           |
| `spring.opcua.server.key-store.type`                | `PKCS12`               | Key Store type                           | string                                           |
| `spring.opcua.server.key-store.server-alias`        | `server-opcua`         | Server certificate alias                 | string                                           |
| `spring.opcua.server.key-store.https-alias`         | `server-https`         | HTTPS server certificate alias           | string                                           |
| `spring.opcua.server.key-store.generate`            | `true`                 | Generate when not found                  | boolean                                          |
| `spring.opcua.server.security.policy`               | `None`                 | Security policy                          | enum (`None`, `Basic128Rsa15`, `Basic256Sha256`) |
| `spring.opcua.server.security.mode`                 | `None`                 | Message security mode                    | enum (`None`, `Sign`, `SignAndEncrypt`)          |
| `spring.opcua.server.authentication.token-policies` | `anonymous`            | List of token policies                   | enum (`anonymous`, `username`, `x509`)           |
| `spring.opcua.server.build-info.product-uri`        |                        |                                          | string                                           |
| `spring.opcua.server.build-info.product-name`       |                        |                                          | string                                           |
| `spring.opcua.server.build-info.manufacturer-name`  |                        |                                          | string                                           |
| `spring.opcua.server.build-info.software-version`   |                        |                                          | string                                           |
| `spring.opcua.server.build-info.build-number`       |                        |                                          | string                                           |
| `spring.opcua.server.build-info.build-date`         | `DateTime.now()`       |                                          | DateTime                                         |

## Authentication

In order to authenticate a user you have to provide one or more identity validators in your Spring configuration:

```java
import org.springframework.context.annotation.Configuration;

@Configuration
class MyOpcUaServerConfig {
    
    @Bean   // for token policy "username"
    UsernameAuthenticator usernameAuthenticator() {
        return auth -> "user".equals(auth.getUsername()) && "pass123".equals(auth.getPassword());
    }

    @Bean   // for token policy "x509"
    X509Authenticator x509Authenticator() {
        return x509Certificate -> /** validate the certificate */;
    }
}
```

## Namespaces

### Eclipse Milo

Start namespaces simply by registering Spring beans of type `org.eclipse.milo.opcua.sdk.server.api.ManagedNamespaceWithLifecycle`:

```java
class ExampleNamespace extends ManagedNamespaceWithLifecycle {
    // ...
}

@Bean 
ExampleNamespace exampleNamespace(OpcUaServer server) {
    return new ExampleNamespace(server);
}
```

## Not Implemented Yet

- WebSockets
- Issued Token (JWT)
