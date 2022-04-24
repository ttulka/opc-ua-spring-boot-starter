package com.ttulka.opcua.spring.boot;

import lombok.Data;
import org.eclipse.milo.opcua.stack.core.types.builtin.DateTime;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

@ConfigurationProperties(prefix = "spring.opcua.server")
@Data
public class OpcUaServerProperties {

    public enum Encoding { binary, xml, json }
    public enum TokenPolicy { anonymous, username, x509 }
    public enum SecurityPolicy { None, Basic128Rsa15, Basic256Sha256 }
    public enum SecurityMode { None, Sign, SignAndEncrypt }

    private String productUri;
    private String applicationName;

    private String path = "/";
    private String discoveryPath = "/discovery";

    private TrustListManagerProperties trustListManager = new TrustListManagerProperties();
    private KeyStoreProperties keyStore = new KeyStoreProperties();

    private TcpProperties tcp = new TcpProperties();
    private HttpsProperties https = new HttpsProperties();

    private SecurityProperties security = new SecurityProperties();

    private AuthenticationProperties authentication = new AuthenticationProperties();

    private BuildInfoProperties buildInfo = new BuildInfoProperties();

    @Data
    public static class TcpProperties {

        private Encoding encoding = Encoding.binary;
        private int port = 4840;
    }

    @Data
    public static class HttpsProperties {

        private boolean enabled = false;
        private Encoding encoding = Encoding.binary;
        private int port = 8443;
    }

    @Data
    public static class SecurityProperties {

        private SecurityPolicy policy = SecurityPolicy.None;
        private SecurityMode mode = SecurityMode.None;
    }

    @Data
    public static class AuthenticationProperties {

        private List<TokenPolicy> tokenPolicies = new ArrayList<>();
    }

    @Data
    public static class TrustListManagerProperties {

        private String path = "security/pki";
    }

    @Data
    public static class KeyStoreProperties {

        private String path = "security/ks.p12";
        private String type = "PKCS12";
        private String serverAlias = "server-opcua";
        private String httpsAlias = "server-https";
        private String password = "pass123";
        private boolean generate = true;
    }

    @Data
    public static class BuildInfoProperties {

        private String productUri;
        private String productName;
        private String manufacturerName;
        private String softwareVersion;
        private String buildNumber;
        private DateTime buildDate = DateTime.now();
    }
}
