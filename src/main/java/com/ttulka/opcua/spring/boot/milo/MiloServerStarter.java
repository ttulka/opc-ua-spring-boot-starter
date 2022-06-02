package com.ttulka.opcua.spring.boot.milo;

import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.eclipse.milo.opcua.sdk.server.OpcUaServer;
import org.eclipse.milo.opcua.sdk.server.api.ManagedNamespaceWithLifecycle;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import java.util.List;
import java.util.concurrent.CompletableFuture;

@RequiredArgsConstructor
@Slf4j
class MiloServerStarter {

    private final OpcUaServer server;
    private final List<ManagedNamespaceWithLifecycle> namespaces;

    private final CompletableFuture<Void> future = new CompletableFuture<>();   // keep server running

    @PostConstruct
    @SneakyThrows
    void startServer() {
        for (ManagedNamespaceWithLifecycle namespace : namespaces) {
            namespace.startup();
            log.info("Namespace {} index {} started", namespace.getNamespaceUri(), namespace.getNamespaceIndex());
        }

        new Thread(() -> {
            try {
                server.startup().get();
                future.get();

            } catch (Exception e) {
                log.error("Cannot startup the OPC UA Server", e);
                throw new RuntimeException(e);
            }
            log.info("OPC UA Server started.");
        }).start();

        Runtime.getRuntime().addShutdownHook(new Thread(() -> future.complete(null)));
    }

    @PreDestroy
    @SneakyThrows
    void stopServer() {
        try {
            future.complete(null);

            for (ManagedNamespaceWithLifecycle namespace : namespaces) {
                namespace.shutdown();
                log.info("Namespace {} index {} shut down", namespace.getNamespaceUri(), namespace.getNamespaceIndex());
            }

            server.shutdown().get();
            log.info("OPC UA Server shut down.");

        } catch (Exception e) {
            log.error("Cannot shutdown OPC UA Server", e);
            throw e;
        }
    }
}
