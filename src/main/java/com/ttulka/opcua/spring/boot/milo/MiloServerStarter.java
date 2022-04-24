package com.ttulka.opcua.spring.boot.milo;

import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.eclipse.milo.opcua.sdk.server.OpcUaServer;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;

@RequiredArgsConstructor
@Slf4j
class MiloServerStarter {

    private final OpcUaServer server;

    @PostConstruct
    @SneakyThrows
    void startServer() {
        try {
            log.info("Staring the OPC UA Server");
            server.startup().get();

        } catch (Exception e) {
            log.error("Cannot startup the OPC UA Server", e);
            throw e;
        }
    }

    @PreDestroy
    @SneakyThrows
    void stopServer() {
        try {
            log.info("Shutting down the OPC UA Server");
            server.shutdown().get();

        } catch (Exception e) {
            log.error("Cannot shutdown OPC UA Server", e);
            throw e;
        }
    }
}
