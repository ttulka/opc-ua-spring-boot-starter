package com.ttulka.opcua.spring.boot.auth;

public interface Authenticator<T> {

    boolean validateToken(T token);
}
