package com.basic.oauth.model;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.OffsetDateTime;

public record RsaKeyPair(
        String id,
        RSAPrivateKey privateKey,
        RSAPublicKey publicKey,
        OffsetDateTime creationDate
) {
}
