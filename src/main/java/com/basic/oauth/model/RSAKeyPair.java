package com.basic.oauth.model;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.OffsetDateTime;

public record RSAKeyPair(
        String id,
        RSAPrivateKey rsaPrivateKey,
        RSAPublicKey rsaPublicKey,

        OffsetDateTime creationDate
) {
}
