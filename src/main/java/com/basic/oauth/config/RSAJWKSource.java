package com.basic.oauth.config;

import com.basic.oauth.model.RSAKeyPair;
import com.basic.oauth.repository.RSAKeyRepository;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

@Component
public class RSAJWKSource implements JWKSource<SecurityContext> {

    private final RSAKeyRepository rsaKeyRepository;

    public RSAJWKSource(RSAKeyRepository rsaKeyRepository) {
        this.rsaKeyRepository = rsaKeyRepository;
    }

    @Override
    public List<JWK> get(JWKSelector jwkSelector, SecurityContext securityContext) throws KeySourceException {
        var keys = rsaKeyRepository.findAllKeys();
        System.out.println("keys" + keys.toString());
        return keys.stream().map(key -> new RSAKey.Builder(key.rsaPublicKey())
                        .privateKey(key.rsaPrivateKey())
                        .keyID(key.id())
                        .build())
                .collect(Collectors.toList());
    }

}
