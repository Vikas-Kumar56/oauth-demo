package com.basic.oauth.config;

import com.basic.oauth.model.RsaKeyPair;
import com.basic.oauth.repository.RsaKeyRepository;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Component
public class RsaJWKSource implements JWKSource<SecurityContext> {

    private final RsaKeyRepository rsaKeyRepository;

    public RsaJWKSource(RsaKeyRepository rsaKeyRepository) {
        this.rsaKeyRepository = rsaKeyRepository;
    }

    @Override
    public List<JWK> get(JWKSelector jwkSelector, SecurityContext securityContext) throws KeySourceException {
        List<RsaKeyPair> allKeys = rsaKeyRepository.findAllKeys();
        return allKeys.stream().map(key -> new RSAKey.Builder(key.publicKey())
                .privateKey(key.privateKey())
                .keyID(key.id())
                .build()).collect(Collectors.toList());
    }
}
