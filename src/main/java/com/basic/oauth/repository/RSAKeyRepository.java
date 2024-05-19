package com.basic.oauth.repository;

import com.basic.oauth.model.RSAKeyPair;

import java.util.List;

public interface RSAKeyRepository {
    List<RSAKeyPair> findAllKeys();

    void save(RSAKeyPair rsaKeyPair);

}
