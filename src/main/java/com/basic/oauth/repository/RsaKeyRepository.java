package com.basic.oauth.repository;

import com.basic.oauth.model.RsaKeyPair;

import java.util.List;

public interface RsaKeyRepository {

    List<RsaKeyPair> findAllKeys();

    void save(RsaKeyPair rsaKeyPair);

}
