package com.basic.oauth.repository;

import com.basic.oauth.model.RsaKeyPair;
import org.springframework.stereotype.Component;

import java.util.Comparator;
import java.util.HashMap;
import java.util.List;

@Component
public class InMemoryRsaKeyRepository implements RsaKeyRepository {

    private final HashMap<String, RsaKeyPair> store = new HashMap<String, RsaKeyPair>();

    @Override
    public List<RsaKeyPair> findAllKeys() {
        return store.values().stream()
                .sorted(Comparator.comparing(value -> value.creationDate().toInstant()))
                .toList();
    }

    @Override
    public void save(RsaKeyPair rsaKeyPair) {
        store.put(rsaKeyPair.id(), rsaKeyPair);
    }
}
