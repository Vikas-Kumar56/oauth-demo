package com.basic.oauth.repository;

import com.basic.oauth.model.RSAKeyPair;
import org.springframework.stereotype.Component;

import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class InMemoryRSAKeyRepository implements RSAKeyRepository{

    private final HashMap<String, RSAKeyPair> store = new HashMap<>();

    @Override
    public List<RSAKeyPair> findAllKeys() {
        return store.values()
                .stream()
                .sorted(Comparator.comparing(value -> value.creationDate().toInstant()))
                .collect(Collectors.toList());
    }

    @Override
    public void save(RSAKeyPair rsaKeyPair) {
      store.put(rsaKeyPair.id(), rsaKeyPair);
    }
}
