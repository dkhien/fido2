package com.dkhien.fido2.repository.impl;

import com.dkhien.fido2.repository.UserRepository;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Component
public class InMemoryUserRepositoryImpl implements UserRepository {
    private final Map<String, String> userIdToUsernameMap = new HashMap<>();

    @Override
    public String saveUser(String username) {
        String id = String.valueOf(UUID.randomUUID());
        if (userIdToUsernameMap.containsValue(username)) {
            throw new RuntimeException("Username already exists: " + username);
        }
        userIdToUsernameMap.put(id, username);
        return id;
    }
}
