package com.dkhien.fido2.repository;

import com.dkhien.fido2.entity.CredentialEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface CredentialJpaRepository extends JpaRepository<CredentialEntity, String> {
    CredentialEntity getCredentialEntityByCredentialId(String credentialId);
    List<CredentialEntity> findByUserUsername(String username);
}
