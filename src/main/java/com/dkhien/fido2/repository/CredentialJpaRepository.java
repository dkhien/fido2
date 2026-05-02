package com.dkhien.fido2.repository;

import com.dkhien.fido2.entity.CredentialEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CredentialJpaRepository extends JpaRepository<CredentialEntity, String> {
}
