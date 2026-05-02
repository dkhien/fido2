package com.dkhien.fido2.repository;

import com.webauthn4j.credential.CredentialRecord;

public interface CredentialRepository {

    String saveCredential(CredentialRecord credentialRecord);

    CredentialRecord getCredentialById(String credentialId);
}
