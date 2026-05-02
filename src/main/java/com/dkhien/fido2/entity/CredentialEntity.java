package com.dkhien.fido2.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "credentials")
@Getter
@Setter
@NoArgsConstructor
public class CredentialEntity {

    @Id
    private String credentialId;

    // CBOR-serialized CredentialRecordImpl
    @Lob
    @Column(nullable = false)
    private byte[] credentialRecord;

    @ManyToOne(optional = false)
    @JoinColumn(name = "user_id")
    private UserEntity user;

    public CredentialEntity(String credentialId, byte[] credentialRecord, UserEntity user) {
        this.credentialId = credentialId;
        this.credentialRecord = credentialRecord;
        this.user = user;
    }
}
