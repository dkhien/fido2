package com.dkhien.fido2.services.impl;

import com.dkhien.fido2.dto.request.PostRegistrationOptionsRequest;
import com.dkhien.fido2.repository.UserRepository;
import com.dkhien.fido2.services.Fido2RegistrationService;
import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class Fido2RegistrationServiceImpl implements Fido2RegistrationService {

    private final UserRepository userRepository;

    @Override
    public PublicKeyCredentialCreationOptions getRegistrationOptions(PostRegistrationOptionsRequest request) {
        String username = request.username();

        PublicKeyCredentialRpEntity rp = buildRp();
        PublicKeyCredentialUserEntity userEntity = buildUserEntity(username);
        Challenge challenge = buildChallenge();
        List<PublicKeyCredentialParameters> pubKeyCredParams = buildPubKeyCredParams();

        return new PublicKeyCredentialCreationOptions(
            rp, userEntity, challenge, pubKeyCredParams
        );
    }

    private PublicKeyCredentialRpEntity buildRp() {
        String rpId = "rpId";
        String rpName = "RP rpName";
        return new PublicKeyCredentialRpEntity(rpId, rpName);
    }

    private PublicKeyCredentialUserEntity buildUserEntity(String username) {
        String id = userRepository.saveUser(username);
        return new PublicKeyCredentialUserEntity(id.getBytes(), username, username);
    }

    private Challenge buildChallenge() {
        return new DefaultChallenge();
    }

    private List<PublicKeyCredentialParameters> buildPubKeyCredParams() {
        return List.of(
                new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256),
                new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.EdDSA),
                new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.RS256)
        );
    }
}
