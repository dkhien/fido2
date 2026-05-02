package com.dkhien.fido2.services.impl;

import com.dkhien.fido2.dto.request.PostAuthenticationOptionsRequest;
import com.dkhien.fido2.dto.request.PostAuthenticationVerifyRequest;
import com.dkhien.fido2.entity.CredentialEntity;
import com.dkhien.fido2.repository.CredentialJpaRepository;
import com.dkhien.fido2.services.Fido2AuthenticationService;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.credential.CredentialRecord;
import com.webauthn4j.credential.CredentialRecordImpl;
import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientInput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.verifier.exception.VerificationException;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Base64;
import java.util.List;

import static com.webauthn4j.data.UserVerificationRequirement.REQUIRED;

@Service
@RequiredArgsConstructor
public class Fido2AuthenticationServiceImpl implements Fido2AuthenticationService {

    private final CredentialJpaRepository credentialRepository;
    private final WebAuthnManager webAuthnManager = WebAuthnManager.createNonStrictWebAuthnManager();
    private final ObjectConverter objectConverter = new ObjectConverter();

    @Override
    public PublicKeyCredentialRequestOptions getAuthenticationOptions(PostAuthenticationOptionsRequest request, HttpSession session) {
        Challenge challenge = new DefaultChallenge();
        session.setAttribute("fido2_authentication_challenge", challenge);
        Long timeout = 60000L;
        String rpId = "localhost";
        List<PublicKeyCredentialDescriptor> allowCredentials = List.of();
        UserVerificationRequirement userVerification = REQUIRED;
        List<PublicKeyCredentialHints> hints = List.of();
        AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput> extensions = null;

        return new PublicKeyCredentialRequestOptions(challenge, timeout, rpId, allowCredentials, userVerification, hints, extensions);
    }

    @Override
    public Boolean verifyAuthentication(PostAuthenticationVerifyRequest request, HttpSession session) {
        String username = request.username();

        String authenticationResponseJSON = request.response().toString();
        AuthenticationData authenticationData;
        try {
            authenticationData = webAuthnManager.parseAuthenticationResponseJSON(authenticationResponseJSON);
        } catch (DataConversionException e) {
            // If you would like to handle WebAuthn data structure parse error, please catch DataConversionException
            throw e;
        }

        // Server properties
        Challenge challenge = (Challenge) session.getAttribute("fido2_authentication_challenge");
        session.removeAttribute("fido2_authentication_challenge");

        // Server properties
        Origin origin = Origin.create("http://localhost:5173");
        String rpId = "localhost";
        ServerProperty serverProperty = ServerProperty.builder()
                .origin(origin)
                .rpId(rpId)
                .challenge(challenge)
                .build();

        // expectations
        List<byte[]> allowCredentials = credentialRepository.findByUserUsername(username)
                .stream().map(credentialEntity -> Base64.getUrlDecoder().decode(credentialEntity.getCredentialId())).toList();

        boolean userVerificationRequired = true;
        boolean userPresenceRequired = true;

        byte[] credentialIdBytes = authenticationData.getCredentialId();
        String credentialId = Base64.getUrlEncoder().withoutPadding().encodeToString(credentialIdBytes);

        CredentialEntity credentialEntity = credentialRepository.getCredentialEntityByCredentialId(credentialId);
        // Deserialize stored attestationObjectBytes back to AttestationObject, then reconstruct CredentialRecord
        AttestationObject attestationObject = objectConverter.getCborMapper()
                .readValue(credentialEntity.getCredentialRecord(), AttestationObject.class);
        CredentialRecord credentialRecord = new CredentialRecordImpl(attestationObject, null, null, null);

        AuthenticationParameters authenticationParameters =
                new AuthenticationParameters(
                        serverProperty,
                        credentialRecord,
                        allowCredentials,
                        userVerificationRequired,
                        userPresenceRequired
                );

        try {
            webAuthnManager.verify(authenticationData, authenticationParameters);
        } catch (VerificationException e) {
            throw e;
        }
//        // TODO: update the counter of the authenticator record
//        updateCounter(
//                authenticationData.getCredentialId(),
//                authenticationData.getAuthenticatorData().getSignCount()
//        );

        return true;
    }

}
