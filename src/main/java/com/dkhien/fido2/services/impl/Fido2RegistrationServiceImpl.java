package com.dkhien.fido2.services.impl;

import com.dkhien.fido2.dto.request.PostRegistrationOptionsRequest;
import com.dkhien.fido2.dto.request.PostRegistrationVerifyRequest;
import com.dkhien.fido2.repository.UserRepository;
import com.dkhien.fido2.services.Fido2RegistrationService;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientInput;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.verifier.exception.VerificationException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import tools.jackson.databind.ObjectMapper;

import java.util.List;

@Service
@RequiredArgsConstructor
public class Fido2RegistrationServiceImpl implements Fido2RegistrationService {

    private final UserRepository userRepository;
    private final ObjectMapper objectMapper;
    private final WebAuthnManager webAuthnManager = WebAuthnManager.createNonStrictWebAuthnManager();

    @Override
    public PublicKeyCredentialCreationOptions getRegistrationOptions(PostRegistrationOptionsRequest request) {
        String username = request.username();

        PublicKeyCredentialRpEntity rp = buildRp();
        PublicKeyCredentialUserEntity userEntity = buildUserEntity(username);
        Challenge challenge = buildChallenge();
        List<PublicKeyCredentialParameters> pubKeyCredParams = buildPubKeyCredParams();
        Long timeout = 60000L;
        List<PublicKeyCredentialDescriptor> excludeCredentials = buildExcludeCredentials();
        AuthenticatorSelectionCriteria authSelectionCriteria = buildAuthSelectionCriteria();
        List<PublicKeyCredentialHints> hints = buildHints();
        AttestationConveyancePreference attestation = buildAttestation();
        List<String> attestationFormats = buildAttestationFormats();
        AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> extensions = buildExtensions();

        return new PublicKeyCredentialCreationOptions(
            // Mandatory fields
            rp, userEntity, challenge, pubKeyCredParams,

            // Optional fields
            timeout, excludeCredentials, authSelectionCriteria, hints, attestation, attestationFormats, extensions
        );
    }

    @Override
    public Boolean verifyRegistration(PostRegistrationVerifyRequest request) {
        String responseJson = objectMapper.writeValueAsString(request.response());

        // Server properties
        Origin origin = Origin.create("http://localhost:5173");
        String rpId = "rpId";
        Challenge challenge = new DefaultChallenge("challenge");
        ServerProperty serverProperty = ServerProperty.builder()
                .origin(origin)
                .rpId(rpId)
                .challenge(challenge)
                .build();

        // expectations
        List<PublicKeyCredentialParameters> pubKeyCredParams = buildPubKeyCredParams();
        boolean userVerificationRequired = true;
        boolean userPresenceRequired = true;

        RegistrationParameters registrationParameters =
                new RegistrationParameters(serverProperty, pubKeyCredParams, userVerificationRequired, userPresenceRequired);

        try {
            webAuthnManager.verifyRegistrationResponseJSON(responseJson, registrationParameters);
        }
        catch (DataConversionException e) {
            throw e;
        } catch (VerificationException e) {
            return false;
        }

        return true;
    }

    private PublicKeyCredentialRpEntity buildRp() {
        String rpId = "rpId";
        String rpName = "rpName";
        return new PublicKeyCredentialRpEntity(rpId, rpName);
    }

    private PublicKeyCredentialUserEntity buildUserEntity(String username) {
        String id = userRepository.saveUser(username);
        return new PublicKeyCredentialUserEntity(id.getBytes(), username, username);
    }

    private Challenge buildChallenge() {
        // TODO: Dynamic challenge, stored in session
        return new DefaultChallenge("challenge");
    }

    private List<PublicKeyCredentialParameters> buildPubKeyCredParams() {
        // List of preferred algorithms
        return List.of(
                new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256),
                new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.EdDSA),
                new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.RS256)
        );
    }

    private AuthenticatorSelectionCriteria buildAuthSelectionCriteria() {
        return new AuthenticatorSelectionCriteria(
                // attachment = null: no preference over platform or cross-platform (roaming) authenticators
                null,

                // requireResidentKey = false
                false,

                // residentKey = null as it is not required
                null,

                // require UV for better security (example: enforce biometric gesture from user)
                UserVerificationRequirement.REQUIRED
        );
    }

    private List<PublicKeyCredentialDescriptor> buildExcludeCredentials() {
        // Currently left empty, check later
        // TODO
        return List.of();
    }

    private List<PublicKeyCredentialHints> buildHints() {
        // Hint to use client device to authenticate (example: fingerprint on device)
        return List.of(PublicKeyCredentialHints.CLIENT_DEVICE);
    }

    private AttestationConveyancePreference buildAttestation() {
        // Direct: enforce attestation from authenticator
        return AttestationConveyancePreference.DIRECT;
    }

    private List<String> buildAttestationFormats() {
        // Currently left empty as no preference
        return List.of();
    }

    private AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> buildExtensions() {
        // Currently left empty as there is no extensions
        return new AuthenticationExtensionsClientInputs<>();
    }
}
