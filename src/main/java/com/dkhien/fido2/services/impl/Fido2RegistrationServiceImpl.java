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
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Base64;
import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class Fido2RegistrationServiceImpl implements Fido2RegistrationService {

    private final UserRepository userRepository;
    private final WebAuthnManager webAuthnManager = WebAuthnManager.createNonStrictWebAuthnManager();

    @Override
    public PublicKeyCredentialCreationOptions getRegistrationOptions(PostRegistrationOptionsRequest request, HttpSession session) {
        log.info("[Register/Options] Request - {}", request);

        String username = request.username();

        PublicKeyCredentialRpEntity rp = buildRp();
        PublicKeyCredentialUserEntity userEntity = buildUserEntity(username);
        Challenge challenge = buildChallenge();
        session.setAttribute("fido2_registration_challenge", challenge);
        List<PublicKeyCredentialParameters> pubKeyCredParams = buildPubKeyCredParams();
        Long timeout = 60000L;
        List<PublicKeyCredentialDescriptor> excludeCredentials = buildExcludeCredentials();
        AuthenticatorSelectionCriteria authSelectionCriteria = buildAuthSelectionCriteria();
        List<PublicKeyCredentialHints> hints = buildHints();
        AttestationConveyancePreference attestation = buildAttestation();
        List<String> attestationFormats = buildAttestationFormats();
        AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> extensions = buildExtensions();

        PublicKeyCredentialCreationOptions options = new PublicKeyCredentialCreationOptions(
            rp, userEntity, challenge, pubKeyCredParams,
            timeout, excludeCredentials, authSelectionCriteria, hints, attestation, attestationFormats, extensions
        );

        log.info("[Register/Options] Response - {}", options);
        return options;
    }

    @Override
    public Boolean verifyRegistration(PostRegistrationVerifyRequest request, HttpSession session) {
        log.info("[Register/Verify] Request - username={}", request.username());

        String responseJson = request.response().toString();
        log.info("[Register/Verify] Credential JSON - {}", responseJson);

        Challenge challenge = (Challenge) session.getAttribute("fido2_registration_challenge");
        session.removeAttribute("fido2_registration_challenge");
        log.info("[Register/Verify] Challenge retrieved from session - challengeFound={}", challenge != null);

        // Server properties
        Origin origin = Origin.create("http://localhost:5173");
        String rpId = "localhost";
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

        RegistrationData registrationData;
        try {
            registrationData = webAuthnManager.parseRegistrationResponseJSON(responseJson);
        } catch (DataConversionException e) {
            log.error("[Register/Verify] Data conversion failed - {}", e.getMessage());
            throw e;
        }

        logParsedRegistrationData(registrationData);

        try {
            webAuthnManager.verify(registrationData, registrationParameters);

            // TODO: Verify credential ID hasn't existed in repository
            log.info("[Register/Verify] Verification successful - username={}", request.username());
            return true;
        } catch (VerificationException e) {
            log.warn("[Register/Verify] Verification failed - {}", e.getMessage());
            return false;
        }
    }

    private void logParsedRegistrationData(RegistrationData data) {
        var clientData = data.getCollectedClientData();
        if (clientData != null) {
            log.info("[Register/Verify] ClientData - type={} origin={} crossOrigin={} challenge={}",
                    clientData.getType(),
                    clientData.getOrigin(),
                    clientData.getCrossOrigin(),
                    Base64.getUrlEncoder().withoutPadding().encodeToString(clientData.getChallenge().getValue()));
        }

        var authData = data.getAttestationObject() != null
                ? data.getAttestationObject().getAuthenticatorData()
                : null;
        if (authData != null) {
            log.info("[Register/Verify] AuthData - flagUP={} flagUV={} flagBE={} flagBS={} signCount={}",
                    authData.isFlagUP(),
                    authData.isFlagUV(),
                    authData.isFlagBE(),
                    authData.isFlagBS(),
                    authData.getSignCount());

            var credData = authData.getAttestedCredentialData();
            if (credData != null) {
                log.info("[Register/Verify] AttestedCredentialData - aaguid={} credentialId={} keyAlgorithm={}",
                        credData.getAaguid(),
                        Base64.getUrlEncoder().withoutPadding().encodeToString(credData.getCredentialId()),
                        credData.getCOSEKey().getAlgorithm());
            }
        }
    }

    private PublicKeyCredentialRpEntity buildRp() {
        String rpId = "localhost";
        String rpName = "FIDO2 Demo";
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
        // TODO: Make a credential repository and add list of existing cred IDs to exclude
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
