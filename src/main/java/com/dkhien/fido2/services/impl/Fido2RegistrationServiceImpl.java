package com.dkhien.fido2.services.impl;

import com.dkhien.fido2.dto.request.PostRegistrationOptionsRequest;
import com.dkhien.fido2.dto.request.PostRegistrationVerifyRequest;
import com.dkhien.fido2.entity.CredentialEntity;
import com.dkhien.fido2.entity.UserEntity;
import com.dkhien.fido2.repository.CredentialJpaRepository;
import com.dkhien.fido2.repository.UserJpaRepository;
import com.dkhien.fido2.services.Fido2RegistrationService;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.credential.CredentialRecordImpl;
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
import org.springframework.transaction.annotation.Transactional;

import java.util.Base64;
import java.util.List;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class Fido2RegistrationServiceImpl implements Fido2RegistrationService {

    private final UserJpaRepository userJpaRepository;
    private final CredentialJpaRepository credentialJpaRepository;
    private final WebAuthnManager webAuthnManager = WebAuthnManager.createNonStrictWebAuthnManager();
    private final ObjectConverter objectConverter = new ObjectConverter();

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
        List<PublicKeyCredentialDescriptor> excludeCredentials = buildExcludeCredentials(username);
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
    @Transactional
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

            saveCredential(request.username(), registrationData);
            log.info("[Register/Verify] Verification successful - username={}", request.username());
            return true;
        } catch (VerificationException e) {
            log.warn("[Register/Verify] Verification failed - {}", e.getMessage());
            return false;
        }
    }

    private void saveCredential(String username, RegistrationData registrationData) {
        UserEntity user = userJpaRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found: " + username));

        byte[] credentialIdBytes = registrationData.getAttestationObject()
                .getAuthenticatorData()
                .getAttestedCredentialData()
                .getCredentialId();
        String credentialId = Base64.getUrlEncoder().withoutPadding().encodeToString(credentialIdBytes);

        CredentialRecordImpl credentialRecord = new CredentialRecordImpl(
                registrationData.getAttestationObject(),
                registrationData.getCollectedClientData(),
                registrationData.getClientExtensions(),
                registrationData.getTransports()
        );

        byte[] credentialRecordBytes = objectConverter.getCborMapper().writeValueAsBytes(credentialRecord);
        credentialJpaRepository.save(new CredentialEntity(credentialId, credentialRecordBytes, user));
        log.info("[Register/Verify] Credential saved - credentialId={}", credentialId);
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
        if (userJpaRepository.existsByUsername(username)) {
            throw new RuntimeException("Username already exists: " + username);
        }
        String id = UUID.randomUUID().toString();
        userJpaRepository.save(new UserEntity(id, username));
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

    private List<PublicKeyCredentialDescriptor> buildExcludeCredentials(String username) {
        return credentialJpaRepository.findByUserUsername(username).stream()
                .map(credential -> {
                    byte[] credentialIdBytes = Base64.getUrlDecoder().decode(credential.getCredentialId());
                    return new PublicKeyCredentialDescriptor(PublicKeyCredentialType.PUBLIC_KEY, credentialIdBytes, null);
                })
                .toList();
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
