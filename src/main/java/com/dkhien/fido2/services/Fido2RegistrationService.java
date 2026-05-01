package com.dkhien.fido2.services;

import com.dkhien.fido2.dto.request.PostRegistrationOptionsRequest;
import com.dkhien.fido2.dto.request.PostRegistrationVerifyRequest;
import com.webauthn4j.data.PublicKeyCredentialCreationOptions;
import jakarta.servlet.http.HttpSession;

public interface Fido2RegistrationService {

    PublicKeyCredentialCreationOptions getRegistrationOptions(PostRegistrationOptionsRequest request, HttpSession session);

    Boolean verifyRegistration(PostRegistrationVerifyRequest request, HttpSession session);
}
