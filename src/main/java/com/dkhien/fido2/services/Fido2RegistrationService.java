package com.dkhien.fido2.services;

import com.dkhien.fido2.dto.request.PostRegistrationOptionsRequest;
import com.dkhien.fido2.dto.request.PostRegistrationVerifyRequest;
import com.webauthn4j.data.PublicKeyCredentialCreationOptions;

public interface Fido2RegistrationService {

    PublicKeyCredentialCreationOptions getRegistrationOptions(PostRegistrationOptionsRequest request);

    Boolean verifyRegistration(PostRegistrationVerifyRequest request);
}
