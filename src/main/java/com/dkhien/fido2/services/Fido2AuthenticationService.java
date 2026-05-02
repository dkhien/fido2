package com.dkhien.fido2.services;

import com.dkhien.fido2.dto.request.PostAuthenticationOptionsRequest;
import com.dkhien.fido2.dto.request.PostAuthenticationVerifyRequest;
import com.webauthn4j.data.PublicKeyCredentialRequestOptions;
import jakarta.servlet.http.HttpSession;

public interface Fido2AuthenticationService {

    PublicKeyCredentialRequestOptions getAuthenticationOptions(PostAuthenticationOptionsRequest request, HttpSession session);

    Boolean verifyAuthentication(PostAuthenticationVerifyRequest request, HttpSession session);
}
