package com.dkhien.fido2.controllers;

import com.dkhien.fido2.dto.request.PostRegistrationOptionsRequest;
import com.dkhien.fido2.dto.request.PostRegistrationVerifyRequest;
import com.dkhien.fido2.services.Fido2RegistrationService;
import com.webauthn4j.data.PublicKeyCredentialCreationOptions;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/fido2")
public class Fido2Controller {
    private final Fido2RegistrationService fido2RegistrationService;

    @PostMapping("/register/options")
    public ResponseEntity<PublicKeyCredentialCreationOptions> postRegistrationOptions(PostRegistrationOptionsRequest request) {
        return ResponseEntity.ok(fido2RegistrationService.getRegistrationOptions(request));
    }

    @PostMapping("/register/verify")
    public ResponseEntity<Boolean> postRegistrationVerify(PostRegistrationVerifyRequest request) {
        return ResponseEntity.ok(fido2RegistrationService.verifyRegistration(request));
    }
}
