package com.dkhien.fido2.controllers;

import com.dkhien.fido2.dto.request.PostRegistrationOptionsRequest;
import com.dkhien.fido2.dto.request.PostRegistrationVerifyRequest;
import com.dkhien.fido2.services.Fido2RegistrationService;
import com.webauthn4j.data.PublicKeyCredentialCreationOptions;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/fido2")
public class Fido2Controller {
    private final Fido2RegistrationService fido2RegistrationService;

    @PostMapping("/register/options")
    public ResponseEntity<PublicKeyCredentialCreationOptions> postRegistrationOptions(@RequestBody PostRegistrationOptionsRequest request, HttpSession session) {
        return ResponseEntity.ok(fido2RegistrationService.getRegistrationOptions(request, session));
    }

    @PostMapping("/register/verify")
    public ResponseEntity<Boolean> postRegistrationVerify(@RequestBody PostRegistrationVerifyRequest request, HttpSession session) {
        return ResponseEntity.ok(fido2RegistrationService.verifyRegistration(request, session));
    }
}
