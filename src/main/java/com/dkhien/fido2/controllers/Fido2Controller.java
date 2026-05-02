package com.dkhien.fido2.controllers;

import com.dkhien.fido2.dto.request.PostAuthenticationOptionsRequest;
import com.dkhien.fido2.dto.request.PostAuthenticationVerifyRequest;
import com.dkhien.fido2.dto.request.PostRegistrationOptionsRequest;
import com.dkhien.fido2.dto.request.PostRegistrationVerifyRequest;
import com.dkhien.fido2.services.Fido2AuthenticationService;
import com.dkhien.fido2.services.Fido2RegistrationService;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.PublicKeyCredentialCreationOptions;
import com.webauthn4j.data.PublicKeyCredentialRequestOptions;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
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
    private final Fido2AuthenticationService fido2AuthenticationService;
    private final ObjectConverter objectConverter = new ObjectConverter();

    @PostMapping(value = "/register/options", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> postRegistrationOptions(@RequestBody PostRegistrationOptionsRequest request, HttpSession session) {
        PublicKeyCredentialCreationOptions options = fido2RegistrationService.getRegistrationOptions(request, session);
        String json = objectConverter.getJsonMapper().writeValueAsString(options);
        return ResponseEntity.ok(json);
    }

    @PostMapping("/register/verify")
    public ResponseEntity<Boolean> postRegistrationVerify(@RequestBody PostRegistrationVerifyRequest request, HttpSession session) {
        return ResponseEntity.ok(fido2RegistrationService.verifyRegistration(request, session));
    }

    @PostMapping("/authenticate/options")
    public ResponseEntity<String> postAuthenticationOptions(@RequestBody PostAuthenticationOptionsRequest request, HttpSession session) {
        PublicKeyCredentialRequestOptions options = fido2AuthenticationService.getAuthenticationOptions(request, session);
        String json = objectConverter.getJsonMapper().writeValueAsString(options);
        return ResponseEntity.ok(json);
    }

    @PostMapping("/authenticate/verify")
    public ResponseEntity<Boolean> postAuthenticationVerify(@RequestBody PostAuthenticationVerifyRequest request, HttpSession session) {
        return ResponseEntity.ok(fido2AuthenticationService.verifyAuthentication(request, session));
    }

}
