package com.dkhien.fido2.dto.request;

import tools.jackson.databind.JsonNode;

public record PostAuthenticationVerifyRequest(String username, JsonNode response) {
}
