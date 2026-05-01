package com.dkhien.fido2.dto.request;

import tools.jackson.databind.JsonNode;

public record PostRegistrationVerifyRequest(String username, JsonNode response) {
}
