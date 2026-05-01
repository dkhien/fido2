package com.dkhien.fido2.config;

import com.webauthn4j.converter.util.ObjectConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import tools.jackson.databind.ObjectMapper;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Bean
    public ObjectConverter objectConverter() {
        return new ObjectConverter();
    }

    @Bean
    public ObjectMapper objectMapper(ObjectConverter objectConverter) {
        return objectConverter.getJsonMapper();
    }

    @Bean
    public com.webauthn4j.WebAuthnManager webAuthnManager(ObjectConverter objectConverter) {
        return com.webauthn4j.WebAuthnManager.createNonStrictWebAuthnManager(objectConverter);
    }

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/**")
                .allowedOrigins("http://localhost:5173", "http://localhost:3000")
                .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                .allowedHeaders("*")
                .allowCredentials(true);
    }
}
