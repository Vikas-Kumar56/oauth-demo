package com.basic.oauth;

import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/test")
public class TestController {

    private final OAuth2AuthorizationService oAuth2AuthorizationService;

    public TestController(OAuth2AuthorizationService oAuth2AuthorizationService) {
        this.oAuth2AuthorizationService = oAuth2AuthorizationService;
    }

    @GetMapping
    public OAuth2Authorization getAuth(@RequestParam("clientId") String clientId) {
      return  oAuth2AuthorizationService.findByToken(clientId, OAuth2TokenType.ACCESS_TOKEN);
    }
}
