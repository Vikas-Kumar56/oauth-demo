package com.basic.oauth;

import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.provisioning.UserDetailsManager;

import java.util.UUID;

@SpringBootApplication
public class OauthApplication {

	public static void main(String[] args) {
		SpringApplication.run(OauthApplication.class, args);
	}

	@Bean
	public ApplicationRunner applicationRunner(RegisteredClientRepository registeredClientRepository, UserDetailsManager userDetailsManager) {
		return args -> {
			if(registeredClientRepository.findByClientId("public-client") == null) {
				RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
						.clientId("public-client")
						.clientSecret("secret")
						.clientAuthenticationMethod(ClientAuthenticationMethod.NONE) // authoprization code + PCKE
						.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
						.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
						.redirectUri("http://127.0.0.1:8081/login/aouth2/code/public-client")
						.postLogoutRedirectUri("http:127.0.0.1:8080")
						.scope(OidcScopes.OPENID)
						.scope(OidcScopes.PROFILE)
						.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
						.build();

				registeredClientRepository.save(registeredClient);
			}

			if(!userDetailsManager.userExists("user")) {
				var user = User.withDefaultPasswordEncoder()
						.username("user")
						.password("password")
						.authorities("read", "write")
						.build();

				userDetailsManager.createUser(user);
			}
		};
	}
}
