package com.kt.edu.thirdproject.employee.runner;

import com.kt.edu.thirdproject.common.config.SecurityConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Slf4j
@RequiredArgsConstructor
@Component
public class KeycloakInitializerRunner implements CommandLineRunner {

    private final Keycloak keycloakAdmin;

    @Override
    public void run(String... args) {
        log.info("Initializing '{}' realm in Keycloak ...", COMPANY_SERVICE_REALM_NAME);

        Optional<RealmRepresentation> representationOptional = keycloakAdmin.realms()
                .findAll()
                .stream()
                .filter(r -> r.getRealm().equals(COMPANY_SERVICE_REALM_NAME))
                .findAny();
        if (representationOptional.isPresent()) {
            log.info("Removing already pre-configured '{}' realm", COMPANY_SERVICE_REALM_NAME);
            keycloakAdmin.realm(COMPANY_SERVICE_REALM_NAME).remove();
        }

        // Realm
        RealmRepresentation realmRepresentation = new RealmRepresentation();
        realmRepresentation.setRealm(COMPANY_SERVICE_REALM_NAME);
        realmRepresentation.setEnabled(true);
        realmRepresentation.setRegistrationAllowed(true);

        // Client
        ClientRepresentation clientRepresentation = new ClientRepresentation();
        clientRepresentation.setClientId(EMPLOYEE_APP_CLIENT_ID);
        clientRepresentation.setDirectAccessGrantsEnabled(true);
        clientRepresentation.setPublicClient(true);
        clientRepresentation.setRedirectUris(List.of(EMPLOYEE_APP_REDIRECT_URL));
        clientRepresentation.setDefaultRoles(new String[]{SecurityConfig.EMPLOYEE_USER});
        realmRepresentation.setClients(List.of(clientRepresentation));

        // Users
        List<UserRepresentation> userRepresentations = EMPLOYEE_USER_LIST.stream()
                .map(userPass -> {
                    // User Credentials
                    CredentialRepresentation credentialRepresentation = new CredentialRepresentation();
                    credentialRepresentation.setType(CredentialRepresentation.PASSWORD);
                    credentialRepresentation.setValue(userPass.password());

                    // User
                    UserRepresentation userRepresentation = new UserRepresentation();
                    userRepresentation.setUsername(userPass.username());
                    userRepresentation.setEnabled(true);
                    userRepresentation.setCredentials(List.of(credentialRepresentation));
                    userRepresentation.setClientRoles(getClientRoles(userPass));

                    return userRepresentation;
                })
                .toList();
        realmRepresentation.setUsers(userRepresentations);

        // Create Realm
        keycloakAdmin.realms().create(realmRepresentation);

        // Testing
        UserPass admin = EMPLOYEE_USER_LIST.get(0);
        log.info("Testing getting token for '{}' ...", admin.username());

        Keycloak keycloakMovieApp = KeycloakBuilder.builder().serverUrl(KEYCLOAK_SERVER_URL)
                .realm(COMPANY_SERVICE_REALM_NAME).username(admin.username()).password(admin.password())
                .clientId(EMPLOYEE_APP_CLIENT_ID).build();

        log.info("'{}' token: {}", admin.username(), keycloakMovieApp.tokenManager().grantToken().getToken());
        log.info("'{}' initialization completed successfully!", COMPANY_SERVICE_REALM_NAME);
    }

    private Map<String, List<String>> getClientRoles(UserPass userPass) {
        List<String> roles = new ArrayList<>();
        roles.add(SecurityConfig.EMPLOYEE_USER);
        if ("admin".equals(userPass.username())) {
            roles.add(SecurityConfig.EMPLOYEE_MANAGER);
        }
        return Map.of(EMPLOYEE_APP_CLIENT_ID, roles);
    }

    private static final String KEYCLOAK_SERVER_URL = "http://keycloak.yoonchang.duckdns.org:30002";
    private static final String COMPANY_SERVICE_REALM_NAME = "employee-services";
    private static final String EMPLOYEE_APP_CLIENT_ID = "employee-app";
    private static final String EMPLOYEE_APP_REDIRECT_URL = "http://frontend.yoonchang.duckdns.org:30002/*";
    private static final List<UserPass> EMPLOYEE_USER_LIST = Arrays.asList(
            new UserPass("admin", "admin"),
            new UserPass("user", "user"));

    private record UserPass(String username, String password) {
    }
}