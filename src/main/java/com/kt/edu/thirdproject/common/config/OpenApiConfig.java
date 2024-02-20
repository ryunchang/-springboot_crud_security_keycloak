package com.kt.edu.thirdproject.common.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import io.swagger.v3.oas.models.ExternalDocumentation;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;

@Configuration
public class OpenApiConfig {


    @Value("${spring.application.name}")
    private String applicationName;

    //@Value("${spring.application.name}")
    //private String group;

    @Value("${app-info.title}")
    private String title;

    @Value("${app-info.desc}")
    private String desc;

    @Value("${app-info.build.version}")
    private String version;

    @Value("${app-info.license}")
    private String license;

    @Value("${app-info.license-url}")
    private String licenseUrl;

    @Value("${app-info.doc-desc}")
    private String docDesc;

    @Value("${app-info.doc-url}")
    private String docUurl;

    /*@Profile({"local", "dev"})
    @Bean
    public GroupedOpenApi openApi() {
        String[] paths = {"/**"};
        return GroupedOpenApi.builder().group(group).pathsToMatch(paths).build();
    } */

    @Profile({"local", "dev"})
    @Bean
    public GroupedOpenApi customApi() {
        return GroupedOpenApi.builder().group("api").pathsToMatch("/api/**").build();
    }

    @Profile({"local", "dev"})
    @Bean
    public GroupedOpenApi actuatorApi() {
        return GroupedOpenApi.builder().group("actuator").pathsToMatch("/actuator/**").build();
    }

    private SecurityScheme createAPIKeyScheme() {
        return new SecurityScheme().type(SecurityScheme.Type.HTTP)
                .bearerFormat("JWT")
                .scheme("bearer");
    }

    @Bean
    public OpenAPI springShopOpenAPI() {
        return new OpenAPI()
                .addSecurityItem(new SecurityRequirement().
                        addList("Bearer Authentication"))
                .components(new Components().addSecuritySchemes
                        ("Bearer Authentication", createAPIKeyScheme()))
                .info(new Info().title(title)
                        .description(desc)
                        .version(version)
                        .license(new License().name(license).url(licenseUrl)))
                .externalDocs(new ExternalDocumentation()
                        .description(docDesc)
                        .url(docUurl));
    }

}
