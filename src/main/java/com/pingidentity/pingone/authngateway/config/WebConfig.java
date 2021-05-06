package com.pingidentity.pingone.authngateway.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
@EnableWebMvc
public class WebConfig implements WebMvcConfigurer {

	@Value("${ping.allowedOrigin}")
	private String allowedOrigin;

	@Override
	public void addCorsMappings(CorsRegistry registry) {
		
        registry.addMapping("/**")
        .allowedOrigins(allowedOrigin)
        .allowedMethods("POST", "GET", "OPTIONS")
        .allowedHeaders("Origin","Content-Type","Content-Length","Content-Disposition","X-Amz-Date","Authorization","X-Api-Key","X-Amz-Security-Token","Cookie","Accept")
        .allowCredentials(true)
        .maxAge(32400);  // 9 hours max age
	}
}
