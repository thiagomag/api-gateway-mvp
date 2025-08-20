package br.com.thiagomagdalena.apigatewaymvp.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.Collections;

@Configuration
public class CorsConfig {

    @Bean
    public CorsWebFilter corsWebFilter() {
        CorsConfiguration corsConfig = new CorsConfiguration();
        // Permite requisições da sua aplicação Vue. Use "*" para desenvolvimento se preferir.
        corsConfig.setAllowedOrigins(Collections.singletonList("http://localhost:5174"));
        corsConfig.setMaxAge(3600L); // Tempo que o navegador pode cachear a resposta preflight
        corsConfig.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
        corsConfig.addAllowedHeader("*"); // Permite todos os headers
        corsConfig.setAllowCredentials(true); // Permite o envio de credenciais (cookies, tokens)

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfig); // Aplica a configuração para todas as rotas (/**)

        return new CorsWebFilter(source);
    }
}
