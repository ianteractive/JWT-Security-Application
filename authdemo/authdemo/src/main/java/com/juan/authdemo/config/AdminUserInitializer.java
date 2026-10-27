
package com.juan.authdemo.config;

import com.juan.authdemo.entity.User;
import com.juan.authdemo.repository.UserRepository;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class AdminUserInitializer {

    @Bean
    public CommandLineRunner createAdminUser(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            @Value("${app.admin.username:}") String username,
            @Value("${app.admin.password:}") String password) {

        return args -> {

            // Skip admin creation if credentials are not configured.
            if (username.isBlank() || password.isBlank()) {
                return;
            }

            if (password.length() < 12) {
                throw new IllegalStateException(
                        "Admin password must contain at least 12 characters."
                );
            }

            // Never overwrite or promote an existing account automatically.
            if (userRepository.existsByUsername(username)) {
                return;
            }

            User admin = new User(
                    username,
                    passwordEncoder.encode(password),
                    "ADMIN"
            );

            userRepository.save(admin);

            System.out.println("Initial admin user created.");
        };
    }
}
