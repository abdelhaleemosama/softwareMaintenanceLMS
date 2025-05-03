package net.java.lms_backend.Security;

import net.java.lms_backend.Repositrory.UserRepository;
import net.java.lms_backend.entity.Admin;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
public class ApplicationInitializer {
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public ApplicationInitializer(BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    @Bean
    public CommandLineRunner demo(UserRepository userRepository) {
        return (args) -> {
            // Check if the admin already exists
            if (userRepository.count() == 0) {
                // Create the admin user
                Admin admin = new Admin();
                admin.setUsername("FcaiAdmin");  // Set the admin username
                admin.setPassword( bCryptPasswordEncoder.encode("1234"));  // Set the password and encode it
                admin.setEnabled(true);
                userRepository.save(admin);
            }
        };
    }
}
