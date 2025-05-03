package net.java.lms_backend;

import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

@Component
public class DatabaseInitializer {

    @PostConstruct
    public void initDatabase() {
        try (InputStream inputStream = getClass().getClassLoader().getResourceAsStream("init.sql")) {
            if (inputStream == null) {
                throw new IllegalStateException("Initialization script not found in resources folder.");
            }

            BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8));
            StringBuilder sql = new StringBuilder();
            String line;

            while ((line = reader.readLine()) != null) {
                sql.append(line).append("\n");
            }

            ServerInitializer.runInitScriptFromString(sql.toString());
            System.out.println("Database initialized.");
        } catch (Exception e) {
            System.err.println("Error executing initialization script: " + e.getMessage());
        }
    }
}
