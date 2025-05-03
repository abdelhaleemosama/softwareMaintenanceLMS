package net.java.lms_backend;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

public class ServerInitializer {

    private static final String DB_URL = "jdbc:postgresql://localhost:5432/LMS";
    private static final String DB_USER = "postgres";
    private static final String DB_PASSWORD = "1234";

    public static void runInitScriptFromString(String sqlScript) {
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             Statement stmt = conn.createStatement()) {

            for (String query : sqlScript.split(";")) {
                if (!query.trim().isEmpty()) {
                    stmt.execute(query);
                }
            }

            System.out.println("Initialization script executed successfully.");

        } catch (Exception e) {
            System.err.println("Error executing initialization script: " + e.getMessage());
        }
    }
}