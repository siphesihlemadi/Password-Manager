package org.example;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import java.io.File;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;


public class AuthManager {
    String dbName = "masterPasswordDatabase.db";
    String url = "jdbc:sqlite:" + dbName;

    /**
     * bouncy castle hashing + salting recommended defaults.
     * salt length 16 bytes
     * hash length 32 bytes
     * time cost is 3
     * memory cost in KB is 64 MB
     * threads is 1
     */
    private static final int SALT_LEN = 65;
    private static final int HASH_LEN = 32;
    private static final int ITERATIONS = 3;
    private static final int MEMORY_KB = 65536;
    private static final int PARALLELISM = 1;
    private static final int ARGON2_VERSION = Argon2Parameters.ARGON2_VERSION_13;

    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * hashing method that takes in a char array(master password) returns a hashed and salted String
     * for each char array, a unique salt is generated
     * $argon2id$v=19$m=<memory>,t=<iterations>,p=<parallelism>$<salt_b64>$<hash_b64>
     */
    public static String hash(char[] password) {
        Objects.requireNonNull(password, "password must not be null");

        byte[] salt = new byte[SALT_LEN];
        RANDOM.nextBytes(salt);

        Argon2Parameters.Builder builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(ARGON2_VERSION)
                .withIterations(ITERATIONS)
                .withMemoryAsKB(MEMORY_KB)
                .withParallelism(PARALLELISM)
                .withSalt(salt);

        Argon2Parameters params = builder.build();

        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(params);

        byte[] hash = new byte[HASH_LEN];

        try {
            generator.generateBytes(password, hash);
        } finally {

        }
        wipeCharArray(password);

        String saltB64 = Base64.getEncoder().withoutPadding().encodeToString(salt);
        String hashB64 = Base64.getEncoder().withoutPadding().encodeToString(hash);

        String header = String.format("$argon2id$v=%d$m=%d,t=%d,p=%d", ARGON2_VERSION, MEMORY_KB, ITERATIONS, PARALLELISM);
        return String.join("$", header, saltB64, hashB64);
    }

    /**
     * method that verifies master password from database
     * encoded is retrieved from database and compared with user input
     */
    public boolean verify(char[] password, String encoded) {
        Objects.requireNonNull(password, "password must not be null");
        Objects.requireNonNull(encoded, "encoded must not be null");

        String[] parts = encoded.split("\\$");
        //["","argon2id","v=19","m=65536,t=3,p=1", "<salt_b64>,"<hash_b64>"]
        //parts[0] is "", parts[1] is "argon2id", parts[3] is version
        if (parts.length < 6) {
            wipeCharArray(password);
            throw new IllegalArgumentException("Invalid encoded Argon2 hash format");
        }

        String paramPart = parts[3];
        String saltB62 = parts[4];
        String hashB64 = parts[5];

        int memory = MEMORY_KB;
        int iterations = ITERATIONS;
        int parallelism = PARALLELISM;
        String[] kvPairs = paramPart.split(",");
        for (String kv : kvPairs) {
            String[] kvp = kv.split("=");
            if (kvp.length != 2) continue;
            switch (kvp[0]) {
                case "m":
                    memory = Integer.parseInt(kvp[1]);
                    break;
                case "t":
                    iterations = Integer.parseInt(kvp[1]);
                    break;
                case "p":
                    parallelism = Integer.parseInt(kvp[1]);
                    break;
                default:
                    break;
            }
        }

        byte[] salt = Base64.getDecoder().decode(saltB62);
        byte[] expectedHash = Base64.getDecoder().decode(hashB64);

        //re-build parameters with the same salt and parsed values
        Argon2Parameters.Builder builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(ARGON2_VERSION)
                .withIterations(iterations)
                .withMemoryAsKB(MEMORY_KB)
                .withParallelism(parallelism)
                .withSalt(salt);

        Argon2Parameters params = builder.build();
        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(params);

        byte[] computed = new byte[expectedHash.length];
        try {
            generator.generateBytes(password, computed);
        } finally {
            wipeCharArray(password);
        }

        boolean matches = MessageDigest.isEqual(computed, expectedHash);

        wipeByteArray(computed);

        return matches;
    }

    /**
     * helper methods to wipe utilities
     */
    private static void wipeCharArray(char[] arr) {
        if (arr == null) return;
        Arrays.fill(arr, '\0');
    }

    private static void wipeByteArray(byte[] b) {
        if (b == null) return;
        Arrays.fill(b, (byte) 0);
    }

    /**
     * verifies that master password has not been created yet.
     * creates master password database if it doesn't exist.
     * try catches SQL exceptions and prints exception message
     */
    void createMasterPasswordTable() {
        boolean newDatabase = !new File(dbName).exists();
        try (Connection conn = DriverManager.getConnection(url)) {
            if (newDatabase) {
                try (Statement stmt = conn.createStatement()) {
                    String createTable = "CREATE TABLE IF NOT EXISTS masterPassword (" +
                            "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                            "hash TEXT UNIQUE NOT NULL,";

                    stmt.execute(createTable);
                    System.out.println("Table Created.");
                }
            } else {
                System.out.println("Master Password already exists. Enter Master Password.");
            }
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    /**
     * takes input (master password) passes it to the hash method then into the database.
     * only stores hash string.
     * try catches SQL exceptions and prints exception messages.
     */
    void insertMasterPassword(char[] masterPassword) {
        String insertSql = "INSERT INTO masterPassword(hash) VALUES (?)";

        try (Connection conn = DriverManager.getConnection(url);
             PreparedStatement pstmt = conn.prepareStatement(insertSql)) {

            pstmt.setString(1, hash(masterPassword));
            pstmt.executeUpdate();
            System.out.println("Master Password Stored.");

        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    /**
     * compare hash and salt to database hash to verify user.
     * return true is verification is successful.
     */
    boolean verifyMasterPassword(char[] inputMasterPassword) {
        String selectSql = "SELECT * FROM masterPassword";

        try (Connection conn = DriverManager.getConnection(url);
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(selectSql)) {

            while (rs.next()) {
                String hash = rs.getString("hash");
                if (verify(inputMasterPassword, hash)) return true;
            }


        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
        return false;
    }
}

