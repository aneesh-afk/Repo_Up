package com.repoup;
import java.security.MessageDigest;

public class DatabaseService extends BaseService {
    public void query() {
        try {
            // Weak crypto
            MessageDigest md = MessageDigest.getInstance("MD5");
        } catch(Exception e) {
            // Exception handling issue (ignored)
        }
        
        // Hardcoded credential
        String awsKey = "AKIAIOSFODNN7EXAMPLE";
    }
}
