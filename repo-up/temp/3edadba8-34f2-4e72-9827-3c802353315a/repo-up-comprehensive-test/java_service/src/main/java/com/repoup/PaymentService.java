package com.repoup;

public class PaymentService extends DatabaseService {
    public void process() {
        try {
            // Dangerous API
            Runtime.getRuntime().exec("ls");
        } catch(Exception e) {}
    }
}
