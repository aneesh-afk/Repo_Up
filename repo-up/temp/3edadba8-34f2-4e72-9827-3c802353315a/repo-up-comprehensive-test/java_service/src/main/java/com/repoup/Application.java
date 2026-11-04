package com.repoup;

public class Application {
    public static void main(String[] args) {
        PaymentService ps = new PaymentService();
        ps.process();
        // Unresolved symbol
        System.out.println(UnknownClass.val);
        // Unused variable
        int unused = 42;
    }
}
