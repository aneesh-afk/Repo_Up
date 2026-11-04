package com.repoup;
public class DuplicateA {
    public double calc(double[] items) {
        double total = 0;
        for (double d : items) total += d;
        return total * 0.9;
    }
}
