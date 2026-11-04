package com.repoup;
public class DuplicateB {
    public double compute(double[] products) {
        double sum = 0;
        for (double p : products) sum += p;
        return sum * 0.9;
    }
}
