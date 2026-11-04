package com.repoup;
public class CycleA {
    public void a() { new CycleB().b(); }
}
