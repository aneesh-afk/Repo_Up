package com.repoup;
public class CycleB {
    public void b() { new CycleA().a(); }
}
