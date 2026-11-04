double calc(double* items, int size) {
    double total = 0;
    for(int i=0; i<size; i++) total += items[i];
    return total * 0.9;
}
