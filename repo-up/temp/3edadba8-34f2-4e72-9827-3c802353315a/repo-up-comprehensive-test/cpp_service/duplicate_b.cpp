double compute(double* products, int count) {
    double sum = 0;
    for(int j=0; j<count; j++) sum += products[j];
    return sum * 0.9;
}
