function compute(products) {
    let sum = 0;
    for(let p of products) sum += p.price;
    return sum * 0.9;
}
