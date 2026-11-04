function calc(items) {
    let t = 0;
    for(let i of items) t += i.price;
    return t * 0.9;
}
