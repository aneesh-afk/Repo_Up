def calculate_discount_a(items):
    total = 0
    for item in items:
        total += item["price"]
    return total * 0.9
