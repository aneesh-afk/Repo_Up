def calculate_discount_b(products):
    amount = 0
    for product in products:
        amount += product["price"]
    return amount * 0.9
