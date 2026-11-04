import sys
from .service import process_data

def calculate_total(items):
    total = 0
    for item in items:
        total += item["price"]
    # Intentional: Undefined Name (undefined_discount)
    return total + undefined_discount

def get_user_status(user):
    # Intentional: Inconsistent Return
    if user:
        return "active"
    else:
        return
