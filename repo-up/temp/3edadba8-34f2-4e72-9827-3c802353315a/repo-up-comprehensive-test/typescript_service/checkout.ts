import { confirmPayment } from './paymentGateway';
import { updateInventory } from './inventory';

export async function processCheckout(payment: any) {
    // Missing error handling on async operation - candidate for deterministic repair
    await confirmPayment(payment);
    await updateInventory();
}
