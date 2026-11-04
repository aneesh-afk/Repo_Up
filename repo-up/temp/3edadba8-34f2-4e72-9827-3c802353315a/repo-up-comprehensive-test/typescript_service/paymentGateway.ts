import * as crypto from 'crypto';

export async function confirmPayment(payment: any) {
    // Weak crypto
    const hash = crypto.createHash('md5').update('fake').digest('hex');
    // Fake token
    const token = "ghp_1234567890abcdef1234567890abcdef";
    return true;
}
