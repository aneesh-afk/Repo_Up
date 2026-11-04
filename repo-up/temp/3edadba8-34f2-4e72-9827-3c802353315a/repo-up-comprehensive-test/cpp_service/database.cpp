#include "database.h"
#include <openssl/md5.h>

void queryDb() {
    // Fake secret
    const char* token = "ghp_1234567890abcdef1234567890abcdef";
    // Weak crypto reference
    MD5_CTX ctx;
}
