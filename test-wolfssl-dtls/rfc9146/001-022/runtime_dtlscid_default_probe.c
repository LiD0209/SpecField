#include <stdio.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

int main(void)
{
    wolfSSL_Init();
#ifdef WOLFSSL_DTLS_CID
    printf("WOLFSSL_DTLS_CID defined\n");
    printf("max_size=%d\n", wolfSSL_dtls_cid_max_size());
#else
    printf("WOLFSSL_DTLS_CID not defined\n");
#endif
    wolfSSL_Cleanup();
    return 0;
}
