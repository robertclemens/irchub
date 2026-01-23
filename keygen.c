#include "hub.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    char *priv_pem = NULL, *pub_pem = NULL;
    
    printf("Generating RSA-2048 keypair...\n");
    
    if (!hub_crypto_generate_keypair(&priv_pem, &pub_pem)) {
        fprintf(stderr, "Key generation failed\n");
        return 1;
    }
    
    const char *priv_file = (argc > 1) ? argv[1] : "hub_private.pem";
    const char *pub_file = (argc > 2) ? argv[2] : "hub_public.pem";
    
    FILE *fp = fopen(priv_file, "w");
    if (!fp) {
        perror("Failed to create private key file");
        free(priv_pem); free(pub_pem);
        return 1;
    }
    fputs(priv_pem, fp);
    fclose(fp);
    printf("Private key written to: %s\n", priv_file);
    
    fp = fopen(pub_file, "w");
    if (!fp) {
        perror("Failed to create public key file");
        free(priv_pem); free(pub_pem);
        return 1;
    }
    fputs(pub_pem, fp);
    fclose(fp);
    printf("Public key written to: %s\n", pub_file);
    
    secure_wipe(priv_pem, strlen(priv_pem));
    free(priv_pem);
    free(pub_pem);
    
    printf("\nDone! You can now run setup:\n");
    printf("  ./bin/irchub <password> -setup\n");
    return 0;
}
