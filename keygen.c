#include "hub.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void hub_log(const char *format, ...) {
    (void)format;
}

int main(int argc, char *argv[]) {
    unsigned char priv64[64], pub64[64];

    printf("Generating Curve25519 keypair (Ed25519 + X25519)...\n");

    if (!hub_crypto_generate_combined_keypair(priv64, pub64)) {
        fprintf(stderr, "Key generation failed\n");
        return 1;
    }

    char *priv_b64 = base64_encode(priv64, 64);
    char *pub_b64  = base64_encode(pub64,  64);
    secure_wipe(priv64, 64);

    if (!priv_b64 || !pub_b64) {
        fprintf(stderr, "Base64 encoding failed\n");
        if (priv_b64) free(priv_b64);
        if (pub_b64)  free(pub_b64);
        return 1;
    }

    const char *priv_file = (argc > 1) ? argv[1] : "hub_private.b64";
    const char *pub_file  = (argc > 2) ? argv[2] : "hub_public.b64";

    FILE *fp = fopen(priv_file, "w");
    if (!fp) {
        perror("Failed to create private key file");
        secure_wipe(priv_b64, strlen(priv_b64));
        free(priv_b64); free(pub_b64);
        return 1;
    }
    fprintf(fp, "%s\n", priv_b64);
    fclose(fp);
    printf("Private key written to: %s\n", priv_file);

    fp = fopen(pub_file, "w");
    if (!fp) {
        perror("Failed to create public key file");
        secure_wipe(priv_b64, strlen(priv_b64));
        free(priv_b64); free(pub_b64);
        return 1;
    }
    fprintf(fp, "%s\n", pub_b64);
    fclose(fp);
    printf("Public key written to: %s\n", pub_file);

    secure_wipe(priv_b64, strlen(priv_b64));
    free(priv_b64);
    free(pub_b64);

    printf("\nDone! You can now run setup:\n");
    printf("  ./bin/irchub -setup\n");
    printf("\nUse hub_public.b64 with hub_admin:\n");
    printf("  ./bin/hub_admin <ip> <port> hub_public.b64\n");
    return 0;
}
