#include <iostream>
#include <vector>
#include <cstring>
#include <oqs/oqs.h>

int main() {

    std::cout << "=====================================\n";
    std::cout << " Post-Quantum Cryptography Test\n";
    std::cout << "=====================================\n\n";

    // =========================================================
    // ML-KEM-768 TEST
    // =========================================================

    std::cout << "[1] Testing ML-KEM-768...\n";

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);

    if (kem == nullptr) {
        std::cerr << "ERROR: ML-KEM-768 is not available.\n";
        return 1;
    }

    std::vector<uint8_t> public_key(kem->length_public_key);
    std::vector<uint8_t> secret_key(kem->length_secret_key);
    std::vector<uint8_t> ciphertext(kem->length_ciphertext);
    std::vector<uint8_t> shared_secret_enc(kem->length_shared_secret);
    std::vector<uint8_t> shared_secret_dec(kem->length_shared_secret);

    // Generate keypair
    if (OQS_KEM_keypair(
            kem,
            public_key.data(),
            secret_key.data()) != OQS_SUCCESS) {

        std::cerr << "ERROR: ML-KEM key generation failed.\n";
        OQS_KEM_free(kem);
        return 1;
    }

    // Encapsulation
    if (OQS_KEM_encaps(
            kem,
            ciphertext.data(),
            shared_secret_enc.data(),
            public_key.data()) != OQS_SUCCESS) {

        std::cerr << "ERROR: ML-KEM encapsulation failed.\n";
        OQS_KEM_free(kem);
        return 1;
    }

    // Decapsulation
    if (OQS_KEM_decaps(
            kem,
            shared_secret_dec.data(),
            ciphertext.data(),
            secret_key.data()) != OQS_SUCCESS) {

        std::cerr << "ERROR: ML-KEM decapsulation failed.\n";
        OQS_KEM_free(kem);
        return 1;
    }

    // Verify shared secrets
    if (std::memcmp(
            shared_secret_enc.data(),
            shared_secret_dec.data(),
            kem->length_shared_secret) != 0) {

        std::cerr << "ERROR: Shared secrets do not match.\n";
        OQS_KEM_free(kem);
        return 1;
    }

    std::cout << "    ✓ ML-KEM-768 key generation: PASS\n";
    std::cout << "    ✓ Encapsulation: PASS\n";
    std::cout << "    ✓ Decapsulation: PASS\n";
    std::cout << "    ✓ Shared secret verification: PASS\n";

    OQS_KEM_free(kem);


    // =========================================================
    // ML-DSA-65 TEST
    // =========================================================

    std::cout << "\n[2] Testing ML-DSA-65...\n";

    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);

    if (sig == nullptr) {
        std::cerr << "ERROR: ML-DSA-65 is not available.\n";
        return 1;
    }

    std::vector<uint8_t> sig_public_key(sig->length_public_key);
    std::vector<uint8_t> sig_secret_key(sig->length_secret_key);
    std::vector<uint8_t> signature(sig->length_signature);

    const char *message =
        "Post-Quantum API Gateway Authentication Test";

    size_t signature_length = 0;

    // Generate signing keypair
    if (OQS_SIG_keypair(
            sig,
            sig_public_key.data(),
            sig_secret_key.data()) != OQS_SUCCESS) {

        std::cerr << "ERROR: ML-DSA key generation failed.\n";
        OQS_SIG_free(sig);
        return 1;
    }

    // Sign message
    if (OQS_SIG_sign(
            sig,
            signature.data(),
            &signature_length,
            reinterpret_cast<const uint8_t*>(message),
            std::strlen(message),
            sig_secret_key.data()) != OQS_SUCCESS) {

        std::cerr << "ERROR: ML-DSA signing failed.\n";
        OQS_SIG_free(sig);
        return 1;
    }

    // Verify signature
    if (OQS_SIG_verify(
            sig,
            reinterpret_cast<const uint8_t*>(message),
            std::strlen(message),
            signature.data(),
            signature_length,
            sig_public_key.data()) != OQS_SUCCESS) {

        std::cerr << "ERROR: ML-DSA signature verification failed.\n";
        OQS_SIG_free(sig);
        return 1;
    }

    std::cout << "    ✓ ML-DSA-65 key generation: PASS\n";
    std::cout << "    ✓ Signing: PASS\n";
    std::cout << "    ✓ Signature verification: PASS\n";

    OQS_SIG_free(sig);


    // =========================================================
    // FINAL RESULT
    // =========================================================

    std::cout << "\n=====================================\n";
    std::cout << " ALL PQC TESTS PASSED\n";
    std::cout << "=====================================\n";

    return 0;
}
