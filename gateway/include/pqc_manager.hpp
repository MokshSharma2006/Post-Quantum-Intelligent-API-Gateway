#pragma once

#include <string>
#include <vector>


class PQCManager
{
private:

    // ========================================================
    // ML-KEM-768
    // ========================================================

    std::vector<unsigned char> kem_public_key;
    std::vector<unsigned char> kem_secret_key;


    // ========================================================
    // ML-DSA-65
    // ========================================================

    std::vector<unsigned char> sig_public_key;
    std::vector<unsigned char> sig_secret_key;


    // ========================================================
    // INITIALIZATION STATE
    // ========================================================

    bool initialized = false;


public:

    // ========================================================
    // CONSTRUCTOR
    // ========================================================

    PQCManager();


    // ========================================================
    // INITIALIZATION
    // ========================================================

    bool initialize();


    // ========================================================
    // ML-KEM PUBLIC KEY
    // ========================================================

    std::string get_kem_public_key_hex() const;


    // ========================================================
    // ML-DSA PUBLIC KEY
    // ========================================================

    std::string get_signature_public_key_hex() const;


    // ========================================================
    // ML-KEM DECAPSULATION
    // ========================================================

    bool decapsulate(
        const std::string& ciphertext_hex,
        std::vector<unsigned char>& shared_secret
    );


    // ========================================================
    // ML-DSA SIGNATURE
    // ========================================================

    bool sign_message(
        const std::string& message,
        std::string& signature_hex
    );


    // ========================================================
    // ALGORITHM INFORMATION
    // ========================================================

    std::string get_kem_algorithm() const;

    std::string get_signature_algorithm() const;


    // ========================================================
    // STATUS
    // ========================================================

    std::string get_status() const;

    bool is_initialized() const;
};