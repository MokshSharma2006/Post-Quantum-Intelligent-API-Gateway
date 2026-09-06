#include "pqc_manager.hpp"

#include <oqs/oqs.h>

#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>


// ============================================================
// HEX ENCODING
// ============================================================

static std::string bytes_to_hex(
    const unsigned char* data,
    size_t length)
{
    std::ostringstream output;

    for (size_t i = 0; i < length; ++i)
    {
        output << std::hex
               << std::setw(2)
               << std::setfill('0')
               << static_cast<int>(data[i]);
    }

    return output.str();
}


// ============================================================
// HEX DECODING
// ============================================================

static bool hex_to_bytes(
    const std::string& hex,
    std::vector<unsigned char>& output)
{
    if (hex.length() % 2 != 0)
    {
        return false;
    }

    output.clear();

    output.reserve(hex.length() / 2);


    for (size_t i = 0; i < hex.length(); i += 2)
    {
        unsigned int value;

        std::stringstream stream;

        stream << std::hex
               << hex.substr(i, 2);

        stream >> value;

        if (stream.fail())
        {
            return false;
        }

        output.push_back(
            static_cast<unsigned char>(value)
        );
    }

    return true;
}


// ============================================================
// CONSTRUCTOR
// ============================================================

PQCManager::PQCManager()
{
    initialize();
}


// ============================================================
// INITIALIZE PQC
// ============================================================

bool PQCManager::initialize()
{
    std::cout
        << "[PQC] Initializing post-quantum cryptography...\n";


    // ========================================================
    // ML-KEM-768
    // ========================================================

    OQS_KEM* kem =
        OQS_KEM_new(OQS_KEM_alg_ml_kem_768);


    if (kem == nullptr)
    {
        std::cerr
            << "[PQC] ERROR: ML-KEM-768 initialization failed\n";

        return false;
    }


    kem_public_key.resize(
        kem->length_public_key
    );

    kem_secret_key.resize(
        kem->length_secret_key
    );


    if (OQS_KEM_keypair(
            kem,
            kem_public_key.data(),
            kem_secret_key.data()
        ) != OQS_SUCCESS)
    {
        std::cerr
            << "[PQC] ERROR: ML-KEM-768 key generation failed\n";

        OQS_KEM_free(kem);

        return false;
    }


    std::cout
        << "[PQC] ML-KEM-768 keypair generated\n";


    OQS_KEM_free(kem);


    // ========================================================
    // ML-DSA-65
    // ========================================================

    OQS_SIG* sig =
        OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);


    if (sig == nullptr)
    {
        std::cerr
            << "[PQC] ERROR: ML-DSA-65 initialization failed\n";

        return false;
    }


    sig_public_key.resize(
        sig->length_public_key
    );

    sig_secret_key.resize(
        sig->length_secret_key
    );


    if (OQS_SIG_keypair(
            sig,
            sig_public_key.data(),
            sig_secret_key.data()
        ) != OQS_SUCCESS)
    {
        std::cerr
            << "[PQC] ERROR: ML-DSA-65 key generation failed\n";

        OQS_SIG_free(sig);

        return false;
    }


    std::cout
        << "[PQC] ML-DSA-65 keypair generated\n";


    OQS_SIG_free(sig);


    initialized = true;


    std::cout
        << "[PQC] Post-quantum cryptography initialized successfully\n";


    return true;
}


// ============================================================
// GET ML-KEM PUBLIC KEY
// ============================================================

std::string PQCManager::get_kem_public_key_hex() const
{
    if (!initialized)
    {
        return "";
    }

    return bytes_to_hex(
        kem_public_key.data(),
        kem_public_key.size()
    );
}


// ============================================================
// GET ML-DSA PUBLIC KEY
// ============================================================

std::string PQCManager::get_signature_public_key_hex() const
{
    if (!initialized)
    {
        return "";
    }

    return bytes_to_hex(
        sig_public_key.data(),
        sig_public_key.size()
    );
}


// ============================================================
// ML-KEM DECAPSULATION
// ============================================================

bool PQCManager::decapsulate(
    const std::string& ciphertext_hex,
    std::vector<unsigned char>& shared_secret)
{
    if (!initialized)
    {
        return false;
    }


    // Convert hexadecimal ciphertext to bytes

    std::vector<unsigned char> ciphertext;

    if (!hex_to_bytes(
            ciphertext_hex,
            ciphertext))
    {
        return false;
    }


    // Create ML-KEM object

    OQS_KEM* kem =
        OQS_KEM_new(OQS_KEM_alg_ml_kem_768);


    if (kem == nullptr)
    {
        return false;
    }


    // Check ciphertext size

    if (ciphertext.size() !=
        kem->length_ciphertext)
    {
        OQS_KEM_free(kem);

        return false;
    }


    // Allocate shared secret

    shared_secret.resize(
        kem->length_shared_secret
    );


    // Perform decapsulation

    OQS_STATUS result =
        OQS_KEM_decaps(
            kem,
            shared_secret.data(),
            ciphertext.data(),
            kem_secret_key.data()
        );


    OQS_KEM_free(kem);


    if (result != OQS_SUCCESS)
    {
        shared_secret.clear();

        return false;
    }


    std::cout
        << "[PQC] ML-KEM-768 decapsulation successful\n";


    return true;
}


// ============================================================
// ML-DSA SIGN MESSAGE
// ============================================================

bool PQCManager::sign_message(
    const std::string& message,
    std::string& signature_hex)
{
    if (!initialized)
    {
        return false;
    }


    OQS_SIG* sig =
        OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);


    if (sig == nullptr)
    {
        return false;
    }


    std::vector<unsigned char> signature(
        sig->length_signature
    );


    size_t signature_length = 0;


    OQS_STATUS result =
        OQS_SIG_sign(
            sig,
            signature.data(),
            &signature_length,
            reinterpret_cast<const unsigned char*>(
                message.data()
            ),
            message.size(),
            sig_secret_key.data()
        );


    if (result != OQS_SUCCESS)
    {
        OQS_SIG_free(sig);

        return false;
    }


    signature_hex =
        bytes_to_hex(
            signature.data(),
            signature_length
        );


    OQS_SIG_free(sig);


    std::cout
        << "[PQC] ML-DSA-65 signature generated\n";


    return true;
}


// ============================================================
// ALGORITHM INFORMATION
// ============================================================

std::string PQCManager::get_kem_algorithm() const
{
    return "ML-KEM-768";
}


std::string PQCManager::get_signature_algorithm() const
{
    return "ML-DSA-65";
}


// ============================================================
// STATUS
// ============================================================

std::string PQCManager::get_status() const
{
    if (initialized)
    {
        return "initialized";
    }

    return "not_initialized";
}


// ============================================================
// INITIALIZATION CHECK
// ============================================================

bool PQCManager::is_initialized() const
{
    return initialized;
}