#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>

#include <oqs/oqs.h>
#include <curl/curl.h>
#include <openssl/sha.h>


#include "crow.h"


// ============================================================
// CURL RESPONSE CALLBACK
// ============================================================

static size_t write_callback(
    void* contents,
    size_t size,
    size_t nmemb,
    void* userp)
{
    size_t total_size = size * nmemb;

    std::string* response =
        static_cast<std::string*>(userp);

    response->append(
        static_cast<char*>(contents),
        total_size
    );

    return total_size;
}


// ============================================================
// HEX -> BYTES
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

    output.reserve(
        hex.length() / 2
    );


    for (size_t i = 0; i < hex.length(); i += 2)
    {
        unsigned int value = 0;

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
// BYTES -> HEX
// ============================================================

static std::string bytes_to_hex(
    const unsigned char* data,
    size_t length)
{
    static const char hex_chars[] =
        "0123456789abcdef";

    std::string result;

    result.reserve(
        length * 2
    );


    for (size_t i = 0; i < length; ++i)
    {
        result.push_back(
            hex_chars[
                (data[i] >> 4) & 0x0F
            ]
        );

        result.push_back(
            hex_chars[
                data[i] & 0x0F
            ]
        );
    }


    return result;
}


// ============================================================
// SHA-256
// ============================================================

static std::string sha256_hex(
    const std::vector<unsigned char>& data)
{
    unsigned char hash[
        SHA256_DIGEST_LENGTH
    ];


    SHA256(
        data.data(),
        data.size(),
        hash
    );


    return bytes_to_hex(
        hash,
        SHA256_DIGEST_LENGTH
    );
}


// ============================================================
// HTTP GET
// ============================================================

static bool http_get(
    const std::string& url,
    std::string& response)
{
    CURL* curl =
        curl_easy_init();


    if (!curl)
    {
        return false;
    }


    curl_easy_setopt(
        curl,
        CURLOPT_URL,
        url.c_str()
    );


    curl_easy_setopt(
        curl,
        CURLOPT_WRITEFUNCTION,
        write_callback
    );


    curl_easy_setopt(
        curl,
        CURLOPT_WRITEDATA,
        &response
    );


    curl_easy_setopt(
        curl,
        CURLOPT_TIMEOUT,
        5L
    );


    CURLcode result =
        curl_easy_perform(curl);


    curl_easy_cleanup(curl);


    return result == CURLE_OK;
}


// ============================================================
// HTTP POST
// ============================================================

static bool http_post(
    const std::string& url,
    const std::string& body,
    std::string& response)
{
    CURL* curl =
        curl_easy_init();


    if (!curl)
    {
        return false;
    }


    struct curl_slist* headers =
        nullptr;


    headers =
        curl_slist_append(
            headers,
            "Content-Type: application/json"
        );


    curl_easy_setopt(
        curl,
        CURLOPT_URL,
        url.c_str()
    );


    curl_easy_setopt(
        curl,
        CURLOPT_HTTPHEADER,
        headers
    );


    curl_easy_setopt(
        curl,
        CURLOPT_POST,
        1L
    );


    curl_easy_setopt(
        curl,
        CURLOPT_POSTFIELDS,
        body.c_str()
    );


    curl_easy_setopt(
        curl,
        CURLOPT_WRITEFUNCTION,
        write_callback
    );


    curl_easy_setopt(
        curl,
        CURLOPT_WRITEDATA,
        &response
    );


    curl_easy_setopt(
        curl,
        CURLOPT_TIMEOUT,
        5L
    );


    CURLcode result =
        curl_easy_perform(curl);


    curl_slist_free_all(headers);

    curl_easy_cleanup(curl);


    return result == CURLE_OK;
}


// ============================================================
// MAIN
// ============================================================

int main()
{
    std::cout
        << "=====================================\n"
        << " PQC Test Client\n"
        << "=====================================\n";


    curl_global_init(
        CURL_GLOBAL_DEFAULT
    );


    // ========================================================
    // STEP 1: GET PQC INFORMATION
    // ========================================================

    std::cout
        << "[1] Requesting gateway PQC information...\n";


    std::string info_response;


    if (!http_get(
            "http://127.0.0.1:8080/pq/info",
            info_response))
    {
        std::cerr
            << "[ERROR] Could not contact gateway\n";

        curl_global_cleanup();

        return 1;
    }


    std::cout
        << "[OK] Gateway responded\n";


    auto info =
        crow::json::load(
            info_response
        );


    if (!info)
    {
        std::cerr
            << "[ERROR] Invalid gateway JSON\n";

        curl_global_cleanup();

        return 1;
    }


    // ========================================================
    // READ ALGORITHMS AND PUBLIC KEYS
    // ========================================================

    std::string kem_algorithm =
        info["kem_algorithm"].s();


    std::string signature_algorithm =
        info["signature_algorithm"].s();


    std::string kem_public_key_hex =
        info["kem_public_key"].s();


    std::string signature_public_key_hex =
        info["signature_public_key"].s();


    std::cout
        << "[INFO] KEM: "
        << kem_algorithm
        << "\n";


    std::cout
        << "[INFO] Signature: "
        << signature_algorithm
        << "\n";


    std::cout
        << "[OK] ML-KEM public key received\n";


    std::cout
        << "[OK] ML-DSA public key received\n";


    // ========================================================
    // STEP 2: CONVERT ML-KEM PUBLIC KEY
    // ========================================================

    std::vector<unsigned char>
        kem_public_key;


    if (!hex_to_bytes(
            kem_public_key_hex,
            kem_public_key))
    {
        std::cerr
            << "[ERROR] Invalid ML-KEM public key\n";

        curl_global_cleanup();

        return 1;
    }


    // ========================================================
    // CREATE ML-KEM-768
    // ========================================================

    OQS_KEM* kem =
        OQS_KEM_new(
            OQS_KEM_alg_ml_kem_768
        );


    if (!kem)
    {
        std::cerr
            << "[ERROR] Could not initialize ML-KEM-768\n";

        curl_global_cleanup();

        return 1;
    }


    if (kem_public_key.size() !=
        kem->length_public_key)
    {
        std::cerr
            << "[ERROR] Incorrect ML-KEM public key size\n";

        OQS_KEM_free(kem);

        curl_global_cleanup();

        return 1;
    }


    // ========================================================
    // STEP 3: ML-KEM ENCAPSULATION
    // ========================================================

    std::cout
        << "[2] Performing ML-KEM-768 encapsulation...\n";


    std::vector<unsigned char>
        ciphertext(
            kem->length_ciphertext
        );


    std::vector<unsigned char>
        client_shared_secret(
            kem->length_shared_secret
        );


    OQS_STATUS kem_result =
        OQS_KEM_encaps(
            kem,
            ciphertext.data(),
            client_shared_secret.data(),
            kem_public_key.data()
        );


    if (kem_result != OQS_SUCCESS)
    {
        std::cerr
            << "[ERROR] ML-KEM encapsulation failed\n";

        OQS_KEM_free(kem);

        curl_global_cleanup();

        return 1;
    }


    std::cout
        << "[OK] ML-KEM encapsulation successful\n";


    // ========================================================
    // CREATE CIPHERTEXT HEX
    // ========================================================

    std::string ciphertext_hex =
        bytes_to_hex(
            ciphertext.data(),
            ciphertext.size()
        );


    // ========================================================
    // CALCULATE CLIENT SECRET FINGERPRINT
    // ========================================================

    std::string client_secret_fingerprint =
        sha256_hex(
            client_shared_secret
        );


    std::cout
        << "[OK] Client shared secret generated\n";


    std::cout
        << "[INFO] Client secret SHA-256: "
        << client_secret_fingerprint
        << "\n";


    // ========================================================
    // STEP 4: SEND CIPHERTEXT TO GATEWAY
    // ========================================================

    std::cout
        << "[3] Sending ciphertext to gateway...\n";


    crow::json::wvalue request_body;


    request_body["ciphertext"] =
        ciphertext_hex;


    std::string request_json =
        request_body.dump();


    std::string handshake_response;


    if (!http_post(
            "http://127.0.0.1:8080/pq/handshake",
            request_json,
            handshake_response))
    {
        std::cerr
            << "[ERROR] Handshake request failed\n";

        OQS_KEM_free(kem);

        curl_global_cleanup();

        return 1;
    }


    std::cout
        << "[OK] Gateway responded\n";


    // ========================================================
    // PARSE HANDSHAKE RESPONSE
    // ========================================================

    auto handshake =
        crow::json::load(
            handshake_response
        );


    if (!handshake)
    {
        std::cerr
            << "[ERROR] Invalid handshake response\n";

        OQS_KEM_free(kem);

        curl_global_cleanup();

        return 1;
    }


    if (!handshake.has("handshake"))
    {
        std::cerr
            << "[ERROR] Handshake result missing\n";

        OQS_KEM_free(kem);

        curl_global_cleanup();

        return 1;
    }


    std::string handshake_status =
        handshake["handshake"].s();


    std::cout
        << "[INFO] Handshake status: "
        << handshake_status
        << "\n";


    if (handshake_status != "success")
    {
        std::cerr
            << "[ERROR] PQC handshake failed\n";

        OQS_KEM_free(kem);

        curl_global_cleanup();

        return 1;
    }


    // ========================================================
    // STEP 5: VERIFY SHARED SECRET FINGERPRINT
    // ========================================================

    std::string gateway_secret_fingerprint =
        handshake["shared_secret_sha256"].s();


    std::cout
        << "[4] Comparing shared-secret fingerprints...\n";


    if (client_secret_fingerprint ==
        gateway_secret_fingerprint)
    {
        std::cout
            << "[PASS] Client and gateway have the same "
            << "shared secret\n";
    }
    else
    {
        std::cerr
            << "[FAIL] Shared-secret fingerprints do not match\n";

        OQS_KEM_free(kem);

        curl_global_cleanup();

        return 1;
    }


    // ========================================================
    // STEP 6: CONVERT ML-DSA PUBLIC KEY
    // ========================================================

    std::vector<unsigned char>
        signature_public_key;


    if (!hex_to_bytes(
            signature_public_key_hex,
            signature_public_key))
    {
        std::cerr
            << "[ERROR] Invalid ML-DSA public key\n";

        OQS_KEM_free(kem);

        curl_global_cleanup();

        return 1;
    }


    // ========================================================
    // CONVERT SIGNATURE
    // ========================================================

    std::string signature_hex =
        handshake["signature"].s();


    std::vector<unsigned char>
        signature;


    if (!hex_to_bytes(
            signature_hex,
            signature))
    {
        std::cerr
            << "[ERROR] Invalid ML-DSA signature\n";

        OQS_KEM_free(kem);

        curl_global_cleanup();

        return 1;
    }


    // ========================================================
    // STEP 7: RECREATE HANDSHAKE TRANSCRIPT
    // ========================================================

    std::string transcript =
        "Post-Quantum API Gateway|"
        "ML-KEM-768|"
        + client_secret_fingerprint;


    // ========================================================
    // STEP 8: ML-DSA-65 SIGNATURE VERIFICATION
    // ========================================================

    std::cout
        << "[5] Verifying ML-DSA-65 signature...\n";


    OQS_SIG* sig =
        OQS_SIG_new(
            OQS_SIG_alg_ml_dsa_65
        );


    if (!sig)
    {
        std::cerr
            << "[ERROR] Could not initialize ML-DSA-65\n";

        OQS_KEM_free(kem);

        curl_global_cleanup();

        return 1;
    }


    if (signature_public_key.size() !=
        sig->length_public_key)
    {
        std::cerr
            << "[ERROR] Incorrect ML-DSA public key size\n";

        OQS_SIG_free(sig);

        OQS_KEM_free(kem);

        curl_global_cleanup();

        return 1;
    }


    OQS_STATUS verify_result =
        OQS_SIG_verify(
            sig,
            reinterpret_cast<const unsigned char*>(
                transcript.data()
            ),
            transcript.size(),
            signature.data(),
            signature.size(),
            signature_public_key.data()
        );


    if (verify_result != OQS_SUCCESS)
    {
        std::cerr
            << "[FAIL] ML-DSA-65 signature verification failed\n";

        OQS_SIG_free(sig);

        OQS_KEM_free(kem);

        curl_global_cleanup();

        return 1;
    }


    std::cout
        << "[PASS] ML-DSA-65 signature verified\n";


    // ========================================================
    // FINAL RESULT
    // ========================================================

    std::cout
        << "\n=====================================\n"
        << " PQC HANDSHAKE FULLY VERIFIED\n"
        << "=====================================\n";

    std::cout
        << " ML-KEM-768 encapsulation : PASS\n";

    std::cout
        << " Gateway decapsulation    : PASS\n";

    std::cout
        << " Shared secret match      : PASS\n";

    std::cout
        << " ML-DSA-65 signing        : PASS\n";

    std::cout
        << " ML-DSA-65 verification   : PASS\n";

    std::cout
        << "=====================================\n";


    // ========================================================
    // CLEANUP
    // ========================================================

    OQS_SIG_free(sig);

    OQS_KEM_free(kem);

    curl_global_cleanup();


    return 0;
}