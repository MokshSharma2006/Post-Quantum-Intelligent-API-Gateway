#include <crow.h>

#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>
#include <regex>
#include <utility>

#include <curl/curl.h>
#include <openssl/sha.h>

#include "rate_limiter.hpp"
#include "security_metrics.hpp"
#include "pqc_manager.hpp"
#include "zmq_client.hpp"
#include "ai_enforcement.hpp"
#include "ai_decision_receiver.hpp"


// ============================================================
// CONFIGURATION
// ============================================================

const std::string BACKEND_URL =
    "http://127.0.0.1:5000";


// ============================================================
// GLOBAL COMPONENTS
// ============================================================

RateLimiter rate_limiter(
    20.0,
    10.0
);

SecurityMetrics metrics;

PQCManager pqc_manager;

ZMQClient zmq_client;

AIEnforcement ai_enforcement;

AIDecisionReceiver ai_receiver(
    ai_enforcement
);


// ============================================================
// CORS MIDDLEWARE
// ============================================================

struct CORSMiddleware
{
    struct context
    {
    };

    void before_handle(
        crow::request&,
        crow::response&,
        context&
    )
    {
    }

    void after_handle(
        crow::request&,
        crow::response& response,
        context&
    )
    {
        response.set_header(
            "Access-Control-Allow-Origin",
            "*"
        );

        response.set_header(
            "Access-Control-Allow-Methods",
            "GET, POST, OPTIONS"
        );

        response.set_header(
            "Access-Control-Allow-Headers",
            "Content-Type"
        );
    }
};


// ============================================================
// SHA-256 HELPER
// ============================================================

std::string sha256_hex(
    const std::vector<unsigned char>& data
)
{
    unsigned char hash[
        SHA256_DIGEST_LENGTH
    ];

    SHA256(
        data.data(),
        data.size(),
        hash
    );

    std::stringstream ss;

    for (
        int i = 0;
        i < SHA256_DIGEST_LENGTH;
        i++
    )
    {
        ss
            << std::hex
            << std::setw(2)
            << std::setfill('0')
            << static_cast<int>(hash[i]);
    }

    return ss.str();
}


// ============================================================
// JSON STRING ESCAPING
// ============================================================

std::string escape_json_string(
    const std::string& input
)
{
    std::string output;

    output.reserve(
        input.size() + 20
    );

    for (char c : input)
    {
        switch (c)
        {
            case '"':
                output += "\\\"";
                break;

            case '\\':
                output += "\\\\";
                break;

            case '\n':
                output += "\\n";
                break;

            case '\r':
                output += "\\r";
                break;

            case '\t':
                output += "\\t";
                break;

            default:
                output += c;
                break;
        }
    }

    return output;
}


// ============================================================
// SANITIZE REQUEST BODY
//
// Redacts common sensitive JSON fields before sending the
// request information to the AI engine / Gemini.
//
// This is a demonstration-level sanitizer. Production systems
// should use structured request parsing and a comprehensive
// secret-redaction policy.
// ============================================================

std::string sanitize_request_body(
    const std::string& original_body
)
{
    if (original_body.empty())
    {
        return "";
    }

    // --------------------------------------------------------
    // Limit body size sent to AI
    // --------------------------------------------------------

    std::string body =
        original_body.substr(
            0,
            2000
        );


    // --------------------------------------------------------
    // Common sensitive JSON fields
    // --------------------------------------------------------

    const std::vector<std::string> sensitive_fields =
    {
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "authorization",
        "access_token",
        "refresh_token",
        "cookie"
    };


    // --------------------------------------------------------
    // Redact quoted JSON values
    //
    // Example:
    //
    // "password":"hello"
    //
    // becomes:
    //
    // "password":"[REDACTED]"
    // --------------------------------------------------------

    for (
        const std::string& field :
        sensitive_fields
    )
    {
        try
        {
            std::regex pattern(
                "(\"" +
                field +
                "\"\\s*:\\s*\")([^\"]*)(\")",
                std::regex_constants::icase
            );

            body =
                std::regex_replace(
                    body,
                    pattern,
                    "$1[REDACTED]$3"
                );
        }
        catch (...)
        {
            // Continue safely if a regex operation fails
        }
    }


    return body;
}


// ============================================================
// BUILD AI EVENT
// ============================================================

std::string build_ai_event(
    const std::string& endpoint,
    const std::string& client_ip,
    const std::string& method,
    const std::string& request_body
)
{
    std::string sanitized_body =
        sanitize_request_body(
            request_body
        );

    std::string event =
        "{"
        "\"endpoint\":\""
        + escape_json_string(endpoint)
        + "\","
        "\"client_ip\":\""
        + escape_json_string(client_ip)
        + "\","
        "\"method\":\""
        + escape_json_string(method)
        + "\","
        "\"request_body\":\""
        + escape_json_string(sanitized_body)
        + "\""
        "}";

    return event;
}


// ============================================================
// CURL RESPONSE CALLBACK
// ============================================================

size_t write_callback(
    void* contents,
    size_t size,
    size_t nmemb,
    void* userp
)
{
    size_t total_size =
        size * nmemb;

    std::string* response =
        static_cast<std::string*>(
            userp
        );

    response->append(
        static_cast<char*>(contents),
        total_size
    );

    return total_size;
}


// ============================================================
// BACKEND PROXY
// ============================================================

crow::response proxy_to_backend(
    const crow::request& req,
    const std::string& endpoint
)
{
    CURL* curl =
        curl_easy_init();

    if (!curl)
    {
        return crow::response(
            500,
            "Backend proxy initialization failed"
        );
    }

    std::string response_body;

    std::string url =
        BACKEND_URL +
        endpoint;


    // --------------------------------------------------------
    // URL
    // --------------------------------------------------------

    curl_easy_setopt(
        curl,
        CURLOPT_URL,
        url.c_str()
    );


    // --------------------------------------------------------
    // Response callback
    // --------------------------------------------------------

    curl_easy_setopt(
        curl,
        CURLOPT_WRITEFUNCTION,
        write_callback
    );

    curl_easy_setopt(
        curl,
        CURLOPT_WRITEDATA,
        &response_body
    );


    // --------------------------------------------------------
    // Timeout
    // --------------------------------------------------------

    curl_easy_setopt(
        curl,
        CURLOPT_TIMEOUT,
        10L
    );


    // --------------------------------------------------------
    // Headers
    // --------------------------------------------------------

    struct curl_slist* headers =
        nullptr;

    headers =
        curl_slist_append(
            headers,
            "Content-Type: application/json"
        );

    curl_easy_setopt(
        curl,
        CURLOPT_HTTPHEADER,
        headers
    );


    // --------------------------------------------------------
    // POST
    // --------------------------------------------------------

    if (
        req.method ==
        crow::HTTPMethod::POST
    )
    {
        curl_easy_setopt(
            curl,
            CURLOPT_POST,
            1L
        );

        curl_easy_setopt(
            curl,
            CURLOPT_POSTFIELDS,
            req.body.c_str()
        );

        curl_easy_setopt(
            curl,
            CURLOPT_POSTFIELDSIZE,
            static_cast<long>(
                req.body.size()
            )
        );
    }


    // --------------------------------------------------------
    // GET
    // --------------------------------------------------------

    else
    {
        curl_easy_setopt(
            curl,
            CURLOPT_HTTPGET,
            1L
        );
    }


    // --------------------------------------------------------
    // Execute
    // --------------------------------------------------------

    CURLcode result =
        curl_easy_perform(
            curl
        );

    long http_code = 500;

    if (
        result ==
        CURLE_OK
    )
    {
        curl_easy_getinfo(
            curl,
            CURLINFO_RESPONSE_CODE,
            &http_code
        );
    }


    // --------------------------------------------------------
    // Cleanup CURL
    // --------------------------------------------------------

    curl_slist_free_all(
        headers
    );

    curl_easy_cleanup(
        curl
    );


    // --------------------------------------------------------
    // Backend error
    // --------------------------------------------------------

    if (
        result !=
        CURLE_OK
    )
    {
        std::cerr
            << "[BACKEND ERROR] "
            << curl_easy_strerror(
                result
            )
            << std::endl;

        return crow::response(
            502,
            "Backend unavailable"
        );
    }


    // --------------------------------------------------------
    // Return backend response
    // --------------------------------------------------------

    crow::response response(
        static_cast<int>(
            http_code
        ),
        response_body
    );

    response.set_header(
        "Content-Type",
        "application/json"
    );

    return response;
}


// ============================================================
// MAIN
// ============================================================

int main()
{
    std::cout
        << "====================================="
        << std::endl;

    std::cout
        << " Post-Quantum AI-Powered API Gateway"
        << std::endl;

    std::cout
        << "====================================="
        << std::endl;


    // ========================================================
    // CURL INITIALIZATION
    // ========================================================

    curl_global_init(
        CURL_GLOBAL_DEFAULT
    );


    // ========================================================
    // START AI RECEIVER
    // ========================================================

    ai_receiver.start();


    // ========================================================
    // STARTUP INFORMATION
    // ========================================================

    std::cout
        << " Gateway       : "
           "http://0.0.0.0:8080"
        << std::endl;

    std::cout
        << " Backend       : "
        << BACKEND_URL
        << std::endl;

    std::cout
        << " Rate Limiter  : ENABLED"
        << std::endl;

    std::cout
        << " Capacity      : 20 requests"
        << std::endl;

    std::cout
        << " Refill Rate   : 10 requests/sec"
        << std::endl;

    std::cout
        << " Metrics       : ENABLED"
        << std::endl;

    std::cout
        << " PQC           : ENABLED"
        << std::endl;

    std::cout
        << " KEM           : ML-KEM-768"
        << std::endl;

    std::cout
        << " Signature     : ML-DSA-65"
        << std::endl;

    std::cout
        << " ZeroMQ        : ENABLED"
        << std::endl;

    std::cout
        << " AI Engine     : "
           "tcp://127.0.0.1:5555"
        << std::endl;

    std::cout
        << " AI Receiver   : "
           "tcp://127.0.0.1:5556"
        << std::endl;

    std::cout
        << " AI Enforcement: ENABLED"
        << std::endl;

    std::cout
        << " CORS          : ENABLED"
        << std::endl;

    std::cout
        << " AI Body Scan  : ENABLED"
        << std::endl;

    std::cout
        << " Body Limit    : 2000 bytes"
        << std::endl;

    std::cout
        << " Secret Redact : ENABLED"
        << std::endl;

    std::cout
        << "====================================="
        << std::endl;


    // ========================================================
    // CROW APPLICATION
    // ========================================================

    crow::App<CORSMiddleware> app;


    // ========================================================
    // ROOT
    // ========================================================

    CROW_ROUTE(
        app,
        "/"
    )
    ([]()
    {
        crow::json::wvalue response;

        response["service"] =
            "Post-Quantum AI-Powered API Gateway";

        response["status"] =
            "running";

        response["version"] =
            "1.0";

        response["pqc"] =
            "enabled";

        response["ai_security"] =
            "enabled";

        response["ai_enforcement"] =
            "enabled";

        response["rate_limiter"] =
            "enabled";

        response["zeromq"] =
            "enabled";

        response["ai_body_scan"] =
            "enabled";

        return crow::response(
            response
        );
    });


    // ========================================================
    // HEALTH
    // ========================================================

    CROW_ROUTE(
        app,
        "/health"
    )
    ([]()
    {
        crow::json::wvalue response;

        response["gateway"] =
            "healthy";

        response["backend"] =
            "http://127.0.0.1:5000";

        response["rate_limiter"] =
            "enabled";

        response["metrics"] =
            "enabled";

        response["pqc"] =
            pqc_manager.is_initialized()
                ? "healthy"
                : "failed";

        response["kem"] =
            pqc_manager.get_kem_algorithm();

        response["signature"] =
            pqc_manager.get_signature_algorithm();

        response["zeromq"] =
            "enabled";

        response["ai_enforcement"] =
            "enabled";

        response["ai_body_scan"] =
            "enabled";

        response["blocked_clients"] =
            ai_enforcement.get_blocked_count();

        return crow::response(
            response
        );
    });


    // ========================================================
    // METRICS
    // ========================================================

    CROW_ROUTE(
        app,
        "/metrics"
    )
    ([]()
    {
        crow::json::wvalue response;

        // ----------------------------------------------------
        // Gateway metrics
        // ----------------------------------------------------

        response["total_requests"] =
            metrics.get_total_requests();

        response["allowed_requests"] =
            metrics.get_allowed_requests();

        response["blocked_requests"] =
            metrics.get_blocked_requests();

        response["requests_per_second"] =
            metrics.get_requests_per_second();


        // ----------------------------------------------------
        // AI metrics
        // ----------------------------------------------------

        response["ai_blocked_clients"] =
            ai_enforcement.get_blocked_count();

        response["ai_total_decisions"] =
            ai_enforcement.get_total_decisions();

        response["ai_normal"] =
            ai_enforcement.get_normal_decisions();

        response["ai_suspicious"] =
            ai_enforcement.get_suspicious_decisions();

        response["ai_malicious"] =
            ai_enforcement.get_malicious_decisions();

        response["ai_block_decisions"] =
            ai_enforcement.get_block_decisions();


        // ----------------------------------------------------
        // Last AI decision
        // ----------------------------------------------------

        response["ai_last_score"] =
            ai_enforcement.get_last_threat_score();

        response["ai_last_threat"] =
            ai_enforcement.get_last_threat_level();

        response["ai_last_action"] =
            ai_enforcement.get_last_action();


        // ----------------------------------------------------
        // LLM / Gemini information
        // ----------------------------------------------------

        response["llm_enabled"] =
            ai_enforcement.get_llm_enabled();

        response["llm_provider"] =
            ai_enforcement.get_llm_provider();

        response["llm_attack_type"] =
            ai_enforcement.get_last_attack_type();

        response["llm_severity"] =
            ai_enforcement.get_last_severity();

        response["llm_confidence"] =
            ai_enforcement.get_last_confidence();

        response["llm_recommendation"] =
            ai_enforcement.get_last_recommendation();

        response["llm_explanation"] =
            ai_enforcement.get_last_explanation();


        // ----------------------------------------------------
        // Payload analysis
        // ----------------------------------------------------

        response["payload_score"] =
            ai_enforcement.get_last_payload_score();

        auto indicators =
            ai_enforcement.get_last_payload_indicators();

        response["payload_indicators"] =
            indicators;


        // ----------------------------------------------------
        // Return JSON
        // ----------------------------------------------------

        return crow::response(
            response
        );
    });


    // ========================================================
    // PQC INFORMATION
    // ========================================================

    CROW_ROUTE(
        app,
        "/pq/info"
    )
    ([]()
    {
        crow::json::wvalue response;

        response["status"] =
            pqc_manager.get_status();

        response["initialized"] =
            pqc_manager.is_initialized();

        response["kem_algorithm"] =
            pqc_manager.get_kem_algorithm();

        response["signature_algorithm"] =
            pqc_manager.get_signature_algorithm();

        response["kem_public_key"] =
            pqc_manager.get_kem_public_key_hex();

        response["signature_public_key"] =
            pqc_manager.get_signature_public_key_hex();

        return crow::response(
            response
        );
    });


    // ========================================================
    // PQC HANDSHAKE
    // ========================================================

    CROW_ROUTE(
        app,
        "/pq/handshake"
    )
    .methods(
        crow::HTTPMethod::POST
    )
    ([](
        const crow::request& req
    )
    {
        try
        {
            auto body =
                crow::json::load(
                    req.body
                );

            if (!body)
            {
                return crow::response(
                    400,
                    "Invalid JSON"
                );
            }

            if (
                !body.has(
                    "ciphertext"
                )
            )
            {
                return crow::response(
                    400,
                    "Missing ciphertext"
                );
            }

            std::string ciphertext_hex =
                body["ciphertext"].s();

            std::vector<unsigned char>
                shared_secret;

            bool success =
                pqc_manager.decapsulate(
                    ciphertext_hex,
                    shared_secret
                );

            if (!success)
            {
                return crow::response(
                    400,
                    "PQC decapsulation failed"
                );
            }

            std::string fingerprint =
                sha256_hex(
                    shared_secret
                );

            std::string transcript =
                "Post-Quantum API Gateway"
                "|ML-KEM-768|"
                + fingerprint;

            std::string signature_hex;

            bool signed_success =
                pqc_manager.sign_message(
                    transcript,
                    signature_hex
                );

            if (!signed_success)
            {
                return crow::response(
                    500,
                    "ML-DSA signing failed"
                );
            }

            crow::json::wvalue response;

            response["handshake"] =
                "success";

            response["kem_algorithm"] =
                pqc_manager.get_kem_algorithm();

            response["signature_algorithm"] =
                pqc_manager.get_signature_algorithm();

            response["shared_secret_sha256"] =
                fingerprint;

            response["signature"] =
                signature_hex;

            return crow::response(
                response
            );
        }

        catch (
            const std::exception& e
        )
        {
            return crow::response(
                500,
                std::string(
                    "Handshake error: "
                ) + e.what()
            );
        }
    });


    // ========================================================
    // API HELLO
    // ========================================================

    CROW_ROUTE(
        app,
        "/api/hello"
    )
    .methods(
        crow::HTTPMethod::GET
    )
    ([](
        const crow::request& req
    )
    {
        std::string client_ip =
            req.remote_ip_address;


        // ----------------------------------------------------
        // Record request
        // ----------------------------------------------------

        metrics.record_request();


        // ----------------------------------------------------
        // AI blocklist
        // ----------------------------------------------------

        if (
            ai_enforcement.is_blocked(
                client_ip
            )
        )
        {
            metrics.record_blocked();

            std::cout
                << "[AI BLOCK] "
                << client_ip
                << " -> /api/hello"
                << std::endl;

            return crow::response(
                403,
                "Request blocked by AI security engine"
            );
        }


        // ----------------------------------------------------
        // Build AI event
        // ----------------------------------------------------

        std::string event =
            build_ai_event(
                "/api/hello",
                client_ip,
                "GET",
                ""
            );


        // ----------------------------------------------------
        // Send event to AI
        // ----------------------------------------------------

        zmq_client.send_event(
            event
        );


        // ----------------------------------------------------
        // Rate limit
        // ----------------------------------------------------

        if (
            !rate_limiter.allow_request(
                client_ip
            )
        )
        {
            metrics.record_blocked();

            std::cout
                << "[RATE LIMIT] "
                << client_ip
                << " -> /api/hello"
                << std::endl;

            return crow::response(
                429,
                "Too Many Requests"
            );
        }


        // ----------------------------------------------------
        // Allowed
        // ----------------------------------------------------

        metrics.record_allowed();

        return proxy_to_backend(
            req,
            "/api/hello"
        );
    });


    // ========================================================
    // API DATA
    // ========================================================

    CROW_ROUTE(
        app,
        "/api/data"
    )
    .methods(
        crow::HTTPMethod::GET,
        crow::HTTPMethod::POST
    )
    ([](
        const crow::request& req
    )
    {
        std::string client_ip =
            req.remote_ip_address;


        // ----------------------------------------------------
        // Record request
        // ----------------------------------------------------

        metrics.record_request();


        // ----------------------------------------------------
        // AI blocklist
        // ----------------------------------------------------

        if (
            ai_enforcement.is_blocked(
                client_ip
            )
        )
        {
            metrics.record_blocked();

            std::cout
                << "[AI BLOCK] "
                << client_ip
                << " -> /api/data"
                << std::endl;

            return crow::response(
                403,
                "Request blocked by AI security engine"
            );
        }


        // ----------------------------------------------------
        // Determine method
        // ----------------------------------------------------

        std::string method;

        if (
            req.method ==
            crow::HTTPMethod::POST
        )
        {
            method = "POST";
        }
        else
        {
            method = "GET";
        }


        // ----------------------------------------------------
        // Sanitize request body before AI transmission
        // ----------------------------------------------------

        std::string sanitized_body =
            sanitize_request_body(
                req.body
            );


        // ----------------------------------------------------
        // Send event to AI
        // ----------------------------------------------------

        std::string event =
            build_ai_event(
                "/api/data",
                client_ip,
                method,
                sanitized_body
            );


        zmq_client.send_event(
            event
        );


        // ----------------------------------------------------
        // Rate limit
        // ----------------------------------------------------

        if (
            !rate_limiter.allow_request(
                client_ip
            )
        )
        {
            metrics.record_blocked();

            std::cout
                << "[RATE LIMIT] "
                << client_ip
                << " -> /api/data"
                << std::endl;

            return crow::response(
                429,
                "Too Many Requests"
            );
        }


        // ----------------------------------------------------
        // Allowed
        // ----------------------------------------------------

        metrics.record_allowed();

        return proxy_to_backend(
            req,
            "/api/data"
        );
    });


    // ========================================================
    // START SERVER
    // ========================================================

    app.port(8080)
       .multithreaded()
       .run();


    // ========================================================
    // SHUTDOWN
    // ========================================================

    ai_receiver.stop();

    curl_global_cleanup();

    return 0;
}