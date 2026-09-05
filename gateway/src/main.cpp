#include <iostream>
#include <string>

#include "crow.h"
#include <curl/curl.h>


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
// FORWARD REQUEST TO BACKEND
// ============================================================

std::string forward_to_backend(
    const std::string& endpoint)
{
    CURL* curl = curl_easy_init();

    if (!curl)
    {
        return R"({"error":"Failed to initialize CURL"})";
    }

    std::string response;

    std::string url =
        "http://127.0.0.1:5000" + endpoint;

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

    if (result != CURLE_OK)
    {
        response =
            R"({"error":"Backend unavailable"})";
    }

    curl_easy_cleanup(curl);

    return response;
}


// ============================================================
// MAIN GATEWAY
// ============================================================

int main()
{
    curl_global_init(CURL_GLOBAL_DEFAULT);

    crow::SimpleApp app;


    // --------------------------------------------------------
    // Gateway root
    // --------------------------------------------------------

    CROW_ROUTE(app, "/")
    ([] {

        return crow::response(
            200,
            "Post-Quantum API Gateway is running!"
        );

    });


    // --------------------------------------------------------
    // Gateway health
    // --------------------------------------------------------

    CROW_ROUTE(app, "/health")
    ([] {

        crow::json::wvalue result;

        result["gateway"] = "healthy";
        result["backend"] = "http://127.0.0.1:5000";

        return crow::response(
            200,
            result
        );

    });


    // --------------------------------------------------------
    // Forward /api/hello
    // --------------------------------------------------------

    CROW_ROUTE(app, "/api/hello")
    ([] {

        std::string backend_response =
            forward_to_backend("/api/hello");

        return crow::response(
            200,
            backend_response
        );

    });


    // --------------------------------------------------------
    // Forward /api/data
    // --------------------------------------------------------

    CROW_ROUTE(app, "/api/data")
    ([] {

        std::string backend_response =
            forward_to_backend("/api/data");

        return crow::response(
            200,
            backend_response
        );

    });


    std::cout
        << "=====================================\n"
        << " Post-Quantum API Gateway\n"
        << "=====================================\n"
        << " Gateway : http://localhost:8080\n"
        << " Backend : http://localhost:5000\n"
        << "=====================================\n";


    app
        .port(8080)
        .multithreaded()
        .run();


    curl_global_cleanup();

    return 0;
}