#pragma once

#include <unordered_map>
#include <memory>
#include <mutex>
#include <string>

#include "token_bucket.hpp"


class RateLimiter
{
private:

    std::unordered_map<
        std::string,
        std::unique_ptr<TokenBucket>
    > clients;

    std::mutex clients_mutex;

    double bucket_capacity;
    double refill_rate;


public:

    RateLimiter(
        double capacity,
        double requests_per_second
    )
        : bucket_capacity(capacity),
          refill_rate(requests_per_second)
    {
    }


    // ========================================================
    // RESET ALL CLIENT RATE-LIMIT STATE
    // ========================================================

    void reset()
    {
        std::lock_guard<std::mutex> lock(
            clients_mutex
        );

        clients.clear();
    }


    bool allow_request(
        const std::string& client_ip
    )
    {
        TokenBucket* bucket = nullptr;


        // ----------------------------------------------------
        // Find or create bucket for this client
        // ----------------------------------------------------

        {
            std::lock_guard<std::mutex> lock(
                clients_mutex
            );


            auto it =
                clients.find(client_ip);


            // Client does not exist
            if (it == clients.end())
            {
                auto new_bucket =
                    std::make_unique<TokenBucket>(
                        bucket_capacity,
                        refill_rate
                    );


                bucket =
                    new_bucket.get();


                clients.emplace(
                    client_ip,
                    std::move(new_bucket)
                );
            }


            // Client already exists
            else
            {
                bucket =
                    it->second.get();
            }
        }


        // ----------------------------------------------------
        // Use this client's token bucket
        // ----------------------------------------------------

        return bucket->allow_request();
    }
};
