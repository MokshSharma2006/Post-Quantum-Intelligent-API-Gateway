#pragma once

#include <chrono>
#include <mutex>
#include <algorithm>


class TokenBucket
{
private:

    double capacity;
    double tokens;
    double refill_rate;

    std::chrono::steady_clock::time_point
        last_refill;

    std::mutex mutex;


public:

    TokenBucket(
        double bucket_capacity,
        double requests_per_second
    )
        : capacity(bucket_capacity),
          tokens(bucket_capacity),
          refill_rate(requests_per_second),
          last_refill(
              std::chrono::steady_clock::now()
          )
    {
    }


    bool allow_request()
    {
        std::lock_guard<std::mutex> lock(
            mutex
        );


        auto now =
            std::chrono::steady_clock::now();


        std::chrono::duration<double> elapsed =
            now - last_refill;


        // Add new tokens
        tokens +=
            elapsed.count() * refill_rate;


        // Do not exceed bucket capacity
        tokens =
            std::min(tokens, capacity);


        last_refill = now;


        // Request allowed
        if (tokens >= 1.0)
        {
            tokens -= 1.0;

            return true;
        }


        // Request blocked
        return false;
    }
};
