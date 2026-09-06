#pragma once

#include <atomic>
#include <chrono>


class SecurityMetrics
{
private:

    std::atomic<unsigned long long> total_requests{0};
    std::atomic<unsigned long long> allowed_requests{0};
    std::atomic<unsigned long long> blocked_requests{0};

    std::chrono::steady_clock::time_point start_time;


public:

    SecurityMetrics()
        : start_time(std::chrono::steady_clock::now())
    {
    }


    // ========================================================
    // RECORD TOTAL REQUEST
    // ========================================================

    void record_request()
    {
        total_requests++;
    }


    // ========================================================
    // RECORD ALLOWED REQUEST
    // ========================================================

    void record_allowed()
    {
        allowed_requests++;
    }


    // ========================================================
    // RECORD BLOCKED REQUEST
    // ========================================================

    void record_blocked()
    {
        blocked_requests++;
    }


    // ========================================================
    // GET TOTAL REQUESTS
    // ========================================================

    unsigned long long get_total_requests() const
    {
        return total_requests.load();
    }


    // ========================================================
    // GET ALLOWED REQUESTS
    // ========================================================

    unsigned long long get_allowed_requests() const
    {
        return allowed_requests.load();
    }


    // ========================================================
    // GET BLOCKED REQUESTS
    // ========================================================

    unsigned long long get_blocked_requests() const
    {
        return blocked_requests.load();
    }


    // ========================================================
    // GET REQUESTS PER SECOND
    // ========================================================

    double get_requests_per_second() const
    {
        auto now =
            std::chrono::steady_clock::now();

        std::chrono::duration<double> elapsed =
            now - start_time;


        if (elapsed.count() <= 0.0)
        {
            return 0.0;
        }


        return static_cast<double>(
            total_requests.load()
        ) / elapsed.count();
    }
};
