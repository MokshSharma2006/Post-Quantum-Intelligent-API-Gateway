#pragma once

#include <chrono>
#include <ctime>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>


struct SecurityEvent
{
    std::string timestamp;
    std::string client_ip;
    std::string endpoint;
    std::string event_type;
    std::string action;
    std::string attack_type;
};


class SecurityEventLog
{
private:

    static constexpr std::size_t MAX_EVENTS = 100;

    mutable std::mutex mutex;

    std::vector<SecurityEvent> events;


    std::string current_timestamp() const
    {
        auto now =
            std::chrono::system_clock::now();

        std::time_t time_now =
            std::chrono::system_clock::to_time_t(
                now
            );

        std::tm local_time{};

#ifdef _WIN32
        localtime_s(
            &local_time,
            &time_now
        );
#else
        localtime_r(
            &time_now,
            &local_time
        );
#endif

        std::ostringstream timestamp;

        timestamp
            << std::put_time(
                &local_time,
                "%H:%M:%S"
            );

        return timestamp.str();
    }


public:

    void record_event(
        const std::string& client_ip,
        const std::string& endpoint,
        const std::string& event_type,
        const std::string& action,
        const std::string& attack_type = "NONE"
    )
    {
        std::lock_guard<std::mutex> lock(
            mutex
        );

        SecurityEvent event;

        event.timestamp =
            current_timestamp();

        event.client_ip =
            client_ip;

        event.endpoint =
            endpoint;

        event.event_type =
            event_type;

        event.action =
            action;

        event.attack_type =
            attack_type;


        events.push_back(
            event
        );


        if (
            events.size() >
            MAX_EVENTS
        )
        {
            events.erase(
                events.begin()
            );
        }
    }


    std::vector<SecurityEvent> get_events() const
    {
        std::lock_guard<std::mutex> lock(
            mutex
        );

        return events;
    }


    void reset()
    {
        std::lock_guard<std::mutex> lock(
            mutex
        );

        events.clear();
    }


    std::size_t size() const
    {
        std::lock_guard<std::mutex> lock(
            mutex
        );

        return events.size();
    }
};
