#pragma once

#include <string>
#include <thread>
#include <atomic>

#include "ai_enforcement.hpp"

class AIDecisionReceiver
{
private:
    AIEnforcement& enforcement;

    std::thread receiver_thread;
    std::atomic<bool> running;

    void receive_loop();

public:
    explicit AIDecisionReceiver(AIEnforcement& enforcement);

    void start();
    void stop();

    ~AIDecisionReceiver();
};
