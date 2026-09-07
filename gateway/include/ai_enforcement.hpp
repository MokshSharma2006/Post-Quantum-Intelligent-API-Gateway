#pragma once

#include <string>
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <vector>


class AIEnforcement
{
private:

    // ========================================================
    // BLOCK ENTRY
    // ========================================================

    struct BlockEntry
    {
        std::chrono::steady_clock::time_point expires_at;

        int threat_score;

        std::string threat_level;
    };


    std::unordered_map<
        std::string,
        BlockEntry
    > blocked_clients;


    std::mutex mutex;


    // ========================================================
    // AI STATISTICS
    // ========================================================

    unsigned long long total_decisions = 0;

    unsigned long long normal_decisions = 0;

    unsigned long long suspicious_decisions = 0;

    unsigned long long malicious_decisions = 0;

    unsigned long long block_decisions = 0;


    // ========================================================
    // LAST AI DECISION
    // ========================================================

    int last_threat_score = 0;

    std::string last_threat_level =
        "NONE";

    std::string last_action =
        "NONE";


    // ========================================================
    // GEMINI / LLM INTELLIGENCE
    // ========================================================

    bool llm_enabled = false;

    std::string llm_provider =
        "NONE";

    std::string last_attack_type =
        "NONE";

    std::string last_severity =
        "NONE";

    int last_confidence = 0;

    std::string last_recommendation =
        "NONE";

    std::string last_explanation =
        "NONE";


    // ========================================================
    // PAYLOAD INTELLIGENCE
    // ========================================================

    int last_payload_score = 0;

    std::vector<std::string>
        last_payload_indicators;


public:

    AIEnforcement() = default;


    // ========================================================
    // RESET AI SECURITY STATE
    // ========================================================

    void reset()
    {
        std::lock_guard<std::mutex> lock(mutex);

        // Clear blocked clients
        blocked_clients.clear();

        // Reset AI statistics
        total_decisions = 0;
        normal_decisions = 0;
        suspicious_decisions = 0;
        malicious_decisions = 0;
        block_decisions = 0;

        // Reset last AI decision
        last_threat_score = 0;
        last_threat_level = "NONE";
        last_action = "NONE";

        // Reset last LLM result
        last_attack_type = "NONE";
        last_severity = "NONE";
        last_confidence = 0;
        last_recommendation = "NONE";
        last_explanation = "NONE";

        // Reset payload intelligence
        last_payload_score = 0;
        last_payload_indicators.clear();
    }


    // ========================================================
    // RECORD AI DECISION
    // ========================================================

    void record_decision(
        const std::string& action,
        const std::string& threat_level,
        int threat_score
    );


    // ========================================================
    // RECORD LLM RESULT
    // ========================================================

    void record_llm_result(
        bool enabled,
        const std::string& provider,
        const std::string& attack_type,
        const std::string& severity,
        int confidence,
        const std::string& recommendation,
        const std::string& explanation
    );


    // ========================================================
    // RECORD PAYLOAD RESULT
    // ========================================================

    void record_payload_result(
        int payload_score,
        const std::vector<std::string>& indicators
    );


    // ========================================================
    // BLOCK CLIENT
    // ========================================================

    void block_client(
        const std::string& client_ip,
        int duration_seconds,
        int threat_score,
        const std::string& threat_level
    );


    // ========================================================
    // CHECK BLOCK
    // ========================================================

    bool is_blocked(
        const std::string& client_ip
    );


    // ========================================================
    // UNBLOCK CLIENT
    // ========================================================

    void unblock_client(
        const std::string& client_ip
    );


    // ========================================================
    // GET BLOCKED CLIENT COUNT
    // ========================================================

    int get_blocked_count();


    // ========================================================
    // AI STATISTICS
    // ========================================================

    unsigned long long get_total_decisions();

    unsigned long long get_normal_decisions();

    unsigned long long get_suspicious_decisions();

    unsigned long long get_malicious_decisions();

    unsigned long long get_block_decisions();


    // ========================================================
    // LAST AI DECISION
    // ========================================================

    int get_last_threat_score();

    std::string get_last_threat_level();

    std::string get_last_action();


    // ========================================================
    // LLM INFORMATION
    // ========================================================

    bool get_llm_enabled();

    std::string get_llm_provider();

    std::string get_last_attack_type();

    std::string get_last_severity();

    int get_last_confidence();

    std::string get_last_recommendation();

    std::string get_last_explanation();


    // ========================================================
    // PAYLOAD INFORMATION
    // ========================================================

    int get_last_payload_score();

    std::vector<std::string>
    get_last_payload_indicators();
};