#include "ai_enforcement.hpp"

#include <iostream>


// ============================================================
// RECORD AI DECISION
// ============================================================

void AIEnforcement::record_decision(
    const std::string& action,
    const std::string& threat_level,
    int threat_score
)
{
    std::lock_guard<std::mutex> lock(mutex);

    total_decisions++;

    if (threat_level == "NORMAL")
    {
        normal_decisions++;
    }
    else if (threat_level == "SUSPICIOUS")
    {
        suspicious_decisions++;
    }
    else if (threat_level == "MALICIOUS")
    {
        malicious_decisions++;
    }

    if (action == "BLOCK")
    {
        block_decisions++;
    }

    last_threat_score = threat_score;
    last_threat_level = threat_level;
    last_action = action;
}


// ============================================================
// RECORD LLM RESULT
// ============================================================

void AIEnforcement::record_llm_result(
    bool enabled,
    const std::string& provider,
    const std::string& attack_type,
    const std::string& severity,
    int confidence,
    const std::string& recommendation,
    const std::string& explanation
)
{
    std::lock_guard<std::mutex> lock(mutex);

    llm_enabled = enabled;
    llm_provider = provider;

    last_attack_type = attack_type;
    last_severity = severity;
    last_confidence = confidence;
    last_recommendation = recommendation;
    last_explanation = explanation;

    std::cout
        << "[AI LLM] Result received"
        << std::endl;

    std::cout
        << "  Enabled       : "
        << (enabled ? "YES" : "NO")
        << std::endl;

    std::cout
        << "  Provider      : "
        << provider
        << std::endl;

    std::cout
        << "  Attack Type   : "
        << attack_type
        << std::endl;

    std::cout
        << "  Severity      : "
        << severity
        << std::endl;

    std::cout
        << "  Confidence    : "
        << confidence
        << "%"
        << std::endl;

    std::cout
        << "  Recommendation : "
        << recommendation
        << std::endl;
}


// ============================================================
// RECORD PAYLOAD RESULT
// ============================================================

void AIEnforcement::record_payload_result(
    int payload_score,
    const std::vector<std::string>& indicators
)
{
    std::lock_guard<std::mutex> lock(mutex);

    last_payload_score = payload_score;
    last_payload_indicators = indicators;

    std::cout
        << "[AI PAYLOAD] Result received"
        << std::endl;

    std::cout
        << "  Payload Score : "
        << payload_score
        << std::endl;

    std::cout
        << "  Indicators    : "
        << indicators.size()
        << std::endl;
}


// ============================================================
// BLOCK CLIENT
// ============================================================

void AIEnforcement::block_client(
    const std::string& client_ip,
    int duration_seconds,
    int threat_score,
    const std::string& threat_level
)
{
    std::lock_guard<std::mutex> lock(mutex);

    auto expires_at =
        std::chrono::steady_clock::now() +
        std::chrono::seconds(duration_seconds);

    blocked_clients[client_ip] =
    {
        expires_at,
        threat_score,
        threat_level
    };

    std::cout
        << "[AI ENFORCEMENT] Client BLOCKED"
        << std::endl;

    std::cout
        << "  IP            : "
        << client_ip
        << std::endl;

    std::cout
        << "  Threat Score  : "
        << threat_score
        << std::endl;

    std::cout
        << "  Threat Level  : "
        << threat_level
        << std::endl;

    std::cout
        << "  Duration      : "
        << duration_seconds
        << " seconds"
        << std::endl;
}


// ============================================================
// CHECK BLOCK
// ============================================================

bool AIEnforcement::is_blocked(
    const std::string& client_ip
)
{
    std::lock_guard<std::mutex> lock(mutex);

    auto it =
        blocked_clients.find(client_ip);

    if (it == blocked_clients.end())
    {
        return false;
    }

    auto now =
        std::chrono::steady_clock::now();

    if (now >= it->second.expires_at)
    {
        blocked_clients.erase(it);

        std::cout
            << "[AI ENFORCEMENT] Block expired for "
            << client_ip
            << std::endl;

        return false;
    }

    return true;
}


// ============================================================
// UNBLOCK CLIENT
// ============================================================

void AIEnforcement::unblock_client(
    const std::string& client_ip
)
{
    std::lock_guard<std::mutex> lock(mutex);

    blocked_clients.erase(client_ip);
}


// ============================================================
// GET BLOCKED COUNT
// ============================================================

int AIEnforcement::get_blocked_count()
{
    std::lock_guard<std::mutex> lock(mutex);

    auto now =
        std::chrono::steady_clock::now();

    for (
        auto it = blocked_clients.begin();
        it != blocked_clients.end();
    )
    {
        if (now >= it->second.expires_at)
        {
            it = blocked_clients.erase(it);
        }
        else
        {
            ++it;
        }
    }

    return static_cast<int>(
        blocked_clients.size()
    );
}


// ============================================================
// GET TOTAL AI DECISIONS
// ============================================================

unsigned long long
AIEnforcement::get_total_decisions()
{
    std::lock_guard<std::mutex> lock(mutex);

    return total_decisions;
}


// ============================================================
// GET NORMAL DECISIONS
// ============================================================

unsigned long long
AIEnforcement::get_normal_decisions()
{
    std::lock_guard<std::mutex> lock(mutex);

    return normal_decisions;
}


// ============================================================
// GET SUSPICIOUS DECISIONS
// ============================================================

unsigned long long
AIEnforcement::get_suspicious_decisions()
{
    std::lock_guard<std::mutex> lock(mutex);

    return suspicious_decisions;
}


// ============================================================
// GET MALICIOUS DECISIONS
// ============================================================

unsigned long long
AIEnforcement::get_malicious_decisions()
{
    std::lock_guard<std::mutex> lock(mutex);

    return malicious_decisions;
}


// ============================================================
// GET BLOCK DECISIONS
// ============================================================

unsigned long long
AIEnforcement::get_block_decisions()
{
    std::lock_guard<std::mutex> lock(mutex);

    return block_decisions;
}


// ============================================================
// GET LAST THREAT SCORE
// ============================================================

int AIEnforcement::get_last_threat_score()
{
    std::lock_guard<std::mutex> lock(mutex);

    return last_threat_score;
}


// ============================================================
// GET LAST THREAT LEVEL
// ============================================================

std::string
AIEnforcement::get_last_threat_level()
{
    std::lock_guard<std::mutex> lock(mutex);

    return last_threat_level;
}


// ============================================================
// GET LAST ACTION
// ============================================================

std::string
AIEnforcement::get_last_action()
{
    std::lock_guard<std::mutex> lock(mutex);

    return last_action;
}


// ============================================================
// GET LLM ENABLED
// ============================================================

bool
AIEnforcement::get_llm_enabled()
{
    std::lock_guard<std::mutex> lock(mutex);

    return llm_enabled;
}


// ============================================================
// GET LLM PROVIDER
// ============================================================

std::string
AIEnforcement::get_llm_provider()
{
    std::lock_guard<std::mutex> lock(mutex);

    return llm_provider;
}


// ============================================================
// GET LAST ATTACK TYPE
// ============================================================

std::string
AIEnforcement::get_last_attack_type()
{
    std::lock_guard<std::mutex> lock(mutex);

    return last_attack_type;
}


// ============================================================
// GET LAST SEVERITY
// ============================================================

std::string
AIEnforcement::get_last_severity()
{
    std::lock_guard<std::mutex> lock(mutex);

    return last_severity;
}


// ============================================================
// GET LAST CONFIDENCE
// ============================================================

int
AIEnforcement::get_last_confidence()
{
    std::lock_guard<std::mutex> lock(mutex);

    return last_confidence;
}


// ============================================================
// GET LAST RECOMMENDATION
// ============================================================

std::string
AIEnforcement::get_last_recommendation()
{
    std::lock_guard<std::mutex> lock(mutex);

    return last_recommendation;
}


// ============================================================
// GET LAST EXPLANATION
// ============================================================

std::string
AIEnforcement::get_last_explanation()
{
    std::lock_guard<std::mutex> lock(mutex);

    return last_explanation;
}


// ============================================================
// GET LAST PAYLOAD SCORE
// ============================================================

int
AIEnforcement::get_last_payload_score()
{
    std::lock_guard<std::mutex> lock(mutex);

    return last_payload_score;
}


// ============================================================
// GET LAST PAYLOAD INDICATORS
// ============================================================

std::vector<std::string>
AIEnforcement::get_last_payload_indicators()
{
    std::lock_guard<std::mutex> lock(mutex);

    return last_payload_indicators;
}   