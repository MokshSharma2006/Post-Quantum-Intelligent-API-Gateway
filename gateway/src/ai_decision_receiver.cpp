#include "ai_decision_receiver.hpp"

#include <iostream>
#include <chrono>
#include <vector>

#include <zmq.hpp>
#include <crow.h>


// ============================================================
// CONSTRUCTOR
// ============================================================

AIDecisionReceiver::AIDecisionReceiver(
    AIEnforcement& enforcement_ref
)
    : enforcement(enforcement_ref),
      running(false)
{
}


// ============================================================
// START RECEIVER
// ============================================================

void AIDecisionReceiver::start()
{
    if (running)
    {
        return;
    }

    running = true;

    receiver_thread =
        std::thread(
            &AIDecisionReceiver::receive_loop,
            this
        );

    std::cout
        << "[AI RECEIVER] Started"
        << std::endl;

    std::cout
        << "[AI RECEIVER] Listening on "
           "tcp://127.0.0.1:5556"
        << std::endl;
}


// ============================================================
// STOP RECEIVER
// ============================================================

void AIDecisionReceiver::stop()
{
    running = false;

    if (receiver_thread.joinable())
    {
        receiver_thread.join();
    }
}


// ============================================================
// RECEIVE LOOP
// ============================================================

void AIDecisionReceiver::receive_loop()
{
    try
    {
        // ----------------------------------------------------
        // ZeroMQ context
        // ----------------------------------------------------

        zmq::context_t context(1);


        // ----------------------------------------------------
        // PULL socket
        // ----------------------------------------------------

        zmq::socket_t socket(
            context,
            zmq::socket_type::pull
        );

        socket.bind(
            "tcp://127.0.0.1:5556"
        );


        // ----------------------------------------------------
        // RECEIVE LOOP
        // ----------------------------------------------------

        while (running)
        {
            zmq::pollitem_t items[] =
            {
                {
                    static_cast<void*>(socket),
                    0,
                    ZMQ_POLLIN,
                    0
                }
            };


            zmq::poll(
                items,
                1,
                std::chrono::milliseconds(500)
            );


            if (!(items[0].revents & ZMQ_POLLIN))
            {
                continue;
            }


            // ------------------------------------------------
            // RECEIVE MESSAGE
            // ------------------------------------------------

            zmq::message_t message;

            auto result =
                socket.recv(
                    message,
                    zmq::recv_flags::none
                );


            if (!result)
            {
                continue;
            }


            std::string data(
                static_cast<char*>(message.data()),
                message.size()
            );


            std::cout
                << "\n====================================="
                << std::endl;

            std::cout
                << "[AI DECISION RECEIVED]"
                << std::endl;

            std::cout
                << data
                << std::endl;


            // ------------------------------------------------
            // PARSE JSON
            // ------------------------------------------------

            try
            {
                auto decision =
                    crow::json::load(data);


                if (!decision)
                {
                    std::cerr
                        << "[AI RECEIVER] Invalid JSON"
                        << std::endl;

                    continue;
                }


                // ------------------------------------------------
                // BASIC DECISION FIELDS
                // ------------------------------------------------

                std::string client_ip =
                    decision["client_ip"].s();

                std::string action =
                    decision["action"].s();

                std::string threat_level =
                    decision["threat_level"].s();

                int threat_score =
                    decision["threat_score"].i();

                int duration =
                    decision["duration_seconds"].i();


                // ------------------------------------------------
                // LLM FIELDS
                // ------------------------------------------------

                bool llm_enabled = false;

                std::string llm_provider = "NONE";
                std::string attack_type = "NONE";
                std::string severity = "NONE";
                std::string recommendation = "NONE";
                std::string explanation = "NONE";

                int confidence = 0;


                if (decision["llm_enabled"])
                {
                    llm_enabled =
                        decision["llm_enabled"].b();
                }

                if (decision["llm_provider"])
                {
                    llm_provider =
                        decision["llm_provider"].s();
                }

                if (decision["attack_type"])
                {
                    attack_type =
                        decision["attack_type"].s();
                }

                if (decision["severity"])
                {
                    severity =
                        decision["severity"].s();
                }

                if (decision["confidence"])
                {
                    confidence =
                        decision["confidence"].i();
                }

                if (decision["recommendation"])
                {
                    recommendation =
                        decision["recommendation"].s();
                }

                if (decision["explanation"])
                {
                    explanation =
                        decision["explanation"].s();
                }


                // ------------------------------------------------
                // PAYLOAD FIELDS
                // ------------------------------------------------

                int payload_score = 0;

                std::vector<std::string>
                    payload_indicators;


                if (decision["payload_score"])
                {
                    payload_score =
                        decision["payload_score"].i();
                }


                if (decision["payload_indicators"])
                {
                    auto indicators =
                        decision["payload_indicators"];

                    if (indicators.t() ==
                        crow::json::type::List)
                    {
                        for (const auto& indicator :
                             indicators)
                        {
                            if (indicator.t() ==
                                crow::json::type::String)
                            {
                                payload_indicators.push_back(
                                    indicator.s()
                                );
                            }
                        }
                    }
                }


                // ------------------------------------------------
                // DISPLAY DECISION
                // ------------------------------------------------

                std::cout
                    << "\n[AI DECISION DETAILS]"
                    << std::endl;

                std::cout
                    << "Client IP       : "
                    << client_ip
                    << std::endl;

                std::cout
                    << "Action          : "
                    << action
                    << std::endl;

                std::cout
                    << "Threat Level    : "
                    << threat_level
                    << std::endl;

                std::cout
                    << "Threat Score    : "
                    << threat_score
                    << "/100"
                    << std::endl;


                // ------------------------------------------------
                // DISPLAY LLM INFORMATION
                // ------------------------------------------------

                std::cout
                    << "\n[LLM ANALYSIS]"
                    << std::endl;

                std::cout
                    << "LLM Enabled     : "
                    << (llm_enabled ? "YES" : "NO")
                    << std::endl;

                std::cout
                    << "Provider        : "
                    << llm_provider
                    << std::endl;

                std::cout
                    << "Attack Type     : "
                    << attack_type
                    << std::endl;

                std::cout
                    << "Severity        : "
                    << severity
                    << std::endl;

                std::cout
                    << "Confidence      : "
                    << confidence
                    << "%"
                    << std::endl;

                std::cout
                    << "Recommendation  : "
                    << recommendation
                    << std::endl;

                std::cout
                    << "Explanation     : "
                    << explanation
                    << std::endl;


                // ------------------------------------------------
                // DISPLAY PAYLOAD INFORMATION
                // ------------------------------------------------

                std::cout
                    << "\n[PAYLOAD ANALYSIS]"
                    << std::endl;

                std::cout
                    << "Payload Score   : "
                    << payload_score
                    << "/60"
                    << std::endl;

                std::cout
                    << "Indicators      : "
                    << payload_indicators.size()
                    << std::endl;

                for (const auto& indicator :
                     payload_indicators)
                {
                    std::cout
                        << "  - "
                        << indicator
                        << std::endl;
                }


                // ------------------------------------------------
                // RECORD BASIC AI DECISION
                // ------------------------------------------------

                enforcement.record_decision(
                    action,
                    threat_level,
                    threat_score
                );


                // ------------------------------------------------
                // RECORD LLM RESULT
                // ------------------------------------------------

                enforcement.record_llm_result(
                    llm_enabled,
                    llm_provider,
                    attack_type,
                    severity,
                    confidence,
                    recommendation,
                    explanation
                );


                // ------------------------------------------------
                // RECORD PAYLOAD RESULT
                // ------------------------------------------------

                enforcement.record_payload_result(
                    payload_score,
                    payload_indicators
                );


                std::cout
                    << "\n[AI STATISTICS]"
                    << std::endl;

                std::cout
                    << "Decision recorded"
                    << std::endl;


                // ------------------------------------------------
                // AI BLOCK DECISION
                // ------------------------------------------------

                if (
                    !client_ip.empty() &&
                    action == "BLOCK"
                )
                {
                    enforcement.block_client(
                        client_ip,
                        duration,
                        threat_score,
                        threat_level
                    );


                    std::cout
                        << "[AI RECEIVER] BLOCK applied"
                        << std::endl;
                }


                // ------------------------------------------------
                // NON-BLOCK DECISION
                // ------------------------------------------------

                else
                {
                    std::cout
                        << "[AI RECEIVER] Action = "
                        << action
                        << " (no block applied)"
                        << std::endl;
                }


                std::cout
                    << "====================================="
                    << std::endl;
            }


            catch (
                const std::exception& e
            )
            {
                std::cerr
                    << "[AI RECEIVER] JSON processing "
                       "error: "
                    << e.what()
                    << std::endl;
            }
        }
    }


    catch (
        const std::exception& e
    )
    {
        std::cerr
            << "[AI RECEIVER] Error: "
            << e.what()
            << std::endl;
    }
}


// ============================================================
// DESTRUCTOR
// ============================================================

AIDecisionReceiver::~AIDecisionReceiver()
{
    stop();
}