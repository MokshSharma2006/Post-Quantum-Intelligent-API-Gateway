#pragma once

#include <string>
#include <zmq.hpp>

class ZMQClient
{
private:
    zmq::context_t context;
    zmq::socket_t socket;

public:
    ZMQClient()
        : context(1),
          socket(context, zmq::socket_type::push)
    {
        socket.connect("tcp://127.0.0.1:5555");
    }

    bool send_event(const std::string& event)
    {
        try
        {
            zmq::message_t message(event);

            auto result =
                socket.send(
                    message,
                    zmq::send_flags::none
                );

            return result.has_value();
        }
        catch (...)
        {
            return false;
        }
    }
};
