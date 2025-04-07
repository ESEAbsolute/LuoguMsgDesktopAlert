#ifndef WSBROADCASTHDL_H
#define WSBROADCASTHDL_H

#pragma once

#include <nlohmann/json.hpp>
#include <typeindex>
#include <utility>
#include "handler/Event.hpp"
#include "handler/EventListener.hpp"

namespace IBroadcastListener {
    class BroadcastListener : virtual public EventListener {
    public:
        BroadcastListener();
        virtual void onBroadcast(const nlohmann::json &rawMessage) {
            localLogger.log(2, "Event", "Default implementation of onBroadcast. Check if overrides successfully.");
        }
    };

    class BroadcastEvent final : public Event<BroadcastListener> {
        nlohmann::json rawMessage;

    public:
        explicit BroadcastEvent(nlohmann::json rawMsg) : rawMessage(std::move(rawMsg)) {}

        void fireEvent(std::vector<BroadcastListener *> listeners) override {
            for (const auto listener: listeners) {
                listener->onBroadcast(rawMessage);
            }
        }
    };

    inline BroadcastListener::BroadcastListener() : EventListener(typeid(BroadcastEvent)) {}
} // namespace IBroadcastListener

#endif
