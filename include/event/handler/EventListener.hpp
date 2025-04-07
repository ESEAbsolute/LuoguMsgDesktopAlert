#ifndef EVENTLISTENER_H
#define EVENTLISTENER_H

#pragma once

#include <typeindex>

class EventListener {
    std::type_index eventType;

protected:
    explicit EventListener(const std::type_index type) : eventType(type) {}

public:
    EventListener() : eventType(typeid(void)) {}
    virtual ~EventListener() = default;
    [[nodiscard]] std::type_index getEventType() const { return eventType; }
};

#endif
