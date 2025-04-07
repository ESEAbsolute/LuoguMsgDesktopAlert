#ifndef EVENT_H
#define EVENT_H

#pragma once

#include <typeindex>
#include <vector>

template<typename L /*extends EventListener*/>
class Event {
public:
    using listenerType = L;
    virtual ~Event() = default;
    virtual void fireEvent(std::vector<L *> listeners) = 0;
    static std::type_index getListenerType() {
        return std::type_index(typeid(L));
    }
};

#endif
