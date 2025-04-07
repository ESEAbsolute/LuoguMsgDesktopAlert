#ifndef IEVENTLISTENER_HPP
#define IEVENTLISTENER_HPP

#include <iostream>

#include "handler/Event.hpp"
#include "handler/EventListener.hpp"
#include "LocalLogger.hpp"

namespace IEventListener {
    class MyListener : public EventListener {
    public:
        MyListener();
        virtual void onMyEvent(const int &param) {
            localLogger.log(2, "Event", "Default implementation of onMyEvent. Check if overrides successfully.");
        }
    };

    class MyEvent final : public Event<MyListener> {
        int param;

    public:
        explicit MyEvent(int param) : param(std::move(param)) {}

        void fireEvent(std::vector<MyListener *> listeners) override {
            for (const auto listener: listeners) {
                listener->onMyEvent(param);
            }
        }
    };

    inline MyListener::MyListener() : EventListener({typeid(MyEvent)}) {}
} // namespace IEventListener

#endif // IEVENTLISTENER_HPP
