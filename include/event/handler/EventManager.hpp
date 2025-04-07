#ifndef EVENTMANAGER_HPP
#define EVENTMANAGER_HPP

#pragma once

#include <iostream>
#include <map>
#include <string>
#include <typeindex>
#include <vector>

#include "Event.hpp"
#include "EventListener.hpp"
#include "LocalLogger.hpp"

class EventManager {
    std::map<std::type_index, std::vector<EventListener *>> listenerMap;

public:
    template<typename L>
    void addEventListener(L *eventListener) {
        try {
            auto &listeners = listenerMap[eventListener->getEventType()];
            listeners.push_back(eventListener);
            localLogger.log(0, "EventManager",
                            "Added Event Listener: eventType = " + std::string(eventListener->getEventType().name()));
        } catch (const std::exception &e) {
            localLogger.log(2, "EventManager", "Failed in adding: " + std::string(e.what()));
            localLogger.log(2, "EventManager", "eventType = " + std::string(eventListener->getEventType().name()));
            throw;
        }
    }

    template<typename L, typename E>
    void addEventListener(L *eventListener, E *event) {
        try {
            const std::type_index eventType = std::type_index(typeid(E));
            auto &listeners = listenerMap[eventType];
            listeners.push_back(eventListener);
            localLogger.log(0, "EventManager", "Added Event Listener: eventType = " + std::string(eventType.name()));
        } catch (const std::exception &e) {
            localLogger.log(2, "EventManager", "Failed in adding: " + std::string(e.what()));
            localLogger.log(2, "EventManager", "eventType = " + std::string(std::type_index(typeid(E)).name()));
            throw;
        }
    }

    template<typename L>
    void removeEventListener(L *eventListener) {
        try {
            auto &listeners = listenerMap[eventListener->getEventType()];
            listeners.erase(std::remove(listeners.begin(), listeners.end(), eventListener), listeners.end());
            localLogger.log(0, "EventManager",
                            "Removed Event Listener: eventType = " + eventListener->getEventType().name());
        } catch (const std::exception &e) {
            localLogger.log(2, "EventManager", "Failed in removing: " + std::string(e.what()));
            localLogger.log(2, "EventManager", "eventType = " + eventListener->getEventType().name());
            throw;
        }
    }

    template<typename L, typename E>
    void removeEventListener(L *eventListener, E *event) {
        try {
            const std::type_index eventType = std::type_index(typeid(E));
            auto &listeners = listenerMap[eventType];
            listeners.erase(std::remove(listeners.begin(), listeners.end(), eventListener), listeners.end());
            localLogger.log(0, "EventManager", "Removed Event Listener: eventType = " + std::string(eventType.name()));
        } catch (const std::exception &e) {
            localLogger.log(2, "EventManager", "Failed in removing: " + std::string(e.what()));
            localLogger.log(2, "EventManager", "eventType = " + std::string(std::type_index(typeid(E)).name()));
            throw;
        }
    }

    template<typename E /*extends Event, L extends EventListener*/>
    void fireEvent(E *event) {
        try {
            using L = typename E::listenerType;
            auto eventType = std::type_index(typeid(E));
            auto listenerType = event->getListenerType();
            const auto it = listenerMap.find(eventType);
            if (it == listenerMap.end() || it->second.empty())
                return;

            std::vector<L *> listenersCopy;
            for (auto listener: it->second) {
                if (auto castedListener = dynamic_cast<L *>(listener)) {
                    listenersCopy.push_back(castedListener);
                }
            }
            if (std::string(eventType.name()).find("Update") == std::string::npos) {
                localLogger.log(0, "EventManager", "Firing event");
                localLogger.log(0, "EventManager", "| eventType = " + std::string(eventType.name()));
                localLogger.log(0, "EventManager", "| listenerType = " + std::string(listenerType.name()));
                localLogger.log(0, "EventManager", std::to_string(listenersCopy.size()) + " listeners affected.");
            localLogger.log(0, "EventManager", "Fired event: event.class = " + std::string(typeid(E).name()));
            }

            event->fireEvent(listenersCopy);
        } catch (const std::exception &e) {
            localLogger.log(2, "EventManager", "Failed in firing: " + std::string(e.what()));
            localLogger.log(2, "EventManager", "event.class = " + std::string(typeid(E).name()));
            throw;
        }
    }
};

#endif
