#ifndef IUPDATELISTENER_HPP
#define IUPDATELISTENER_HPP

#include "LocalLogger.hpp"
#include "handler/Event.hpp"
#include "handler/EventListener.hpp"

namespace IUpdateListener {
    class UpdateListener : virtual public EventListener {
    public:
        UpdateListener();
        virtual void onUpdate() {
            localLogger.log(2, "Event", "Default implementation of onUpdate. Check if overrides successfully.");
        }
    };

    class UpdateEvent final : public Event<UpdateListener> {

    public:
        explicit UpdateEvent() = default;

        void fireEvent(std::vector<UpdateListener *> listeners) override {
            for (const auto listener: listeners) {
                listener->onUpdate();
            }
        }
    };

    inline UpdateListener::UpdateListener() : EventListener(typeid(UpdateEvent)) {}
} // namespace IUpdateListener

#endif // IUPDATELISTENER_HPP
