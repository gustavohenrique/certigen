package eventbus

import "time"

type Event struct {
	Type      string
	Timestamp time.Time
	Data      interface{}
}

type eventBus struct {
	subscribers map[string][]chan<- Event
}

func NewEventBus() EventBus {
	return &eventBus{
		subscribers: make(map[string][]chan<- Event),
	}
}

func (eb *eventBus) Subscribe(eventType string, subscriber chan<- Event) {
	eb.subscribers[eventType] = append(eb.subscribers[eventType], subscriber)
}

func (eb *eventBus) Publish(event Event) {
	subscribers := eb.subscribers[event.Type]
	for _, subscriber := range subscribers {
		subscriber <- event
	}
}
