package eventbus

type EventBus interface {
	Subscribe(eventType string, subscriber chan<- Event)
	Publish(event Event)
}
