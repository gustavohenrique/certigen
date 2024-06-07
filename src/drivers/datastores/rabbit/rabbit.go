package rabbit

import (
	"context"

	amqp "github.com/rabbitmq/amqp091-go"

	"certigen/src/drivers/datastores/db"
)

type rabbitStore struct {
	connection *amqp.Connection
	ch         *amqp.Channel
	config     Config
	ctx        context.Context
}

type Config struct {
	URL          string
	ConsumerName string
}

func New(config Config) db.QueueStore {
	return &rabbitStore{
		config: config,
		ctx:    context.Background(),
	}
}

func (store *rabbitStore) WithContext(ctx context.Context) db.QueueStore {
	store.ctx = ctx
	return store
}

func (store *rabbitStore) Connect() error {
	config := store.config
	rabbitConfig := amqp.Config{Properties: amqp.NewConnectionProperties()}
	rabbitConfig.Properties.SetClientConnectionName(config.ConsumerName)
	conn, err := amqp.DialConfig(config.URL, rabbitConfig)
	if err != nil {
		return err
	}
	ch, err := conn.Channel()
	if err != nil {
		conn.Close()
		return err
	}
	store.connection = conn
	store.ch = ch
	return nil
}

func (store *rabbitStore) Disconnect() {
	store.ch.Close()
	store.connection.Close()
}

func (store *rabbitStore) Publish(queue, message string) error {
	ch, err := store.getChannel()
	if err != nil {
		return err
	}
	err = ch.PublishWithContext(
		store.getCtx(),
		"",
		queue,
		false,
		false,
		amqp.Publishing{
			ContentType: "text/plain",
			Body:        []byte(message),
		},
	)
	return err
}

func (store *rabbitStore) Consume(queue string, fn func([]byte)) error {
	ch, err := store.getChannel()
	if err != nil {
		return err
	}
	msgs, err := ch.ConsumeWithContext(
		store.getCtx(),
		queue,
		"",
		true,
		false,
		false,
		false,
		nil,
	)
	if err != nil {
		return err
	}

	forever := make(chan bool)
	go func() {
		for d := range msgs {
			fn(d.Body)
		}
	}()
	<-forever
	return nil
}
func (store *rabbitStore) getChannel() (*amqp.Channel, error) {
	var err error
	if store.ch == nil {
		if err := store.Connect(); err != nil {
			return store.ch, err
		}
	}
	return store.ch, err
}

func (store *rabbitStore) getCtx() context.Context {
	if store.ctx != nil {
		return store.ctx
	}
	return context.Background()
}
