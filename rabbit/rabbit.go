package websocket

import (
	"context"
	"fmt"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

func failOnError(err error, msg string) {
	if err != nil {
		fmt.Printf("%s: %s\n", msg, err)
	}
}

const (
	amqpStr string = "amqp://taso:taso@127.0.0.1:5672/taso"
)

var Conn *amqp.Connection

func InitMQ() {
	var err error
	Conn, err = amqp.Dial(amqpStr)
	failOnError(err, "Failed to connect to RabbitMQ")
}

func Send2MQ(body []byte) {
	ch, err := Conn.Channel()
	failOnError(err, "Failed to open a channel")

	err = ch.Confirm(false)
	failOnError(err, "Failed to set channel confirm")

	defer ch.Close()

	err = ch.ExchangeDeclare(
		"send",   // name
		"fanout", // type
		true,     // durable
		false,    // delete when unused
		false,    // exclusive
		false,    // no-wait
		nil,      // arguments
	)
	failOnError(err, "Failed to declare a queue")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = ch.PublishWithContext(ctx,
		"send", // exchange
		"",     // routing key
		true,   // mandatory
		false,  // immediate
		amqp.Publishing{
			ContentType: "text/plain",
			Body:        body,
		})
		
	failOnError(err, "Failed to publish a message")
}
