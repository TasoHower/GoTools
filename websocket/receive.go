package websocket

import (
	"encoding/json"
	"fmt"
	"log"
	"time"
	rabbit "tools/rabbit"
)

func ReceiveFromMQ(name string) {
	for {
		receiveJob(name)

		log.Printf("why run here!")

		time.Sleep(time.Second * 5)
	}
}

func receiveJob(name string) {
	ch, err := rabbit.Conn.Channel()
	if err != nil {
		return
	}

	defer ch.Close()

	_ = ch.ExchangeDeclare(
		"client_send_exchange",   // name
		"fanout", // type
		true,     // durable
		false,    // delete when unused
		false,    // exclusive
		false,    // no-wait
		nil,      // arguments
	)

	// 持久化的队列
	q, _ := ch.QueueDeclare(
		name,  // name
		true,  // durable
		false, // delete when unused
		false, // exclusive
		false, // no-wait
		nil,   // arguments
	)

	_ = ch.QueueBind(
		q.Name, // queue name
		"",     // routing key
		"client_send_exchange", // exchange
		false,
		nil,
	)

	msgs, _ := ch.Consume(
		q.Name, // queue
		"",     // consumer
		false,  // auto-ack
		false,  // exclusive
		false,  // no-local
		false,  // no-wait
		nil,    // args
	)

	forever := make(chan int)
	
	go func() {
		for d := range msgs {
			var a TextMessage
			_ = json.Unmarshal(d.Body,&a)
			fmt.Println(string(a.Body))
			
			d.Ack(false)
		}
	}()

	fmt.Printf("[*] Waiting for messages. To exit press CTRL+C\n")

	<-forever
}

type TextMessage struct {
	From        string `json:"from"`
	To          string `json:"to"`
	Timestamp   int64  `json:"timestamp"` // 发送的时间戳
	MessageType string `json:"message_type"`
	MessageID   int64  `json:"message_id"`

	Body []byte `json:"body"`
}