package websocket

import (
	"log"
	"net/http"
	rabbit "tools/rabbit"
)

func CheckOrigin(r *http.Request) bool {
	return true
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := Server.Upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Failed to upgrade to WebSocket:", err)
		return
	}
	defer conn.Close()
	Server.AddConn("main", conn)

	go func() {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			log.Println("Read error:", err)
		}

		log.Printf("go red:%s", msg)
	}()

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			log.Println("Read error:", err)
			break
		}

		log.Printf("[websocket server] Received: %s", msg)

		msgHandle(msg)

		log.Printf("[websocket server] msg sended: %s", msg)
	}
}

func msgHandle(msg []byte) error {
	rabbit.Send2MQ(msg)
	return nil
}
