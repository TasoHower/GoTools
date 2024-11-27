package websocket

import (
	"log"
	"time"
)

// heartbeat checker
func (c *WebSocketServer) heartbeatChecker() {
	for {
		c.checkJob()

		time.Sleep(time.Minute)
	}
}

func (c *WebSocketServer) checkJob() {
	c.connMapping.Mutex.Lock()
	defer c.connMapping.Mutex.Unlock()

	for name, info := range c.connMapping.Infos {
		if time.Since(info.lastHeartBeat) > time.Minute {
			info.conn.Close()
			delete(c.connMapping.Infos, name)
		}
	}
}

func (c *WebSocketServer) runDataSender() {
	for {
		c.dataSender()

		log.Printf("why run here!!!")
	}
}

func (c *WebSocketServer) dataSender() {
	var forever chan int

	for msg := range c.ch {
		c.SendText("main", msg)
	}

	<-forever
}