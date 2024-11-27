package websocket

import (
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

var Server *WebSocketServer

type WebSocketServer struct {
	Upgrader websocket.Upgrader

	//
	connMapping connMapping

	//data channel
	ch chan []byte
}

type connMapping struct {
	Infos map[string]*ConnInfo

	Mutex sync.RWMutex
}

type ConnInfo struct {
	conn          *websocket.Conn // 链接
	lastHeartBeat time.Time       // 上一次心跳时间
}

func InitSocketServer() chan []byte {
	var ser WebSocketServer

	// init conn mapping
	ser.connMapping.Infos = make(map[string]*ConnInfo)

	ser.Upgrader.CheckOrigin = CheckOrigin

	ser.ch = make(chan []byte, 512)

	Server = &ser

	http.HandleFunc("/ws", handleWebSocket)

	go ser.runDataSender()

	go ser.heartbeatChecker()

	return ser.ch
}

func (c *WebSocketServer) AddConn(name string, conn *websocket.Conn) {
	c.connMapping.Mutex.Lock()

	defer c.connMapping.Mutex.Unlock()

	connBefore, ok := c.connMapping.Infos[name]
	// 断开旧链接
	if ok {
		connBefore.conn.Close()
		connBefore.lastHeartBeat = time.Now()
		return
	}

	var info ConnInfo
	info.conn = conn
	info.lastHeartBeat = time.Now()

	c.connMapping.Infos[name] = &info
}

func (c *WebSocketServer) RemoveConn(name string) {
	c.connMapping.Mutex.Lock()

	defer c.connMapping.Mutex.Unlock()

	connBefore, ok := c.connMapping.Infos[name]
	// 断开旧链接
	if ok {
		connBefore.conn.Close()

		delete(c.connMapping.Infos, name)
	}
}

func (c *WebSocketServer) GetCoon(name string) (*websocket.Conn, error) {
	Server.connMapping.Mutex.RLock()

	defer Server.connMapping.Mutex.RUnlock()

	if info, ok := Server.connMapping.Infos[name]; ok {
		return info.conn, nil
	} else {
		return nil, errors.New("conn not found")
	}
}

func (c *WebSocketServer) SendText(name string, text []byte) error {
	Server.connMapping.Mutex.RLock()

	defer Server.connMapping.Mutex.RUnlock()

	conn, err := c.GetCoon(name)
	if err != nil {
		return err
	}

	err = conn.WriteMessage(websocket.TextMessage, text)

	return err
}
