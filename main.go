package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

func main() {
	// Создаем UDP-соединение
	conn, err := net.Dial("udp", "stun.l.google.com:19302")
	if err != nil {
		fmt.Println("Error creating UDP connection:", err)
		return
	}
	defer conn.Close()

	// Отправляем запрос STUN
	req := buildSTUNRequest()
	_, err = conn.Write(req)
	if err != nil {
		fmt.Println("Error sending STUN request:", err)
		return
	}

	// Устанавливаем таймаут на получение ответа
	conn.SetDeadline(getDeadlineTime())

	// Читаем ответ STUN
	buffer := make([]byte, 1500)
	n, err := conn.Read(buffer)
	if err != nil {
		fmt.Println("Error reading STUN response:", err)
		return
	}

	// Распаковываем и анализируем ответ STUN
	xorAddr, err := parseSTUNResponse(buffer[:n])
	if err != nil {
		fmt.Println("Error parsing STUN response:", err)
		return
	}

	// Получаем общедоступный IP-адрес и порт
	fmt.Printf("Public IP: %s\n", xorAddr.IP.String())
	fmt.Printf("Public Port: %d\n", xorAddr.Port)
}

func buildSTUNRequest() []byte {
	// Формируем STUN Binding Request
	messageType := uint16(0x0001) // Binding Request
	messageLength := uint16(0)

	transactionID := make([]byte, 12)
	binary.BigEndian.PutUint32(transactionID, uint32(time.Now().Unix()))

	request := make([]byte, 20)
	binary.BigEndian.PutUint16(request[0:2], messageType)
	binary.BigEndian.PutUint16(request[2:4], messageLength)
	copy(request[4:], transactionID)

	return request
}

func getDeadlineTime() time.Time {
	return time.Now().Add(2 * time.Second)
}

func parseSTUNResponse(response []byte) (*net.UDPAddr, error) {
	// Пропускаем заголовок STUN
	response = response[20:]

	// Идентификатор атрибута XOR-Mapped Address
	const xorMappedAddressAttr = 0x0020

	// Ищем XOR-Mapped Address в атрибутах
	for len(response) >= 4 {
		attrType := binary.BigEndian.Uint16(response[0:2])
		attrLength := binary.BigEndian.Uint16(response[2:4])

		if attrType == xorMappedAddressAttr {
			ip := net.IP{
				response[4] ^ response[0],
				response[5] ^ response[1],
				response[6] ^ response[2],
				response[7] ^ response[3],
			}
			port := int(binary.BigEndian.Uint16(response[6:8]))

			return &net.UDPAddr{
				IP:   ip,
				Port: port,
			}, nil
		}

		// Переходим к следующему атрибуту
		response = response[4+attrLength:]
	}

	return nil, fmt.Errorf("XOR-Mapped Address attribute not found")
}
