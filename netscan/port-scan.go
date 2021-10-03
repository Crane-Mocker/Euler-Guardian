package main

import (
	"fmt"
	"net"
	"time"
)

func portScan(){
	var beginTime = time.Now()
	fmt.Println("Port scan starts.")
	var ip=""//ip
	for i := 21;i < 120;i++ {
		var address = fmt.Sprintf("%s:%d", ip, i)
		conn, err := net.Dial("tcp", address)
		if err != nil {
			fmt.Println(address, "is closed")
			continue
		}
		conn.Close()
		fmt.Println(address, "is opened")
	}
	var elapseTime = time.Now().Sub(beginTime)
	fmt.Println("Elapse time:",elapseTime)
}
