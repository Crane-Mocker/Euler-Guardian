package main

import (
	"fmt"
	//"time"
	"flag"
)

var (
	cliHelp = flag.Bool("h", false, "Help")
	cliPort = flag.Int("p", 5555, "Port")
	cliTimeOut = flag.Int64("t", 1200, "Timeout, ms")
)

func main(){
	fmt.Println("\033[1;32m-----------------------------------------------")
	fmt.Println(" ___         __              ")
	fmt.Println("(_    /_ _  / _   _ _ _/'_   ")
	fmt.Println("/__(/((-/  (__)(/(// (//(//) ")
	fmt.Println("Welcome to use Euler Guardian!")
	fmt.Println("This is the net scan module.")
	fmt.Println("-----------------------------------------------\033[0m")

	//timeStamp := time.Now().Unix()
	flag.Parse()
	if *cliHelp == true {
		fmt.Println("This is the net scan module of Euler Guardian.")
		fmt.Println("Usage:")
	}
	portScan()
}
