package main

import (
	"log"
)

func main() {
	client := NewClient()

	err := client.GetVersion()
	//err := client.GetVAT("tasos.daris", "1234", "148017270", "148017270")

	if err != nil {
		log.Println(err)
	}
}
