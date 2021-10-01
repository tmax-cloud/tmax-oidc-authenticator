package main

import (
	"github.com/jinsoo-youn/traefik-jwt-decode/config"
)

func main() {
	c, _ := config.NewConfig().RunServer()
	panic(<-c)
}
