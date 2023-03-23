package main

import (
	"flag"

	"github.com/xFaraday/yara-storm/config"
	"github.com/xFaraday/yara-storm/server"
)

var (
	Port         string
	YaraLocation string
)

func main() {
	config.SetupDir()

	flag.StringVar(&Port, "port", "80", "Port to run the server on")
	flag.StringVar(&YaraLocation, "yara", "/srv/yara-storm/rules", "Location of the yara rules")
	flag.Parse()
	println("Port: " + Port)
	config.MakeConfig(Port, YaraLocation)
	server.Init(Port)
}
