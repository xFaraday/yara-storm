package main

import (
	"flag"
	"yarastorm/server"

	"github.com/xFaraday/yarastorm/config"
)

var (
	Port         string
	YaraLocation string
)

func main() {
	config.SetupDir()

	flag.StringVar(&Port, "port", "80", "Port to run the server on")
	flag.StringVar(&YaraLocation, "yara", "/srv/yara-storm/rules", "Location of the yara rules")

	server.Init()
}
