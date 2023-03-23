package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
)

type Configuration struct {
	Port         string `json:"Port"`
	YaraLocation string `json:"YaraLocation"`
}

const CONFIG_LOC string = "/srv/yara-storm/config.json"

func GetPort() string {
	file, _ := os.Open(CONFIG_LOC)
	defer file.Close()
	decoder := json.NewDecoder(file)
	configuration := Configuration{}
	err := decoder.Decode(&configuration)
	if err != nil {
		fmt.Println("error:", err)
	}
	return configuration.Port
}

func GetYaraLocation() string {
	file, _ := os.Open(CONFIG_LOC)
	defer file.Close()
	decoder := json.NewDecoder(file)
	configuration := Configuration{}
	err := decoder.Decode(&configuration)
	if err != nil {
		fmt.Println("error:", err)
	}
	return configuration.YaraLocation
}

func MakeConfig(Port string, YaraLocation string) {
	/*config := Configuration{
		Apis: {
			Kaspersky: {
				APIKey: API,
			},
			SerialScripter: {
				IP:        IPofServ,
				UserAgent: UA,
			},
			Yara: {
				Rules: YaraRules,
			},
		}
	}*/
	config := &Configuration{}
	config.Port = Port
	config.YaraLocation = YaraLocation
	file, _ := json.MarshalIndent(config, "", " ")
	_ = ioutil.WriteFile(CONFIG_LOC, file, 0644)
}

func SetupDir() string {
	dirs := []string{"/srv/yara-storm", "/srv/yara-storm/rules", "/srv/yara-storm/logs", "/srv/yara-storm/scan", "/srv/yara-storm/storage"}
	for _, dir := range dirs {
		_, err := os.Stat(dir)
		if os.IsNotExist(err) {
			err := os.MkdirAll(dir, 0755)
			if err != nil {
				panic(err)
			}
		} else if err != nil {
			panic(err)
		}
	}
	return "Directories Created"
}
