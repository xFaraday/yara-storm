package main

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/hillu/go-yara/v4"
	"go.uber.org/zap"
)

type Proc struct {
	Pid string
	cmd string
	bin string
	CWD string
	uid int
}

type ProcMatch struct {
	Process        Proc
	Rulename       string
	Tags           []string
	Metadata       []yara.Meta
	MatchedStrings []yara.MatchString
}

type FileMatch struct {
	file           finfo
	Rulename       string
	Tags           []string
	Metadata       []yara.Meta
	MatchedStrings []yara.MatchString
}

type finfo struct {
	Name string
	Size int64
	Time string
	Hash string
}

// steps to use this lib:
// 1. Call YaraCompile(yaraRules) to create a compiler with the rules <yaraRules>
// 2. saved variable returned from YaraCompile(yaraRules) and use variable.GetRules() to get the rules
// 3. Call Either YaraScanFile(yaraRules, file) or YaraScanProcess(yaraRules, pid) to scan a file or process

func CheckFile(name string) finfo {
	fileInfo, err := os.Stat(name)
	if err != nil {
		i := finfo{
			Name: "",
			Size: 0,
			Time: "",
			Hash: "",
		}
		return i
	}
	println(name)
	if fileInfo.IsDir() {

		t := fileInfo.ModTime().String()
		b := fileInfo.Size()

		i := finfo{
			Name: name,
			Size: b,
			Time: t,
			Hash: "directory",
		}

		return i
	} else {
		f, err := os.Open(name)
		if err != nil {
			panic(err)
		}
		if err != nil {
			if os.IsNotExist(err) {
				println("file not found:", fileInfo.Name())
			}
		}
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			panic(err)
		}
		hash := h.Sum(nil)
		Enc := base64.StdEncoding.EncodeToString(hash)

		t := fileInfo.ModTime().String()
		b := fileInfo.Size()

		i := finfo{
			Name: name,
			Size: b,
			Time: t,
			Hash: Enc,
		}
		return i
	}
}

func FindRules(yaraRules string) []string {
	stats := CheckFile(yaraRules)
	var YaraRuleList []string
	if stats.Size != 0 {
		if stats.Hash == "directory" {
			err := filepath.Walk(yaraRules, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return fmt.Errorf("error processing path: %s, err: %v", path, err)
				}
				// Skip Directories
				if info.IsDir() {
					return nil
				}
				if !strings.Contains(path, ".yar") {
					return nil
				}
				YaraRuleList = append(YaraRuleList, path)
				return error(nil)
			})
			if err != nil {
				zap.S().Errorf("Error finding YARA Rules: %s", err)
			}
		} else {
			YaraRuleList = append(YaraRuleList, yaraRules)
			return YaraRuleList
		}
	}
	return YaraRuleList
}

func YaraCompile() *yara.Compiler {
	yaraRules := config.GetYaraLocation()
	cmplr, err := yara.NewCompiler()
	if err != nil {
		zap.S().Errorf("Error creating YARA Compiler: %s", err)
	}

	ruleSet := FindRules(yaraRules)

	for _, rule := range ruleSet {
		f, err := os.Open(rule)
		if err != nil {
			zap.S().Errorf("Error opening YARA Rule: %s", err)
			continue
		}

		cmplr.AddFile(f, rule)
		defer f.Close()
	}

	zap.S().Info("YARA Rules Compiled")
	return cmplr
}

func PerformProcScan(rules *yara.Rules, p Proc) ProcMatch {
	scanner, err := yara.NewScanner(rules)
	if err != nil {
		zap.S().Errorf("Error creating YARA Scanner: %s", err)
	}
	var MatchEvents yara.MatchRules
	scanner.SetCallback(&MatchEvents)
	//convert pid to int
	pid, err := strconv.Atoi(p.Pid)
	if err := scanner.ScanProc(pid); err != nil {
		zap.S().Errorf("Error scanning process: %s", err)
	} else {
		for _, match := range MatchEvents {
			zap.S().Infof("YARA Match: %s", match)
			var matcherino ProcMatch = ProcMatch{
				Process:        p,
				Rulename:       match.Rule,
				Tags:           match.Tags,
				Metadata:       match.Metas,
				MatchedStrings: match.Strings,
			}
			return matcherino
		}
	}
	return ProcMatch{}
}

func PerformFileScan(rules *yara.Rules, f string) FileMatch {
	scanner, err := yara.NewScanner(rules)
	if err != nil {
		zap.S().Errorf("Error creating YARA Scanner: %s", err)
	}
	var MatchEvents yara.MatchRules
	scanner.SetCallback(&MatchEvents)

	if err := scanner.ScanFile(f); err != nil {
		zap.S().Errorf("Error scanning file: %s", err)
	} else {
		zap.S().Infof("YARA Match: %s", MatchEvents)
		for _, match := range MatchEvents {
			var matcherino FileMatch = FileMatch{
				file:           CheckFile(f),
				Rulename:       match.Rule,
				Tags:           match.Tags,
				Metadata:       match.Metas,
				MatchedStrings: match.Strings,
			}
			return matcherino
		}
	}
	return FileMatch{}
}
