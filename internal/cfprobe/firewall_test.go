package cfprobe

import (
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestNormalizeOpenPortList(t *testing.T) {
	got, err := normalizeOpenPortList(" 8080 ")
	if err != nil {
		t.Fatalf("normalizeOpenPortList returned error: %v", err)
	}
	if got != "8080" {
		t.Fatalf("normalizeOpenPortList = %q, want 8080", got)
	}

	got, err = normalizeOpenPortList("8080, 8443, 8080")
	if err != nil {
		t.Fatalf("normalizeOpenPortList returned error: %v", err)
	}
	if got != "8080,8443" {
		t.Fatalf("normalizeOpenPortList = %q, want 8080,8443", got)
	}

	got, err = normalizeOpenPortList("0")
	if err != nil || got != "" {
		t.Fatalf("normalizeOpenPortList(0) = %q, %v; want empty", got, err)
	}

	if _, err := normalizeOpenPortList("70000"); err == nil {
		t.Fatal("expected port > 65535 to be rejected")
	}
	if _, err := normalizeOpenPortList("abc"); err == nil {
		t.Fatal("expected non-numeric port to be rejected")
	}
}

func TestNormalizeWhitelistIPs(t *testing.T) {
	got, err := normalizeWhitelistIPs(" 1.2.3.4, 5.6.7.8, 1.2.3.4, 10.0.0.0/24, 2001:db8::1 ")
	if err != nil {
		t.Fatalf("normalizeWhitelistIPs returned error: %v", err)
	}
	want := "1.2.3.4,5.6.7.8,10.0.0.0/24,2001:db8::1"
	if got != want {
		t.Fatalf("normalizeWhitelistIPs = %q, want %q", got, want)
	}

	if _, err := normalizeWhitelistIPs("1.2.3.4, bad-ip"); err == nil {
		t.Fatal("expected invalid IP to be rejected")
	}
}

func TestConfigPersistsOpenPortAndWhitelistIPs(t *testing.T) {
	path := t.TempDir() + "/config.conf"
	cfg := defaultConfig()
	cfg.ServerID = "sid"
	cfg.Secret = "secret"
	cfg.WorkerURL = "https://worker.example.com/update"
	cfg.OpenPort = "8080"
	cfg.WhitelistIPs = "1.2.3.4,5.6.7.8"

	if err := writeConfig(path, cfg); err != nil {
		t.Fatalf("writeConfig returned error: %v", err)
	}
	got, err := readConfig(path)
	if err != nil {
		t.Fatalf("readConfig returned error: %v", err)
	}
	if got.OpenPort != "8080" {
		t.Fatalf("OpenPort = %q, want 8080", got.OpenPort)
	}
	if got.WhitelistIPs != "1.2.3.4,5.6.7.8" {
		t.Fatalf("WhitelistIPs = %q, want 1.2.3.4,5.6.7.8", got.WhitelistIPs)
	}
}

func TestFirewalldOpenAndCloseWithWhitelist(t *testing.T) {
	openPortsPerm := map[string]bool{}
	openPortsRuntime := map[string]bool{}
	richRulesPerm := map[string]bool{}
	richRulesRuntime := map[string]bool{}
	var commands []string

	runner := firewallCommandRunner{
		lookPath: func(name string) bool {
			return name == "firewall-cmd"
		},
		run: func(name string, args ...string) error {
			cmd := name + " " + strings.Join(args, " ")
			commands = append(commands, cmd)
			if len(args) == 1 && args[0] == "--state" {
				return nil
			}
			if len(args) == 1 && args[0] == "--reload" {
				openPortsRuntime = map[string]bool{}
				for k, v := range openPortsPerm {
					openPortsRuntime[k] = v
				}
				richRulesRuntime = map[string]bool{}
				for k, v := range richRulesPerm {
					richRulesRuntime[k] = v
				}
				return nil
			}
			isPerm := false
			for _, arg := range args {
				if arg == "--permanent" {
					isPerm = true
				}
			}
			for _, arg := range args {
				switch {
				case strings.HasPrefix(arg, "--query-port="):
					p := strings.TrimPrefix(arg, "--query-port=")
					if isPerm {
						if openPortsPerm[p] {
							return nil
						}
						return errors.New("no")
					}
					if openPortsRuntime[p] {
						return nil
					}
					return errors.New("no")
				case strings.HasPrefix(arg, "--add-port="):
					p := strings.TrimPrefix(arg, "--add-port=")
					openPortsPerm[p] = true
					return nil
				case strings.HasPrefix(arg, "--remove-port="):
					p := strings.TrimPrefix(arg, "--remove-port=")
					delete(openPortsPerm, p)
					return nil
				case strings.HasPrefix(arg, "--query-rich-rule="):
					r := strings.TrimPrefix(arg, "--query-rich-rule=")
					if isPerm {
						if richRulesPerm[r] {
							return nil
						}
						return errors.New("no")
					}
					if richRulesRuntime[r] {
						return nil
					}
					return errors.New("no")
				case strings.HasPrefix(arg, "--add-rich-rule="):
					r := strings.TrimPrefix(arg, "--add-rich-rule=")
					richRulesPerm[r] = true
					return nil
				case strings.HasPrefix(arg, "--remove-rich-rule="):
					r := strings.TrimPrefix(arg, "--remove-rich-rule=")
					delete(richRulesPerm, r)
					return nil
				}
			}
			return nil
		},
		output: func(name string, args ...string) (string, error) {
			return "", nil
		},
	}

	tmp := t.TempDir()
	configFile := tmp + "/config.conf"
	cfg := defaultConfig()
	cfg.ServerID = "sid"
	cfg.Secret = "secret"
	cfg.WorkerURL = "https://worker.example.com/update"
	cfg.OpenPort = "8080"
	cfg.WhitelistIPs = "1.2.3.4,5.6.7.8"
	if err := writeConfig(configFile, cfg); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}

	agent := &Agent{
		cfg:             cfg,
		paths:           Paths{ConfigFile: configFile, TrafficFile: tmp + "/traffic.dat"},
		log:             newLogger(false),
		fwRunner:        runner,
		fwCheckInterval: -1,
	}

	// 1. 面板下发 X-Agent-Open-Port: 1 -> 放行白名单 + 开放 8080/tcp + reload
	headers := http.Header{}
	headers.Set(agentOpenPortHeader, "1")
	agent.handleReportResponse(http.StatusNoContent, nil, headers)

	if !openPortsRuntime["8080/tcp"] {
		t.Fatal("expected 8080/tcp to be open in runtime after open_port=1")
	}
	rule1 := firewalldRichRuleForPort("1.2.3.4", 8080)
	rule2 := firewalldRichRuleForPort("5.6.7.8", 8080)
	if !richRulesRuntime[rule1] || !richRulesRuntime[rule2] {
		t.Fatalf("expected whitelist rich rules to be active, got %v", richRulesRuntime)
	}

	// 2. 面板下发 X-Agent-Open-Port: 0 -> 关闭 8080/tcp 全网访问，但保留白名单 IP 访问 + reload
	headers.Set(agentOpenPortHeader, "0")
	agent.handleReportResponse(http.StatusNoContent, nil, headers)

	if openPortsRuntime["8080/tcp"] {
		t.Fatal("expected 8080/tcp public access to be closed after open_port=0")
	}
	if !richRulesRuntime[rule1] || !richRulesRuntime[rule2] {
		t.Fatal("expected whitelist rich rules to remain active when open_port=0")
	}

	// 3. 修改磁盘上的 config.conf 白名单（移除 5.6.7.8，新增 9.9.9.9），下次上报自动同步
	cfg.WhitelistIPs = "1.2.3.4,9.9.9.9"
	if err := writeConfig(configFile, cfg); err != nil {
		t.Fatalf("writeConfig updated whitelist: %v", err)
	}
	future := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(configFile, future, future)

	agent.handleReportResponse(http.StatusNoContent, nil, headers)
	rule3 := firewalldRichRuleForPort("9.9.9.9", 8080)
	if richRulesRuntime[rule2] {
		t.Fatal("expected removed whitelist IP 5.6.7.8 rich rule to be deleted")
	}
	if !richRulesRuntime[rule1] || !richRulesRuntime[rule3] {
		t.Fatal("expected updated whitelist rich rules (1.2.3.4, 9.9.9.9) to be active")
	}
}

func TestUfwOpenAndCloseWithWhitelist(t *testing.T) {
	publicOpen := false
	whitelistAllowed := map[string]bool{}
	reloaded := 0

	runner := firewallCommandRunner{
		lookPath: func(name string) bool {
			return name == "ufw"
		},
		run: func(name string, args ...string) error {
			cmd := strings.Join(args, " ")
			switch cmd {
			case "allow 8080/tcp":
				publicOpen = true
			case "delete allow 8080/tcp":
				publicOpen = false
			case "allow from 1.2.3.4 to any port 8080 proto tcp":
				whitelistAllowed["1.2.3.4"] = true
			case "reload":
				reloaded++
			}
			return nil
		},
		output: func(name string, args ...string) (string, error) {
			var lines []string
			lines = append(lines, "Status: active")
			if publicOpen {
				lines = append(lines, "8080/tcp                   ALLOW       Anywhere")
			}
			for ip := range whitelistAllowed {
				lines = append(lines, "8080/tcp                   ALLOW       "+ip)
			}
			return strings.Join(lines, "\n"), nil
		},
	}

	changed, err := syncFirewallPortState([]int{8080}, []string{"1.2.3.4"}, nil, true, true, runner, newLogger(false))
	if err != nil || !changed {
		t.Fatalf("syncFirewallPortState open: changed=%v err=%v", changed, err)
	}
	if !publicOpen || !whitelistAllowed["1.2.3.4"] || reloaded != 1 {
		t.Fatalf("ufw state after open: public=%v whitelist=%v reloaded=%d", publicOpen, whitelistAllowed, reloaded)
	}

	changed, err = syncFirewallPortState([]int{8080}, []string{"1.2.3.4"}, nil, false, true, runner, newLogger(false))
	if err != nil || !changed {
		t.Fatalf("syncFirewallPortState close: changed=%v err=%v", changed, err)
	}
	if publicOpen || !whitelistAllowed["1.2.3.4"] || reloaded != 2 {
		t.Fatalf("ufw state after close: public=%v whitelist=%v reloaded=%d", publicOpen, whitelistAllowed, reloaded)
	}
}

func TestIptablesOpenAndCloseWithWhitelist(t *testing.T) {
	rules := map[string]bool{}
	runner := firewallCommandRunner{
		lookPath: func(name string) bool {
			return name == "iptables"
		},
		run: func(name string, args ...string) error {
			action := args[0]
			ruleKey := strings.Join(args[1:], " ")
			switch action {
			case "-C":
				if rules[ruleKey] {
					return nil
				}
				return errors.New("not found")
			case "-I", "-A":
				rules[ruleKey] = true
				return nil
			case "-D":
				delete(rules, ruleKey)
				return nil
			}
			return nil
		},
		output: func(name string, args ...string) (string, error) {
			return "", nil
		},
	}

	changed, err := syncFirewallPortState([]int{8080}, []string{"1.2.3.4"}, nil, true, true, runner, newLogger(false))
	if err != nil || !changed {
		t.Fatalf("iptables open: changed=%v err=%v", changed, err)
	}
	if !rules["INPUT -p tcp --dport 8080 -j ACCEPT"] || !rules["INPUT -p tcp -s 1.2.3.4 --dport 8080 -j ACCEPT"] || rules["INPUT -p tcp --dport 8080 -j DROP"] {
		t.Fatalf("unexpected iptables rules after open: %v", rules)
	}

	changed, err = syncFirewallPortState([]int{8080}, []string{"1.2.3.4"}, nil, false, true, runner, newLogger(false))
	if err != nil || !changed {
		t.Fatalf("iptables close: changed=%v err=%v", changed, err)
	}
	if rules["INPUT -p tcp --dport 8080 -j ACCEPT"] || !rules["INPUT -p tcp -s 1.2.3.4 --dport 8080 -j ACCEPT"] || !rules["INPUT -p tcp --dport 8080 -j DROP"] {
		t.Fatalf("unexpected iptables rules after close: %v", rules)
	}
}

func TestSSHPortAndOpenPortIndependentWhitelists(t *testing.T) {
	rules := map[string]bool{}
	runner := firewallCommandRunner{
		lookPath: func(name string) bool {
			return name == "iptables"
		},
		run: func(name string, args ...string) error {
			action := args[0]
			ruleKey := strings.Join(args[1:], " ")
			switch action {
			case "-C":
				if rules[ruleKey] {
					return nil
				}
				return errors.New("not found")
			case "-I", "-A":
				rules[ruleKey] = true
				return nil
			case "-D":
				delete(rules, ruleKey)
				return nil
			}
			return nil
		},
		output: func(name string, args ...string) (string, error) {
			return "", nil
		},
	}

	tmp := t.TempDir()
	configFile := tmp + "/config.conf"
	cfg := defaultConfig()
	cfg.ServerID = "sid"
	cfg.Secret = "secret"
	cfg.WorkerURL = "https://worker.example.com/update"
	cfg.OpenPort = "33060"
	cfg.WhitelistIPs = "68.68.249.61,75.37.238.63"
	cfg.SSHPort = "22"
	cfg.SSHWhitelistIPs = "75.37.238.63"
	if err := writeConfig(configFile, cfg); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}

	gotCfg, err := readConfig(configFile)
	if err != nil {
		t.Fatalf("readConfig: %v", err)
	}
	if gotCfg.SSHPort != "22" || gotCfg.SSHWhitelistIPs != "75.37.238.63" {
		t.Fatalf("readConfig ssh fields = (%q, %q)", gotCfg.SSHPort, gotCfg.SSHWhitelistIPs)
	}

	agent := &Agent{
		cfg:             cfg,
		paths:           Paths{ConfigFile: configFile, TrafficFile: tmp + "/traffic.dat"},
		log:             newLogger(false),
		fwRunner:        runner,
		fwCheckInterval: -1,
	}

	// 1. 面板标识为 0：33060 和 22 都关闭全网，但各自只放行自己的白名单
	headers := http.Header{}
	headers.Set(agentOpenPortHeader, "0")
	agent.handleReportResponse(http.StatusNoContent, nil, headers)

	if !rules["INPUT -p tcp --dport 33060 -j DROP"] || !rules["INPUT -p tcp --dport 22 -j DROP"] {
		t.Fatalf("expected DROP rules on 33060 and 22, got %v", rules)
	}
	if !rules["INPUT -p tcp -s 68.68.249.61 --dport 33060 -j ACCEPT"] || rules["INPUT -p tcp -s 68.68.249.61 --dport 22 -j ACCEPT"] {
		t.Fatalf("expected 68.68.249.61 only on 33060, not on 22; got %v", rules)
	}
	if !rules["INPUT -p tcp -s 75.37.238.63 --dport 33060 -j ACCEPT"] || !rules["INPUT -p tcp -s 75.37.238.63 --dport 22 -j ACCEPT"] {
		t.Fatalf("expected 75.37.238.63 on both 33060 and 22; got %v", rules)
	}

	// 2. 面板标识为 1：33060 和 22 都全网放行
	headers.Set(agentOpenPortHeader, "1")
	agent.handleReportResponse(http.StatusNoContent, nil, headers)

	if rules["INPUT -p tcp --dport 33060 -j DROP"] || rules["INPUT -p tcp --dport 22 -j DROP"] {
		t.Fatalf("expected DROP rules removed when open_port=1, got %v", rules)
	}
	if !rules["INPUT -p tcp --dport 33060 -j ACCEPT"] || !rules["INPUT -p tcp --dport 22 -j ACCEPT"] {
		t.Fatalf("expected public ACCEPT rules on 33060 and 22, got %v", rules)
	}
}

