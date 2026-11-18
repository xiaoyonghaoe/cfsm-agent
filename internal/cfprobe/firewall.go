package cfprobe

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

const firewallCommandTimeout = 15 * time.Second

type firewallCommandRunner struct {
	lookPath func(name string) bool
	run      func(name string, args ...string) error
	output   func(name string, args ...string) (string, error)
}

type firewallState struct {
	mu            sync.Mutex
	applied       bool
	allowAll      bool
	openPort      string
	whitelistIPs  string
	lastCheckedAt time.Time
	configModTime time.Time
}

func defaultFirewallCommandRunner() firewallCommandRunner {
	return firewallCommandRunner{
		lookPath: commandExists,
		run:      runFirewallCommand,
		output: func(name string, args ...string) (string, error) {
			return commandOutputWithTimeout(firewallCommandTimeout, name, args...)
		},
	}
}

func runFirewallCommand(name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), firewallCommandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = time.Second
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return fmt.Errorf("%s timed out: %w", name, ctx.Err())
	}
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "), err, msg)
		}
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return nil
}

func (a *Agent) firewallRunner() firewallCommandRunner {
	if a != nil && a.fwRunner.lookPath != nil && a.fwRunner.run != nil && a.fwRunner.output != nil {
		return a.fwRunner
	}
	return defaultFirewallCommandRunner()
}

func parseOpenPortFlag(raw string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true":
		return true, true
	case "0", "false":
		return false, true
	default:
		return false, false
	}
}

func parseOpenPortNumbers(raw string) []int {
	normalized, err := normalizeOpenPortList(raw)
	if err != nil || normalized == "" {
		return nil
	}
	parts := strings.Split(normalized, ",")
	ports := make([]int, 0, len(parts))
	for _, part := range parts {
		if port, err := strconv.Atoi(strings.TrimSpace(part)); err == nil && port >= 1 && port <= 65535 {
			ports = append(ports, port)
		}
	}
	return ports
}

func splitWhitelistIPs(raw string) []string {
	normalized, err := normalizeWhitelistIPs(raw)
	if err != nil || normalized == "" {
		return nil
	}
	return strings.Split(normalized, ",")
}

func diffRemovedStrings(previous, current []string) []string {
	if len(previous) == 0 {
		return nil
	}
	currentSet := make(map[string]bool, len(current))
	for _, item := range current {
		currentSet[item] = true
	}
	var removed []string
	for _, item := range previous {
		if !currentSet[item] {
			removed = append(removed, item)
		}
	}
	return removed
}

// syncLocalFirewallConfigFromDisk 检查配置文件是否在磁盘上被手动修改过 OPEN_PORT / WHITELIST_IPS，
// 若有变更则同步到内存配置，无需重启服务即可生效，且避免后续动态配置写盘覆盖手动修改。
func (a *Agent) syncLocalFirewallConfigFromDisk() {
	if a == nil || strings.TrimSpace(a.paths.ConfigFile) == "" {
		return
	}
	info, err := os.Stat(a.paths.ConfigFile)
	if err != nil {
		return
	}
	a.fwState.mu.Lock()
	unchanged := !a.fwState.configModTime.IsZero() && info.ModTime().Equal(a.fwState.configModTime)
	a.fwState.mu.Unlock()
	if unchanged {
		return
	}

	values, err := parseKVFile(a.paths.ConfigFile)
	if err != nil {
		return
	}
	diskOpenPort, openPortErr := normalizeOpenPortList(firstNonEmpty(values["OPEN_PORT"], values["FIREWALL_PORT"], values["PORT"]))
	diskWhitelist, whitelistErr := normalizeWhitelistIPs(values["WHITELIST_IPS"])

	a.configWriteMu.Lock()
	cfg := a.configSnapshot()
	changed := false
	if openPortErr == nil && cfg.OpenPort != diskOpenPort {
		cfg.OpenPort = diskOpenPort
		changed = true
	}
	if whitelistErr == nil && cfg.WhitelistIPs != diskWhitelist {
		cfg.WhitelistIPs = diskWhitelist
		changed = true
	}
	if changed {
		a.setConfig(cfg)
	}
	a.configWriteMu.Unlock()

	a.fwState.mu.Lock()
	a.fwState.configModTime = info.ModTime()
	a.fwState.mu.Unlock()
}

func (a *Agent) handleOpenPortFlag(raw string) {
	if a == nil {
		return
	}
	allowAll, ok := parseOpenPortFlag(raw)
	if !ok {
		return
	}

	a.syncLocalFirewallConfigFromDisk()
	cfg := a.configSnapshot()
	ports := parseOpenPortNumbers(cfg.OpenPort)
	if len(ports) == 0 {
		return
	}
	whitelist := splitWhitelistIPs(cfg.WhitelistIPs)

	a.fwState.mu.Lock()
	defer a.fwState.mu.Unlock()

	now := time.Now()
	stateChanged := !a.fwState.applied ||
		a.fwState.allowAll != allowAll ||
		a.fwState.openPort != cfg.OpenPort ||
		a.fwState.whitelistIPs != cfg.WhitelistIPs

	if !stateChanged {
		checkInterval := time.Duration(cfg.ReportInterval) * time.Second
		if checkInterval < 30*time.Second {
			checkInterval = 30 * time.Second
		}
		if a.fwCheckInterval != 0 {
			checkInterval = a.fwCheckInterval
		}
		if checkInterval > 0 && !a.fwState.lastCheckedAt.IsZero() && now.Sub(a.fwState.lastCheckedAt) < checkInterval {
			return
		}
	}

	removedWhitelist := diffRemovedStrings(splitWhitelistIPs(a.fwState.whitelistIPs), whitelist)
	changed, err := syncFirewallPortState(ports, whitelist, removedWhitelist, allowAll, stateChanged, a.firewallRunner(), a.log)
	if err != nil {
		a.log.warnf("firewall port sync failed port=%s allow_all=%v: %v", cfg.OpenPort, allowAll, err)
		return
	}
	a.fwState.applied = true
	a.fwState.allowAll = allowAll
	a.fwState.openPort = cfg.OpenPort
	a.fwState.whitelistIPs = cfg.WhitelistIPs
	a.fwState.lastCheckedAt = now
	if changed {
		a.log.info("firewall port synced port=%s allow_all=%v whitelist=%s", cfg.OpenPort, allowAll, firstNonEmpty(cfg.WhitelistIPs, "none"))
	}
}

func detectFirewallBackend(runner firewallCommandRunner) string {
	if runner.lookPath("firewall-cmd") && runner.run("firewall-cmd", "--state") == nil {
		return "firewalld"
	}
	if runner.lookPath("ufw") {
		if out, err := runner.output("ufw", "status"); err == nil && strings.Contains(strings.ToLower(out), "status: active") {
			return "ufw"
		}
	}
	if runner.lookPath("iptables") {
		return "iptables"
	}
	if runner.lookPath("firewall-cmd") {
		return "firewalld"
	}
	if runner.lookPath("ufw") {
		return "ufw"
	}
	return ""
}

func syncFirewallPortState(
	ports []int,
	whitelist []string,
	removedWhitelist []string,
	allowAll bool,
	forceApply bool,
	runner firewallCommandRunner,
	log logger,
) (bool, error) {
	if len(ports) == 0 {
		return false, nil
	}
	backend := detectFirewallBackend(runner)
	switch backend {
	case "firewalld":
		return syncFirewalldPortState(ports, whitelist, removedWhitelist, allowAll, forceApply, runner)
	case "ufw":
		return syncUfwPortState(ports, whitelist, removedWhitelist, allowAll, forceApply, runner)
	case "iptables":
		return syncIptablesPortState(ports, whitelist, removedWhitelist, allowAll, runner)
	default:
		return false, errors.New("未检测到受支持的防火墙工具 (firewall-cmd / ufw / iptables)")
	}
}

func firewalldRichRuleForPort(ip string, port int) string {
	family := "ipv4"
	if strings.Contains(ip, ":") {
		family = "ipv6"
	}
	return fmt.Sprintf(`rule family="%s" source address="%s" port port="%d" protocol="tcp" accept`, family, ip, port)
}

func syncFirewalldPortState(
	ports []int,
	whitelist []string,
	removedWhitelist []string,
	allowAll bool,
	forceApply bool,
	runner firewallCommandRunner,
) (bool, error) {
	needReload := false

	for _, port := range ports {
		portSpec := fmt.Sprintf("%d/tcp", port)

		// 1. 移除已从配置中删掉的旧白名单规则
		for _, oldIP := range removedWhitelist {
			rule := firewalldRichRuleForPort(oldIP, port)
			if runner.run("firewall-cmd", "--zone=public", "--query-rich-rule="+rule, "--permanent") == nil ||
				runner.run("firewall-cmd", "--zone=public", "--query-rich-rule="+rule) == nil {
				if err := runner.run("firewall-cmd", "--zone=public", "--remove-rich-rule="+rule, "--permanent"); err != nil {
					return false, err
				}
				needReload = true
			}
		}

		// 2. 确保固定白名单 IP 始终放行该端口
		for _, ip := range whitelist {
			rule := firewalldRichRuleForPort(ip, port)
			runtimeHas := runner.run("firewall-cmd", "--zone=public", "--query-rich-rule="+rule) == nil
			permHas := runner.run("firewall-cmd", "--zone=public", "--query-rich-rule="+rule, "--permanent") == nil
			if !runtimeHas || !permHas {
				if err := runner.run("firewall-cmd", "--zone=public", "--add-rich-rule="+rule, "--permanent"); err != nil {
					return false, err
				}
				needReload = true
			}
		}

		// 3. 根据 allowAll 标识开启或关闭端口的全网访问
		runtimeOpen := runner.run("firewall-cmd", "--zone=public", "--query-port="+portSpec) == nil
		permOpen := runner.run("firewall-cmd", "--zone=public", "--query-port="+portSpec, "--permanent") == nil
		if allowAll {
			if !runtimeOpen || !permOpen {
				if err := runner.run("firewall-cmd", "--zone=public", "--add-port="+portSpec, "--permanent"); err != nil {
					return false, err
				}
				needReload = true
			}
		} else {
			if runtimeOpen || permOpen {
				if err := runner.run("firewall-cmd", "--zone=public", "--remove-port="+portSpec, "--permanent"); err != nil {
					return false, err
				}
				needReload = true
			}
		}
	}

	if needReload {
		if err := runner.run("firewall-cmd", "--reload"); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

func ufwHasPublicRule(statusOutput string, port int) bool {
	portTCP := fmt.Sprintf("%d/tcp", port)
	portOnly := strconv.Itoa(port)
	for _, rawLine := range strings.Split(statusOutput, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		if (fields[0] == portTCP || fields[0] == portOnly) &&
			strings.EqualFold(fields[1], "ALLOW") &&
			strings.Contains(strings.ToLower(line), "anywhere") {
			return true
		}
	}
	return false
}

func ufwHasWhitelistRule(statusOutput string, port int, ip string) bool {
	portTCP := fmt.Sprintf("%d/tcp", port)
	portOnly := strconv.Itoa(port)
	for _, rawLine := range strings.Split(statusOutput, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		if (fields[0] == portTCP || fields[0] == portOnly) &&
			strings.EqualFold(fields[1], "ALLOW") &&
			strings.Contains(line, ip) {
			return true
		}
	}
	return false
}

func syncUfwPortState(
	ports []int,
	whitelist []string,
	removedWhitelist []string,
	allowAll bool,
	forceApply bool,
	runner firewallCommandRunner,
) (bool, error) {
	statusOut, _ := runner.output("ufw", "status")
	needReload := false

	for _, port := range ports {
		portStr := strconv.Itoa(port)
		portSpec := fmt.Sprintf("%d/tcp", port)

		for _, oldIP := range removedWhitelist {
			if ufwHasWhitelistRule(statusOut, port, oldIP) {
				if err := runner.run("ufw", "delete", "allow", "from", oldIP, "to", "any", "port", portStr, "proto", "tcp"); err != nil {
					return false, err
				}
				needReload = true
			}
		}

		for _, ip := range whitelist {
			if !ufwHasWhitelistRule(statusOut, port, ip) {
				if err := runner.run("ufw", "allow", "from", ip, "to", "any", "port", portStr, "proto", "tcp"); err != nil {
					return false, err
				}
				needReload = true
			}
		}

		publicOpen := ufwHasPublicRule(statusOut, port)
		if allowAll {
			if !publicOpen || (forceApply && statusOut == "") {
				if err := runner.run("ufw", "allow", portSpec); err != nil {
					return false, err
				}
				needReload = true
			}
		} else {
			if publicOpen {
				if err := runner.run("ufw", "delete", "allow", portSpec); err != nil {
					return false, err
				}
				needReload = true
			}
		}
	}

	if needReload {
		if err := runner.run("ufw", "reload"); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

func syncIptablesPortState(
	ports []int,
	whitelist []string,
	removedWhitelist []string,
	allowAll bool,
	runner firewallCommandRunner,
) (bool, error) {
	changed := false

	for _, port := range ports {
		portStr := strconv.Itoa(port)

		for _, oldIP := range removedWhitelist {
			bin := "iptables"
			if strings.Contains(oldIP, ":") {
				bin = "ip6tables"
			}
			if !runner.lookPath(bin) {
				continue
			}
			if runner.run(bin, "-C", "INPUT", "-p", "tcp", "-s", oldIP, "--dport", portStr, "-j", "ACCEPT") == nil {
				if err := runner.run(bin, "-D", "INPUT", "-p", "tcp", "-s", oldIP, "--dport", portStr, "-j", "ACCEPT"); err != nil {
					return false, err
				}
				changed = true
			}
		}

		// 确保本机回环始终可访问该端口
		if runner.lookPath("iptables") {
			if runner.run("iptables", "-C", "INPUT", "-p", "tcp", "-s", "127.0.0.1", "--dport", portStr, "-j", "ACCEPT") != nil {
				if err := runner.run("iptables", "-I", "INPUT", "-p", "tcp", "-s", "127.0.0.1", "--dport", portStr, "-j", "ACCEPT"); err != nil {
					return false, err
				}
				changed = true
			}
		}
		if runner.lookPath("ip6tables") {
			if runner.run("ip6tables", "-C", "INPUT", "-p", "tcp", "-s", "::1/128", "--dport", portStr, "-j", "ACCEPT") != nil {
				_ = runner.run("ip6tables", "-I", "INPUT", "-p", "tcp", "-s", "::1/128", "--dport", portStr, "-j", "ACCEPT")
			}
		}

		for _, ip := range whitelist {
			bin := "iptables"
			if strings.Contains(ip, ":") {
				bin = "ip6tables"
			}
			if !runner.lookPath(bin) {
				continue
			}
			if runner.run(bin, "-C", "INPUT", "-p", "tcp", "-s", ip, "--dport", portStr, "-j", "ACCEPT") != nil {
				if err := runner.run(bin, "-I", "INPUT", "-p", "tcp", "-s", ip, "--dport", portStr, "-j", "ACCEPT"); err != nil {
					return false, err
				}
				changed = true
			}
		}

		publicOpen := runner.run("iptables", "-C", "INPUT", "-p", "tcp", "--dport", portStr, "-j", "ACCEPT") == nil
		publicDrop := runner.run("iptables", "-C", "INPUT", "-p", "tcp", "--dport", portStr, "-j", "DROP") == nil
		if allowAll {
			if publicDrop {
				if err := runner.run("iptables", "-D", "INPUT", "-p", "tcp", "--dport", portStr, "-j", "DROP"); err != nil {
					return false, err
				}
				changed = true
			}
			if runner.lookPath("ip6tables") && runner.run("ip6tables", "-C", "INPUT", "-p", "tcp", "--dport", portStr, "-j", "DROP") == nil {
				_ = runner.run("ip6tables", "-D", "INPUT", "-p", "tcp", "--dport", portStr, "-j", "DROP")
			}
			if !publicOpen {
				if err := runner.run("iptables", "-I", "INPUT", "-p", "tcp", "--dport", portStr, "-j", "ACCEPT"); err != nil {
					return false, err
				}
				changed = true
			}
			if runner.lookPath("ip6tables") && runner.run("ip6tables", "-C", "INPUT", "-p", "tcp", "--dport", portStr, "-j", "ACCEPT") != nil {
				_ = runner.run("ip6tables", "-I", "INPUT", "-p", "tcp", "--dport", portStr, "-j", "ACCEPT")
			}
		} else {
			if publicOpen {
				if err := runner.run("iptables", "-D", "INPUT", "-p", "tcp", "--dport", portStr, "-j", "ACCEPT"); err != nil {
					return false, err
				}
				changed = true
			}
			if runner.lookPath("ip6tables") && runner.run("ip6tables", "-C", "INPUT", "-p", "tcp", "--dport", portStr, "-j", "ACCEPT") == nil {
				_ = runner.run("ip6tables", "-D", "INPUT", "-p", "tcp", "--dport", portStr, "-j", "ACCEPT")
			}
			if !publicDrop {
				if err := runner.run("iptables", "-A", "INPUT", "-p", "tcp", "--dport", portStr, "-j", "DROP"); err != nil {
					return false, err
				}
				changed = true
			}
			if runner.lookPath("ip6tables") && runner.run("ip6tables", "-C", "INPUT", "-p", "tcp", "--dport", portStr, "-j", "DROP") != nil {
				_ = runner.run("ip6tables", "-A", "INPUT", "-p", "tcp", "--dport", portStr, "-j", "DROP")
			}
		}
	}

	if changed && runner.lookPath("netfilter-persistent") {
		_ = runner.run("netfilter-persistent", "save")
		_ = runner.run("netfilter-persistent", "reload")
	}

	return changed, nil
}
