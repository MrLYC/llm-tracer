package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/mrlyc/llm-tracer/internal/collector"
	"github.com/mrlyc/llm-tracer/internal/correlator"
	"github.com/mrlyc/llm-tracer/internal/model"
	"github.com/mrlyc/llm-tracer/internal/selfmon"
	"github.com/mrlyc/llm-tracer/internal/store"
	"github.com/mrlyc/llm-tracer/internal/totp"
	"github.com/mrlyc/llm-tracer/internal/web"
	"github.com/spf13/cobra"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func formatVersion() string {
	ver := strings.TrimSpace(version)
	if ver == "" {
		ver = "dev"
	}
	var meta []string
	if !isEmptyBuildMeta(commit) {
		meta = append(meta, strings.TrimSpace(commit))
	}
	if !isEmptyBuildMeta(date) {
		meta = append(meta, strings.TrimSpace(date))
	}
	if len(meta) == 0 {
		return fmt.Sprintf("llm-tracer version %s", ver)
	}
	return fmt.Sprintf("llm-tracer version %s (%s)", ver, strings.Join(meta, ", "))
}

func isEmptyBuildMeta(v string) bool {
	v = strings.TrimSpace(v)
	return v == "" || strings.EqualFold(v, "none") || strings.EqualFold(v, "unknown")
}

const (
	defaultReadHeaderTimeout = 10 * time.Second
	defaultIdleTimeout       = 120 * time.Second
)

type exitCodeError struct {
	code int
	err  error
}

func (e *exitCodeError) Error() string {
	if e.err != nil {
		return fmt.Sprintf("child process exited with code %d: %v", e.code, e.err)
	}
	return fmt.Sprintf("child process exited with code %d", e.code)
}

func (e *exitCodeError) Unwrap() error {
	return e.err
}

type captureFlags struct {
	listen               string
	proxyListen          string
	cacheDir             string
	window               string
	pids                 []int
	pidOnly              bool
	exes                 []string
	cwds                 []string
	cmds                 []string
	hosts                []string
	recordHeaders        bool
	allowWebHeaderToggle bool
	totpSecret           string
	exitWithChild        bool
	injectLive           bool
	autoIntrusive        bool
	tapInsecure          bool
	captureUnknown       bool
	yes                  bool
}

func main() {
	if err := newRootCmd().Execute(); err != nil {
		var exitErr *exitCodeError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.code)
		}
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	var flags captureFlags
	rootCmd := &cobra.Command{
		Use:           "llm-tracer [flags] [-- command args...]",
		Short:         "基于 eCapture / eBPF uprobe 的本机大模型通信抓取与会话串联工具",
		Version:       formatVersion(),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCaptureWithContext(cmd.Context(), flags, args)
		},
	}
	rootCmd.SetVersionTemplate("{{.Version}}\n")
	bindCaptureFlags(rootCmd, &flags)

	var capFlags captureFlags
	captureCmd := &cobra.Command{
		Use:           "capture [flags] [-- command args...]",
		Short:         "启动实时抓取与 Web 观测界面（支持 -- <cmd> 直接拉起子进程抓取）",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCaptureWithContext(cmd.Context(), capFlags, args)
		},
	}
	bindCaptureFlags(captureCmd, &capFlags)

	var viewListen, viewWindow, viewTOTP string
	viewCmd := &cobra.Command{
		Use:   "view [cache-dir]",
		Short: "以只读模式打开本地缓存目录进行离线回放与时间轴浏览",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := "./traces"
			if len(args) > 0 {
				dir = args[0]
			}
			return runViewWithContext(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), dir, viewListen, viewWindow, viewTOTP)
		},
	}
	viewCmd.Flags().StringVarP(&viewListen, "listen", "l", "127.0.0.1:8787", "Web 界面监听地址")
	viewCmd.Flags().StringVarP(&viewWindow, "window", "w", "10m", "默认加载时间窗口 (如 10m, 1h)")
	viewCmd.Flags().StringVar(&viewTOTP, "totp-secret", "", "可选 TOTP Base32 密钥（未指定时读取 LLM_TRACER_TOTP_SECRET；通过 argv 传入会在 /proc/<pid>/cmdline 中可见，建议用环境变量）")

	var cleanDir, cleanOlderThan string
	var cleanAll, cleanDryRun, cleanIncludeSelfmon, cleanYes bool
	cleanCmd := &cobra.Command{
		Use:   "clean",
		Short: "按时间或全量清理本地文件缓存",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCleanWithIO(cmd.InOrStdin(), cmd.OutOrStdout(), cleanDir, cleanOlderThan, cleanAll, cleanDryRun, cleanIncludeSelfmon, cleanYes)
		},
	}
	cleanCmd.Flags().StringVarP(&cleanDir, "cache-dir", "d", "./traces", "缓存目录路径")
	cleanCmd.Flags().StringVar(&cleanOlderThan, "older-than", "", "清理早于指定时长的缓存 (如 10m, 1h, 24h, 7d)")
	cleanCmd.Flags().BoolVar(&cleanAll, "all", false, "清理全部缓存会话")
	cleanCmd.Flags().BoolVar(&cleanDryRun, "dry-run", false, "仅预览将被删除的会话和释放空间，不实际删除")
	cleanCmd.Flags().BoolVar(&cleanIncludeSelfmon, "include-selfmon", false, "同时清理自监控日志")
	cleanCmd.Flags().BoolVarP(&cleanYes, "yes", "y", false, "跳过交互式二次确认")

	var statusDir string
	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "检查本机 OpenSSL/GoTLS 探针符号、缓存统计与自监控状态",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStatus(statusDir)
		},
	}
	statusCmd.Flags().StringVarP(&statusDir, "cache-dir", "d", "./traces", "缓存目录路径")

	totpCmd := &cobra.Command{
		Use:   "totp",
		Short: "生成新的 TOTP 密钥与 otpauth 二维码 URI",
		RunE: func(cmd *cobra.Command, args []string) error {
			sec, err := totp.GenerateSecret()
			if err != nil {
				return err
			}
			code, _ := totp.GenerateCode(sec, time.Now())
			uri := totp.ProvisioningURI("llm-tracer", "admin", sec)
			fmt.Printf("TOTP Secret : %s\n", sec)
			fmt.Printf("Current Code: %s\n", code)
			fmt.Printf("OTPAuth URI : %s\n", uri)
			fmt.Printf("\n启动示例: llm-tracer capture --totp-secret %s\n", sec)
			return nil
		},
	}

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "显示版本信息",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintln(cmd.OutOrStdout(), formatVersion())
		},
	}

	rootCmd.AddCommand(captureCmd, viewCmd, cleanCmd, statusCmd, totpCmd, versionCmd)
	return rootCmd
}

func bindCaptureFlags(cmd *cobra.Command, f *captureFlags) {
	cmd.Flags().StringVarP(&f.listen, "listen", "l", "127.0.0.1:8787", "Web 界面监听地址")
	cmd.Flags().StringVar(&f.proxyListen, "proxy-listen", "127.0.0.1:0", "本地 HTTP/HTTPS 抓包代理监听地址 (默认随机端口 127.0.0.1:0)")
	cmd.Flags().StringVarP(&f.cacheDir, "cache-dir", "d", "./traces", "本地文件缓存目录")
	cmd.Flags().StringVarP(&f.window, "window", "w", "10m", "默认预加载时间窗 (默认 10m)")
	cmd.Flags().IntSliceVarP(&f.pids, "pid", "p", nil, "指定抓取的 PID 列表 (默认包含其所有后代子进程)")
	cmd.Flags().BoolVar(&f.pidOnly, "pid-only", false, "仅抓取指定的单个 PID 本身，不追踪其子进程")
	cmd.Flags().StringSliceVar(&f.exes, "exe", nil, "指定抓取的二进制文件路径 (如 /usr/bin/python3)")
	cmd.Flags().StringSliceVar(&f.exes, "binary", nil, "指定抓取的二进制文件路径 (--exe 别名)")
	cmd.Flags().StringSliceVar(&f.cwds, "cwd", nil, "指定抓取的工作目录范围")
	cmd.Flags().StringSliceVar(&f.cmds, "cmd", nil, "按进程名或命令行子串过滤")
	cmd.Flags().StringSliceVar(&f.hosts, "host", nil, "按目标域名过滤 (如 api.bamboonode.dev)")
	cmd.Flags().BoolVar(&f.recordHeaders, "record-headers", false, "记录 HTTP 请求与响应头 (默认 false 以避免凭据泄露)")
	cmd.Flags().BoolVar(&f.allowWebHeaderToggle, "allow-web-header-toggle", false, "允许通过 Web 界面动态翻转 record_headers 红线开关 (默认 false)")
	cmd.Flags().StringVar(&f.totpSecret, "totp-secret", "", "可选 TOTP Base32 密钥，开启 Web 登录保护（未指定时读取 LLM_TRACER_TOTP_SECRET；通过 argv 传入会在 /proc/<pid>/cmdline 中可见，建议用环境变量）")
	cmd.Flags().BoolVar(&f.exitWithChild, "exit-with-child", false, "使用 -- <cmd> 拉起子进程时，子进程结束后自动退出")
	cmd.Flags().BoolVar(&f.injectLive, "inject-live", false, "按 --pid/--exe/--cwd/--cmd 匹配运行中进程时，若 eBPF 无法直接覆盖 TLS，自动执行免重启侵入式热注入")
	cmd.Flags().BoolVar(&f.autoIntrusive, "auto-intrusive", true, "使用 -- <cmd> 直接拉起子程序时，若无法使用非侵入式方式，自动通过参数完成侵入式方案")
	cmd.Flags().BoolVar(&f.tapInsecure, "tap-insecure", false, "跳过 LoopbackTap 对非回环上游 HTTPS 服务端证书的校验")
	cmd.Flags().BoolVar(&f.captureUnknown, "capture-unknown", false, "保留未识别协议 (unknown) 的 HTTP 通信事件，用于无限制采集")
	cmd.Flags().BoolVarP(&f.yes, "yes", "y", false, "跳过侵入式热注入二次确认提示")
}

var listenCaptureTCP = net.Listen

func runCapture(flags captureFlags, launchArgs []string) error {
	return runCaptureWithContext(context.Background(), flags, launchArgs)
}

func runCaptureWithContext(parentCtx context.Context, flags captureFlags, launchArgs []string) error {
	if parentCtx == nil {
		parentCtx = context.Background()
	}
	winDur, err := parseDurationWithDays(flags.window)
	if err != nil {
		return fmt.Errorf("invalid --window %q: %w", flags.window, err)
	}
	guard, err := totp.NewGuard(resolveTOTPSecret(flags.totpSecret))
	if err != nil {
		return err
	}
	mon, err := selfmon.NewMonitor(flags.cacheDir)
	if err != nil {
		return err
	}
	defer func() {
		_ = mon.Flush()
		_ = mon.Close()
	}()
	st, err := store.NewStore(flags.cacheDir, winDur, mon)
	if err != nil {
		return err
	}
	defer func() {
		_ = st.Flush()
		_ = st.Close()
	}()
	corr := correlator.NewCorrelator(mon)
	scope := model.ScopeFilter{
		PIDs:          flags.pids,
		PIDOnly:       flags.pidOnly,
		Exes:          flags.exes,
		Cwds:          flags.cwds,
		Cmds:          flags.cmds,
		Hosts:         flags.hosts,
		RecordHeaders: flags.recordHeaders,
	}
	col, err := collector.NewCollector(flags.cacheDir, scope, corr, st, mon)
	if err != nil {
		return err
	}
	col.SetAutoIntrusive(flags.autoIntrusive)
	col.SetAutoInjectLive(flags.injectLive || flags.yes)
	col.SetProxyListen(flags.proxyListen)
	col.SetTapInsecure(flags.tapInsecure)
	applyCaptureUnknown(col, flags.captureUnknown)

	ctx, stop := signal.NotifyContext(parentCtx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := col.Start(ctx); err != nil {
		return err
	}
	defer col.Stop()

	srv := web.NewServer(
		st,
		col,
		mon,
		guard,
		web.WithListenAddr(flags.listen),
		web.WithAllowWebHeaderToggle(flags.allowWebHeaderToggle),
	)
	var httpServer *http.Server
	var shutdownOnce sync.Once
	var shutdownErr error
	shutdownAll := func(shutdownCtx context.Context) error {
		shutdownOnce.Do(func() {
			_ = srv.Close()
			// 严格退出顺序：先停 collector，再 flush/close store 和 selfmon，最后关 HTTP server
			col.Flush()
			col.Stop()
			_ = st.Flush()
			_ = st.Close()
			_ = mon.Flush()
			_ = mon.Close()
			if httpServer != nil {
				if err := httpServer.Shutdown(shutdownCtx); err != nil &&
					!errors.Is(err, context.DeadlineExceeded) &&
					!errors.Is(err, context.Canceled) &&
					!errors.Is(err, http.ErrServerClosed) {
					shutdownErr = err
				}
				_ = httpServer.Close()
			}
		})
		return shutdownErr
	}

	if !isWebListenDisabled(flags.listen) {
		warnIfNonLoopbackWithoutTOTP(flags.listen, guard, mon)
		ln, listenErr := listenCaptureTCP("tcp", flags.listen)
		if listenErr != nil {
			mon.RecordError(selfmon.StageWeb, "http_listen", listenErr, map[string]any{
				"listen": flags.listen,
			})
			fmt.Fprintf(os.Stderr, "Error: failed to listen on %s: %v\n", flags.listen, listenErr)
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = shutdownAll(shutdownCtx)
			return &exitCodeError{code: 1, err: fmt.Errorf("listen %s: %w", flags.listen, listenErr)}
		}
		httpServer = &http.Server{
			Addr:              flags.listen,
			Handler:           srv.Handler(),
			ReadHeaderTimeout: defaultReadHeaderTimeout,
			IdleTimeout:       defaultIdleTimeout,
		}
		httpServer.RegisterOnShutdown(func() {
			_ = srv.Close()
		})
		mon.RecordOK(selfmon.StageWeb, "http_listen", map[string]any{
			"listen":         flags.listen,
			"window":         winDur.String(),
			"record_headers": flags.recordHeaders,
			"totp_enabled":   guard.Enabled(),
		})
		go func() {
			if err := httpServer.Serve(ln); err != nil && err != http.ErrServerClosed {
				mon.RecordWarn(selfmon.StageWeb, "http_listen", err.Error(), nil)
			}
		}()
		fmt.Printf("LLM-Tracer Web UI : http://%s\n", flags.listen)
	} else {
		fmt.Println("LLM-Tracer Web UI : Web UI 已禁用")
	}
	fmt.Printf("Cache Directory   : %s (默认加载窗口: %s)\n", flags.cacheDir, winDur)
	if col.ProxyURL() != "" {
		fmt.Printf("HTTP/HTTPS Proxy  : %s (CA: %s)\n", col.ProxyURL(), col.CABundlePath())
	}
	fmt.Printf("Record Headers    : %v (默认关闭防凭据泄露)\n", flags.recordHeaders)
	fmt.Printf("TOTP Auth Enabled : %v\n", guard.Enabled())

	if len(flags.pids) > 0 || len(flags.exes) > 0 || len(flags.cwds) > 0 || len(flags.cmds) > 0 {
		handleLivePIDAttachPlans(col, flags.injectLive || flags.yes)
	}

	if len(launchArgs) > 0 {
		fmt.Printf("Launching Process : %s\n", strings.Join(launchArgs, " "))
		var (
			exitCode  int
			launchErr error
		)
		plan, env, planErr := col.PlanLaunchCommand(launchArgs)
		if planErr != nil {
			mon.RecordError(selfmon.StageTracker, "launch_command", planErr, map[string]any{"cmd": launchArgs})
			exitCode = 127
			launchErr = planErr
		} else {
			if plan != nil {
				if plan.NonIntrusiveOK {
					fmt.Printf("[Launch %s] 自动识别: %s | 非侵入式 eBPF Uprobe 可直接覆盖 (%s)\n",
						launchArgs[0], plan.DetectedStack, plan.NonIntrusiveReason)
				} else if plan.AutoIntrusiveTriggered {
					fmt.Printf("[Launch %s] 自动识别: %s | 诊断: %s\n",
						launchArgs[0], plan.DetectedStack, plan.NonIntrusiveReason)
					fmt.Printf("  └─ 已通过参数自动完成侵入式方案: methods=%v injected_args=%v ptrace=%v\n",
						plan.IntrusiveMethods, plan.InjectedArgs, plan.PtraceWrapped)
				}
			}
			exitCode, launchErr = col.LaunchPlannedCommand(ctx, plan, env)
		}
		if flags.exitWithChild {
			col.Flush()
			time.Sleep(150 * time.Millisecond)
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = shutdownAll(shutdownCtx)
			if launchErr != nil && exitCode != 0 {
				return &exitCodeError{code: exitCode, err: launchErr}
			}
			return nil
		}
	}

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return shutdownAll(shutdownCtx)
}

func applyCaptureUnknown(col *collector.Collector, captureUnknown bool) bool {
	dropUnknown := !captureUnknown
	if s, ok := any(col).(interface{ SetDropUnknown(bool) }); ok {
		s.SetDropUnknown(dropUnknown)
		return true
	}
	if s, ok := any(col).(interface{ SetCaptureUnknown(bool) }); ok {
		s.SetCaptureUnknown(captureUnknown)
		return true
	}
	return false
}

func resolveTOTPSecret(flagVal string) string {
	if s := strings.TrimSpace(flagVal); s != "" {
		return s
	}
	return strings.TrimSpace(os.Getenv("LLM_TRACER_TOTP_SECRET"))
}

func isLoopbackListenAddr(listen string) bool {
	if isWebListenDisabled(listen) {
		return true
	}
	trimmed := strings.TrimSpace(listen)
	host := trimmed
	if h, _, err := net.SplitHostPort(trimmed); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSpace(strings.Trim(host, "[]")))
	if host == "" {
		return false
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

func isWebListenDisabled(listen string) bool {
	trimmed := strings.TrimSpace(listen)
	return trimmed == "" || strings.EqualFold(trimmed, "off") || strings.EqualFold(trimmed, "none")
}

func warnIfNonLoopbackWithoutTOTP(listen string, guard *totp.Guard, mon *selfmon.Monitor) {
	if isLoopbackListenAddr(listen) {
		return
	}
	if guard != nil && guard.Enabled() {
		return
	}
	warnMsg := fmt.Sprintf("监听地址 %s 非回环地址且未开启 TOTP 认证，Web 界面可被同网段访问；建议增加 --totp-secret 参数开启登录保护", listen)
	fmt.Printf("[WARNING] %s\n", warnMsg)
	if mon != nil {
		mon.RecordWarn(selfmon.StageWeb, "non_loopback_without_totp", warnMsg, map[string]any{
			"listen":       listen,
			"totp_enabled": false,
		})
	}
}

func handleLivePIDAttachPlans(col *collector.Collector, autoInject bool) {
	plans := col.AnalyzePIDPlans()
	for _, p := range plans {
		if !p.IntrusiveNeeded && p.EBPFStatus == "attached" {
			fmt.Printf("[PID %d (%s)] 自动识别: %s | 挂载模式: %s (免重启零侵入)\n  └─ %s\n",
				p.PID, p.Comm, p.DetectedStack, p.ActiveMode, p.EBPFReason)
			continue
		}
		fmt.Printf("[!] [PID %d (%s)] 自动识别: %s | eBPF 状态: %s\n", p.PID, p.Comm, p.DetectedStack, p.EBPFStatus)
		fmt.Printf("  ├─ 诊断原因: %s\n", p.EBPFReason)
		fmt.Printf("  └─ 候选侵入式方案: [%s] %s\n", p.RecommendedIntrusive, p.IntrusiveDescription)
		shouldInject := autoInject
		if !shouldInject && isInteractiveStdin() {
			fmt.Printf("  ? 是否立即对运行中 PID %d (%s) 执行 [%s] 免重启侵入式热注入？[y/N]: ",
				p.PID, p.Comm, p.RecommendedIntrusive)
			reader := bufio.NewReader(os.Stdin)
			line, _ := reader.ReadString('\n')
			ans := strings.TrimSpace(strings.ToLower(line))
			shouldInject = ans == "y" || ans == "yes"
		}
		if shouldInject {
			updated, err := col.InjectRunningPID(p.PID)
			if err != nil {
				fmt.Printf("  [x] PID %d 侵入式热注入失败: %v\n", p.PID, err)
			} else {
				fmt.Printf("  [+] PID %d 已完成免重启热注入 (模式: %s)\n", p.PID, updated.ActiveMode)
			}
		} else {
			fmt.Printf("  -> 未执行侵入式注入（如需启用，可加 --inject-live 参数或调用 POST /api/pid/inject）\n")
		}
	}
}

func isInteractiveStdin() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

var listenViewTCP = net.Listen

func runView(cacheDir, listen, windowStr, totpSecret string) error {
	return runViewWithContext(context.Background(), os.Stdout, os.Stderr, cacheDir, listen, windowStr, totpSecret)
}

func runViewWithContext(parentCtx context.Context, out, errOut io.Writer, cacheDir, listen, windowStr, totpSecret string) error {
	if parentCtx == nil {
		parentCtx = context.Background()
	}
	if out == nil {
		out = os.Stdout
	}
	if errOut == nil {
		errOut = os.Stderr
	}
	winDur, err := parseDurationWithDays(windowStr)
	if err != nil {
		return err
	}
	guard, err := totp.NewGuard(resolveTOTPSecret(totpSecret))
	if err != nil {
		return err
	}
	st, err := store.OpenReadOnly(cacheDir, winDur)
	if err != nil {
		return err
	}
	defer func() {
		_ = st.Close()
	}()
	srv := web.NewServer(st, nil, nil, guard, web.WithListenAddr(listen))
	warnIfNonLoopbackWithoutTOTP(listen, guard, nil)
	ln, err := listenViewTCP("tcp", listen)
	if err != nil {
		fmt.Fprintf(errOut, "Error: failed to listen on %s: %v\n", listen, err)
		_ = st.Close()
		return &exitCodeError{code: 1, err: fmt.Errorf("listen %s: %w", listen, err)}
	}
	fmt.Fprintf(out, "LLM-Tracer Offline Viewer: http://%s (cache: %s, window: %s)\n", listen, cacheDir, winDur)
	httpServer := &http.Server{
		Addr:              listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: defaultReadHeaderTimeout,
		IdleTimeout:       defaultIdleTimeout,
	}
	httpServer.RegisterOnShutdown(func() {
		_ = srv.Close()
	})
	ctx, stop := signal.NotifyContext(parentCtx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		if err := httpServer.Serve(ln); err != nil && err != http.ErrServerClosed {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case err := <-errCh:
		_ = srv.Close()
		_ = st.Close()
		return err
	case <-ctx.Done():
		_ = srv.Close()
		_ = st.Close()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		err := httpServer.Shutdown(shutdownCtx)
		_ = httpServer.Close()
		if err != nil &&
			!errors.Is(err, context.DeadlineExceeded) &&
			!errors.Is(err, context.Canceled) &&
			!errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}

func runClean(cacheDir, olderThan string, all, dryRun, includeSelfmon, yes bool) error {
	return runCleanWithIO(os.Stdin, os.Stdout, cacheDir, olderThan, all, dryRun, includeSelfmon, yes)
}

func runCleanWithIO(in io.Reader, out io.Writer, cacheDir, olderThan string, all, dryRun, includeSelfmon, yes bool) error {
	if in == nil {
		in = os.Stdin
	}
	if out == nil {
		out = os.Stdout
	}
	var dur time.Duration
	if olderThan != "" {
		d, err := parseDurationWithDays(olderThan)
		if err != nil {
			return fmt.Errorf("无效的 --older-than 参数 %q: %w", olderThan, err)
		}
		dur = d
	}
	if !all && dur <= 0 {
		return fmt.Errorf("请指定 --older-than <duration> (例如 10m, 24h) 或 --all")
	}
	if all && !dryRun && !yes {
		fmt.Fprintf(out, "确认要清空 %s 下的全部缓存数据吗？输入 yes 继续: ", cacheDir)
		reader := bufio.NewReader(in)
		line, _ := reader.ReadString('\n')
		if strings.TrimSpace(strings.ToLower(line)) != "yes" {
			fmt.Fprintln(out, "已取消清理。")
			return nil
		}
	}
	st, err := store.NewStore(cacheDir, store.DefaultHotWindow, nil)
	if err != nil {
		return err
	}
	defer func() {
		_ = st.Flush()
		_ = st.Close()
	}()
	rep, err := st.Clean(store.CleanOptions{
		OlderThan:      dur,
		All:            all,
		DryRun:         dryRun,
		IncludeSelfmon: includeSelfmon,
	})
	if err != nil {
		return err
	}
	mode := "已清理"
	if rep.DryRun {
		mode = "Dry-Run 预览"
	}
	fmt.Fprintf(out, "[%s] 删除会话: %d 个 | 删除文件: %d 个 | 释放空间: %d 字节 (%.2f KB)\n",
		mode, rep.DeletedSessions, rep.DeletedFiles, rep.FreedBytes, float64(rep.FreedBytes)/1024.0)
	return nil
}

func runStatus(cacheDir string) error {
	mon, err := selfmon.NewMonitor(cacheDir)
	if err != nil {
		return err
	}
	defer func() {
		_ = mon.Flush()
		_ = mon.Close()
	}()
	st, err := store.NewStore(cacheDir, store.DefaultHotWindow, mon)
	if err != nil {
		return err
	}
	defer func() {
		_ = st.Flush()
		_ = st.Close()
	}()
	exeSelf, _ := os.Executable()
	probes := collector.ProbeAndRecordTargets(nil, []string{exeSelf}, mon)
	out := map[string]any{
		"cache_dir": cacheDir,
		"probes":    probes,
		"timeline":  st.TimelineOverview(12),
		"selfmon":   mon.Stats(),
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(b))
	return nil
}

func parseDurationWithDays(s string) (time.Duration, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if strings.HasSuffix(s, "d") {
		days, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil {
			return 0, err
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}
