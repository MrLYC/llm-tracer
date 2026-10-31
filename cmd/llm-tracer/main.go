package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/liuyicong/llm-tracer/internal/collector"
	"github.com/liuyicong/llm-tracer/internal/correlator"
	"github.com/liuyicong/llm-tracer/internal/model"
	"github.com/liuyicong/llm-tracer/internal/selfmon"
	"github.com/liuyicong/llm-tracer/internal/store"
	"github.com/liuyicong/llm-tracer/internal/totp"
	"github.com/liuyicong/llm-tracer/internal/web"
	"github.com/spf13/cobra"
)

type captureFlags struct {
	listen        string
	cacheDir      string
	window        string
	pids          []int
	pidOnly       bool
	exes          []string
	cwds          []string
	cmds          []string
	hosts         []string
	recordHeaders bool
	totpSecret    string
	exitWithChild bool
}

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	var flags captureFlags
	rootCmd := &cobra.Command{
		Use:   "llm-tracer [flags] [-- command args...]",
		Short: "基于 eCapture / eBPF uprobe 的本机大模型通信抓取与会话串联工具",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCapture(flags, args)
		},
	}
	bindCaptureFlags(rootCmd, &flags)

	var capFlags captureFlags
	captureCmd := &cobra.Command{
		Use:   "capture [flags] [-- command args...]",
		Short: "启动实时抓取与 Web 观测界面（支持 -- <cmd> 直接拉起子进程抓取）",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCapture(capFlags, args)
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
			return runView(dir, viewListen, viewWindow, viewTOTP)
		},
	}
	viewCmd.Flags().StringVarP(&viewListen, "listen", "l", "127.0.0.1:8787", "Web 界面监听地址")
	viewCmd.Flags().StringVarP(&viewWindow, "window", "w", "10m", "默认加载时间窗口 (如 10m, 1h)")
	viewCmd.Flags().StringVar(&viewTOTP, "totp-secret", os.Getenv("LLM_TRACER_TOTP_SECRET"), "可选 TOTP Base32 密钥")

	var cleanDir, cleanOlderThan string
	var cleanAll, cleanDryRun, cleanIncludeSelfmon, cleanYes bool
	cleanCmd := &cobra.Command{
		Use:   "clean",
		Short: "按时间或全量清理本地文件缓存",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runClean(cleanDir, cleanOlderThan, cleanAll, cleanDryRun, cleanIncludeSelfmon, cleanYes)
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

	rootCmd.AddCommand(captureCmd, viewCmd, cleanCmd, statusCmd, totpCmd)
	return rootCmd
}

func bindCaptureFlags(cmd *cobra.Command, f *captureFlags) {
	cmd.Flags().StringVarP(&f.listen, "listen", "l", "127.0.0.1:8787", "Web 界面监听地址")
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
	cmd.Flags().StringVar(&f.totpSecret, "totp-secret", os.Getenv("LLM_TRACER_TOTP_SECRET"), "可选 TOTP Base32 密钥，开启 Web 登录保护")
	cmd.Flags().BoolVar(&f.exitWithChild, "exit-with-child", false, "使用 -- <cmd> 拉起子进程时，子进程结束后自动退出")
}

func runCapture(flags captureFlags, launchArgs []string) error {
	winDur, err := parseDurationWithDays(flags.window)
	if err != nil {
		return fmt.Errorf("invalid --window %q: %w", flags.window, err)
	}
	guard, err := totp.NewGuard(flags.totpSecret)
	if err != nil {
		return err
	}
	mon, err := selfmon.NewMonitor(flags.cacheDir)
	if err != nil {
		return err
	}
	st, err := store.NewStore(flags.cacheDir, winDur, mon)
	if err != nil {
		return err
	}
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := col.Start(ctx); err != nil {
		return err
	}
	defer col.Stop()

		srv := web.NewServer(st, col, mon, guard)
		var httpServer *http.Server
		if flags.listen != "" && flags.listen != "off" && flags.listen != "none" {
			httpServer = &http.Server{
				Addr:    flags.listen,
				Handler: srv.Handler(),
			}
			go func() {
				mon.RecordOK(selfmon.StageWeb, "http_listen", map[string]any{
					"listen":         flags.listen,
					"window":         winDur.String(),
					"record_headers": flags.recordHeaders,
					"totp_enabled":   guard.Enabled(),
				})
				if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					mon.RecordWarn(selfmon.StageWeb, "http_listen", err.Error(), nil)
				}
			}()
		}

		fmt.Printf("LLM-Tracer Web UI : http://%s\n", flags.listen)
		fmt.Printf("Cache Directory   : %s (默认加载窗口: %s)\n", flags.cacheDir, winDur)
		fmt.Printf("Record Headers    : %v (默认关闭防凭据泄露)\n", flags.recordHeaders)
		fmt.Printf("TOTP Auth Enabled : %v\n", guard.Enabled())

		if len(launchArgs) > 0 {
			fmt.Printf("Launching Process : %s\n", strings.Join(launchArgs, " "))
			exitCode, launchErr := col.LaunchCommand(ctx, launchArgs)
			if flags.exitWithChild {
				col.Flush()
				time.Sleep(150 * time.Millisecond)
				if httpServer != nil {
					_ = httpServer.Shutdown(context.Background())
				}
				if launchErr != nil && exitCode != 0 {
					os.Exit(exitCode)
				}
				return nil
			}
		}

		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if httpServer == nil {
			return nil
		}
		return httpServer.Shutdown(shutdownCtx)
	}

func runView(cacheDir, listen, windowStr, totpSecret string) error {
	winDur, err := parseDurationWithDays(windowStr)
	if err != nil {
		return err
	}
	guard, err := totp.NewGuard(totpSecret)
	if err != nil {
		return err
	}
	mon, err := selfmon.NewMonitor(cacheDir)
	if err != nil {
		return err
	}
	st, err := store.NewStore(cacheDir, winDur, mon)
	if err != nil {
		return err
	}
	srv := web.NewServer(st, nil, mon, guard)
	fmt.Printf("LLM-Tracer Offline Viewer: http://%s (cache: %s, window: %s)\n", listen, cacheDir, winDur)
	return http.ListenAndServe(listen, srv.Handler())
}

func runClean(cacheDir, olderThan string, all, dryRun, includeSelfmon, yes bool) error {
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
		fmt.Printf("确认要清空 %s 下的全部缓存数据吗？输入 yes 继续: ", cacheDir)
		reader := bufio.NewReader(os.Stdin)
		line, _ := reader.ReadString('\n')
		if strings.TrimSpace(strings.ToLower(line)) != "yes" {
			fmt.Println("已取消清理。")
			return nil
		}
	}
	mon, err := selfmon.NewMonitor(cacheDir)
	if err != nil {
		return err
	}
	st, err := store.NewStore(cacheDir, store.DefaultHotWindow, mon)
	if err != nil {
		return err
	}
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
	fmt.Printf("[%s] 删除会话: %d 个 | 删除文件: %d 个 | 释放空间: %d 字节 (%.2f KB)\n",
		mode, rep.DeletedSessions, rep.DeletedFiles, rep.FreedBytes, float64(rep.FreedBytes)/1024.0)
	return nil
}

func runStatus(cacheDir string) error {
	mon, err := selfmon.NewMonitor(cacheDir)
	if err != nil {
		return err
	}
	st, err := store.NewStore(cacheDir, store.DefaultHotWindow, mon)
	if err != nil {
		return err
	}
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
