package collector

import "fmt"

func planNativeLaunch(in launchPlanInput, _ []string, plan *LaunchAttachPlan) {
	isGo := in.GoTarget != nil && len(in.GoTarget.Symbols) > 0
	prof := in.Profile
	archCap := resolvePlanArchCapabilities(in)

	switch {
	case isGo:
		plan.DetectedStack = "gotls"
		if in.EBPFActive {
			plan.NonIntrusiveOK = true
			plan.NonIntrusiveReason = fmt.Sprintf("已自动解析 GoTLS (%s) 函数偏移 (含 .gopclntab 恢复) 并挂载非侵入式内核 eBPF Uprobe", in.GoTarget.GoVersion)
		} else {
			plan.NonIntrusiveOK = false
			if archCap.PtraceUserspaceSupported {
				plan.NonIntrusiveReason = fmt.Sprintf("已解析 GoTLS (%s) 符号偏移，但当前无内核 eBPF 权限，自动通过参数完成代理/证书与 ptrace 侵入式方案", in.GoTarget.GoVersion)
			} else {
				plan.NonIntrusiveReason = fmt.Sprintf("已解析 GoTLS (%s) 符号偏移，但当前无内核 eBPF 权限且 %s 架构不支持内置用户态 ptrace 注入器 (PtraceUserspaceSupported=false)，已跳过 ptrace 并自动降级为代理/证书侵入式方案", in.GoTarget.GoVersion, archCap.Arch)
			}
		}
	case prof != nil && (prof.TLSStack == "dynamic-libssl" || prof.TLSStack == "static-openssl"):
		plan.DetectedStack = prof.TLSStack
		if in.EBPFActive {
			plan.NonIntrusiveOK = true
			plan.NonIntrusiveReason = fmt.Sprintf("已识别 %s 并挂载非侵入式内核 eBPF Uprobe (SSL_write/SSL_read)", prof.TLSStack)
		} else {
			plan.NonIntrusiveOK = false
			plan.NonIntrusiveReason = fmt.Sprintf("已识别 %s，但当前未启用内核 eBPF 引擎，自动通过参数完成 LD_PRELOAD/DYLD_INSERT_LIBRARIES 与代理注入", prof.TLSStack)
		}
	case prof != nil && prof.RequiresPtrace:
		plan.DetectedStack = "static-pie"
		plan.NonIntrusiveOK = false
		if archCap.PtraceUserspaceSupported {
			plan.NonIntrusiveReason = "目标程序为无 PT_INTERP 的静态链接二进制且无 OpenSSL/GoTLS 符号，非侵入式 eBPF Uprobe 无法解密，自动通过参数完成 ptrace + 代理注入"
		} else {
			plan.NonIntrusiveReason = fmt.Sprintf("目标程序为无 PT_INTERP 的静态链接二进制且无 OpenSSL/GoTLS 符号，非侵入式 eBPF Uprobe 无法解密；当前 %s 架构不支持内置用户态 ptrace 注入器 (PtraceUserspaceSupported=false)，已跳过 ptrace 包装并降级为代理注入", archCap.Arch)
		}
	default:
		plan.DetectedStack = "stripped-embedded-tls"
		plan.NonIntrusiveOK = false
		plan.NonIntrusiveReason = "目标程序使用内嵌/strip TLS 栈 (如 rustls/BoringSSL)，无导出 TLS 符号可供非侵入式 eBPF Uprobe 挂载，自动通过参数完成代理证书与 Hook 注入"
	}

	if in.AutoIntrusive && !plan.NonIntrusiveOK {
		plan.AutoIntrusiveTriggered = true
	}
}

func planNativePtraceWrap(in launchPlanInput, archCap ebpfArchCapabilities, childArgs []string, plan *LaunchAttachPlan) {
	execBin := in.BinPath
	execArgs := childArgs
	isGoFallback := in.GoTarget != nil && len(in.GoTarget.Symbols) > 0 && !in.EBPFActive
	needsPtrace := in.AutoIntrusive && !plan.NonIntrusiveOK && ((in.Profile != nil && in.Profile.RequiresPtrace) || isGoFallback)

	if needsPtrace && !archCap.PtraceUserspaceSupported {
		notice := fmt.Sprintf("linux/%s 能力表 PtraceUserspaceSupported=false（内置用户态 ptrace 注入器仅支持 x86_64），已跳过 ptrace_wrapper 包装并降级为代理/环境变量方案", archCap.Arch)
		if archCap.DegradationNotice != "" {
			notice = fmt.Sprintf("%s [%s]", notice, archCap.DegradationNotice)
		}
		plan.DegradationNotices = appendUniqueStr(plan.DegradationNotices, notice)
	} else if in.AutoIntrusive && !plan.NonIntrusiveOK && in.Profile != nil && in.Profile.RequiresPtrace && in.PtraceBin != "" && archCap.PtraceUserspaceSupported {
		execBin = in.PtraceBin
		execArgs = append([]string{in.BinPath}, childArgs...)
		plan.PtraceWrapped = true
		plan.IntrusiveMethods = append(plan.IntrusiveMethods, "ptrace_wrapper")
	}
	plan.ExecBin = execBin
	plan.ExecArgs = execArgs
}

func planNativePreloadMethods(in launchPlanInput, isJVM bool, plan *LaunchAttachPlan) {
	if in.PreloadPath == "" || isJVM {
		return
	}
	switch in.GOOS {
	case "darwin":
		plan.IntrusiveMethods = appendUniqueStr(plan.IntrusiveMethods, "preload:dyld_insert_libraries")
	case "linux":
		plan.IntrusiveMethods = appendUniqueStr(plan.IntrusiveMethods, "preload:ld_preload")
	}
}

func planNativeTapMethods(in launchPlanInput, isJVM bool, resolvedELF string, plan *LaunchAttachPlan) {
	if !in.TapActive {
		return
	}
	if nativeNeedsProxyEnv(in, resolvedELF) {
		plan.IntrusiveMethods = appendUniqueStr(plan.IntrusiveMethods, "env:HTTPS_PROXY", "env:SSL_CERT_FILE", "loopback_tap")
	}
	if isJVM {
		plan.IntrusiveMethods = appendUniqueStr(plan.IntrusiveMethods, "loopback_tap")
	}
}

func nativeNeedsProxyEnv(in launchPlanInput, resolvedELF string) bool {
	isRuntime := isShellOrRuntimeBinary(in.BinPath) || isShellOrRuntimeBinary(resolvedELF)
	return !isRuntime &&
		(in.GOOS != "linux" || (in.Profile != nil && (in.Profile.RequiresPtrace || in.Profile.TLSStack == "stripped-embedded-tls")))
}

func applyNativePreloadEnv(
	in launchPlanInput,
	isJVM bool,
	plan *LaunchAttachPlan,
	env []string,
	setAndTrackEnv func(env []string, k, v string) []string,
) []string {
	if in.PreloadPath == "" || isJVM {
		return env
	}
	switch in.GOOS {
	case "darwin":
		if existingDyld := lookupEnvVar(env, "DYLD_INSERT_LIBRARIES"); existingDyld != "" {
			env = setAndTrackEnv(env, "DYLD_INSERT_LIBRARIES", in.PreloadPath+":"+existingDyld)
		} else {
			env = setAndTrackEnv(env, "DYLD_INSERT_LIBRARIES", in.PreloadPath)
		}
		if in.Profile != nil && in.Profile.TLSStack == "dynamic-libssl" {
			env = setAndTrackEnv(env, "DYLD_FORCE_FLAT_NAMESPACE", "1")
		}
		plan.IntrusiveMethods = appendUniqueStr(plan.IntrusiveMethods, "preload:dyld_insert_libraries")
	case "linux":
		if existingPreload := lookupEnvVar(env, "LD_PRELOAD"); existingPreload != "" {
			env = setAndTrackEnv(env, "LD_PRELOAD", in.PreloadPath+":"+existingPreload)
		} else {
			env = setAndTrackEnv(env, "LD_PRELOAD", in.PreloadPath)
		}
		plan.IntrusiveMethods = appendUniqueStr(plan.IntrusiveMethods, "preload:ld_preload")
	}
	return env
}

func applyNativeTapEnv(
	in launchPlanInput,
	isJVM bool,
	resolvedELF string,
	plan *LaunchAttachPlan,
	env []string,
	setAndTrackEnv func(env []string, k, v string) []string,
) []string {
	if !in.TapActive {
		return env
	}
	env = setAndTrackEnv(env, "LLM_TRACER_PROXY_HOST", in.ProxyHost)
	env = setAndTrackEnv(env, "LLM_TRACER_PROXY_PORT", in.ProxyPort)
	env = setAndTrackEnv(env, "SSL_CERT_FILE", in.CABundlePath)
	env = setAndTrackEnv(env, "CURL_CA_BUNDLE", in.CABundlePath)
	env = setAndTrackEnv(env, "REQUESTS_CA_BUNDLE", in.CABundlePath)
	env = setAndTrackEnv(env, "NODE_EXTRA_CA_CERTS", in.CABundlePath)
	env = setAndTrackEnv(env, "CARGO_HTTP_CAINFO", in.CABundlePath)

	needsProxyEnv := nativeNeedsProxyEnv(in, resolvedELF)
	env = unsetEnvVar(env, "ALL_PROXY")
	env = unsetEnvVar(env, "all_proxy")
	env = unsetEnvVar(env, "NO_PROXY")
	env = unsetEnvVar(env, "no_proxy")
	if needsProxyEnv {
		archCap := resolvePlanArchCapabilities(in)
		env = setAndTrackEnv(env, "HTTPS_PROXY", in.ProxyURL)
		env = setAndTrackEnv(env, "https_proxy", in.ProxyURL)
		plan.IntrusiveMethods = appendUniqueStr(plan.IntrusiveMethods, "env:HTTPS_PROXY", "env:SSL_CERT_FILE", "loopback_tap")
		if !in.CanUsePtrace || !archCap.PtraceUserspaceSupported || (in.Profile != nil && in.Profile.TLSStack == "stripped-embedded-tls") {
			env = setAndTrackEnv(env, "HTTP_PROXY", in.ProxyURL)
			env = setAndTrackEnv(env, "http_proxy", in.ProxyURL)
		}
	} else {
		env = unsetEnvVar(env, "HTTPS_PROXY")
		env = unsetEnvVar(env, "https_proxy")
		env = unsetEnvVar(env, "HTTP_PROXY")
		env = unsetEnvVar(env, "http_proxy")
	}
	if isJVM {
		plan.IntrusiveMethods = appendUniqueStr(plan.IntrusiveMethods, "loopback_tap")
	}
	return env
}
