package collector

import (
	"path/filepath"
	"strings"
)

func isNodeLaunchTarget(baseBin, baseResolved string) bool {
	return baseBin == "node" || baseBin == "nodejs" || baseBin == "node.exe" ||
		baseResolved == "node" || baseResolved == "nodejs" || strings.HasPrefix(baseResolved, "node")
}

func isBunLaunchTarget(baseBin, baseResolved string) bool {
	return baseBin == "bun" || baseBin == "bunx" || baseBin == "bun.exe" || baseResolved == "bun"
}

func planNodeLaunch(in launchPlanInput, userArgs []string, plan *LaunchAttachPlan) {
	plan.DetectedStack = "nodejs"
	plan.NonIntrusiveOK = false
	if in.EBPFActive {
		plan.NonIntrusiveReason = "Node.js (undici/fetch/TLSSocket) 使用 BIO 流与内置根证书束，仅靠非侵入式 eBPF Uprobe 无法完整覆盖，自动通过参数完成 Runtime Hook 注入"
	} else {
		plan.NonIntrusiveReason = "当前未启用内核 eBPF Uprobe，自动通过 CLI 参数 (--require) 与环境变量完成 Node.js Runtime Hook 注入"
	}

	if !in.AutoIntrusive {
		return
	}
	plan.AutoIntrusiveTriggered = true
	if in.NodeHookJS != "" && !hasArgPrefix(userArgs, "--require") && !hasArgExact(userArgs, "-r") && !isVersionOrHelpArgs(userArgs) {
		nodeHookSlash := filepath.ToSlash(in.NodeHookJS)
		plan.InjectedArgs = []string{"--require", nodeHookSlash}
		plan.IntrusiveMethods = append(plan.IntrusiveMethods, "cli_arg:--require")
	}
}

func planBunLaunch(in launchPlanInput, userArgs []string, plan *LaunchAttachPlan) {
	plan.DetectedStack = "bun-boringssl"
	plan.NonIntrusiveOK = false
	plan.NonIntrusiveReason = "Bun 静态内嵌并 strip 了 BoringSSL 符号表，非侵入式 eBPF Uprobe 无可挂载符号"

	if !in.AutoIntrusive {
		return
	}
	plan.AutoIntrusiveTriggered = true
	if in.NodeHookJS != "" && !hasArgPrefix(userArgs, "--preload") && !isVersionOrHelpArgs(userArgs) {
		nodeHookSlash := filepath.ToSlash(in.NodeHookJS)
		plan.InjectedArgs = []string{"--preload", nodeHookSlash}
		plan.IntrusiveMethods = append(plan.IntrusiveMethods, "cli_arg:--preload")
	}
}

func planNodeBunEnvMethods(in launchPlanInput, isNode, isBun bool, plan *LaunchAttachPlan) {
	if in.NodeHookJS == "" {
		return
	}
	if isNode {
		plan.IntrusiveMethods = appendUniqueStr(plan.IntrusiveMethods, "env:NODE_OPTIONS")
	}
	if isBun {
		plan.IntrusiveMethods = appendUniqueStr(plan.IntrusiveMethods, "env:BUN_OPTIONS")
	}
}

func applyNodeBunLaunchEnv(
	in launchPlanInput,
	isNode, isBun bool,
	plan *LaunchAttachPlan,
	env []string,
	setAndTrackEnv func(env []string, k, v string) []string,
) []string {
	if in.NodeHookJS == "" {
		return env
	}
	nodeHookSlash := filepath.ToSlash(in.NodeHookJS)
	reqOpt := "--require " + nodeHookSlash
	if existingNodeOpts := lookupEnvVar(env, "NODE_OPTIONS"); existingNodeOpts != "" {
		env = setAndTrackEnv(env, "NODE_OPTIONS", existingNodeOpts+" "+reqOpt)
	} else {
		env = setAndTrackEnv(env, "NODE_OPTIONS", reqOpt)
	}
	preloadOpt := "--preload " + nodeHookSlash
	if existingBunOpts := lookupEnvVar(env, "BUN_OPTIONS"); existingBunOpts != "" {
		env = setAndTrackEnv(env, "BUN_OPTIONS", existingBunOpts+" "+preloadOpt)
	} else {
		env = setAndTrackEnv(env, "BUN_OPTIONS", preloadOpt)
	}
	if isNode {
		plan.IntrusiveMethods = appendUniqueStr(plan.IntrusiveMethods, "env:NODE_OPTIONS")
	}
	if isBun {
		plan.IntrusiveMethods = appendUniqueStr(plan.IntrusiveMethods, "env:BUN_OPTIONS")
	}
	return env
}
