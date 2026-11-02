package collector

import (
	"os"
	"strings"
)

func isPythonLaunchTarget(baseBin, baseResolved string) bool {
	return strings.HasPrefix(baseBin, "python") || strings.HasPrefix(baseResolved, "python") || baseBin == "uv"
}

func planPythonLaunch(in launchPlanInput, _ []string, plan *LaunchAttachPlan) {
	plan.DetectedStack = "python"
	plan.NonIntrusiveOK = false
	plan.NonIntrusiveReason = "Python LLM SDK (httpx/aiohttp/uv) 普遍使用 ssl.SSLObject (MemoryBIO/SSL_write_ex) 或静态 strip OpenSSL，仅靠非侵入式 SSL_write Uprobe 无法完整覆盖"

	if in.AutoIntrusive {
		plan.AutoIntrusiveTriggered = true
	}
}

func planPythonEnvMethods(in launchPlanInput, isPython bool, plan *LaunchAttachPlan) {
	if isPython && in.PyHookDir != "" {
		plan.IntrusiveMethods = appendUniqueStr(plan.IntrusiveMethods, "env:PYTHONPATH(sitecustomize)")
	}
}

func applyPythonLaunchEnv(
	in launchPlanInput,
	isPython bool,
	plan *LaunchAttachPlan,
	env []string,
	setAndTrackEnv func(env []string, k, v string) []string,
) []string {
	if in.PyHookDir == "" {
		return env
	}
	existingPyPath := lookupEnvVar(env, "PYTHONPATH")
	sep := string(os.PathListSeparator)
	if existingPyPath != "" {
		env = setAndTrackEnv(env, "PYTHONPATH", in.PyHookDir+sep+existingPyPath)
	} else {
		env = setAndTrackEnv(env, "PYTHONPATH", in.PyHookDir)
	}
	if isPython {
		plan.IntrusiveMethods = appendUniqueStr(plan.IntrusiveMethods, "env:PYTHONPATH(sitecustomize)")
	}
	return env
}
