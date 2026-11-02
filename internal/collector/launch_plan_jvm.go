package collector

func isJVMLaunchTarget(binPath, resolvedELF string) bool {
	return isJavaBinary(binPath) || isJavaBinary(resolvedELF)
}

func planJVMLaunch(in launchPlanInput, userArgs []string, plan *LaunchAttachPlan) {
	plan.DetectedStack = "jvm-jsse"
	plan.NonIntrusiveOK = false
	plan.NonIntrusiveReason = "Java/JVM 使用 JSSE 纯字节码/JIT 执行 TLS 加解密，无固定 ELF 函数偏移，非侵入式 eBPF Uprobe 无法直接解密"

	if !in.AutoIntrusive {
		return
	}
	plan.AutoIntrusiveTriggered = true
	if in.JavaAgentJar != "" && !hasArgPrefix(userArgs, "-javaagent:") && !isVersionOrHelpArgs(userArgs) {
		if in.TapActive {
			plan.InjectedArgs = []string{
				"-javaagent:" + in.JavaAgentJar + "=" + in.ProxyURL,
				"-Dhttp.proxyHost=" + in.ProxyHost,
				"-Dhttp.proxyPort=" + in.ProxyPort,
				"-Dhttps.proxyHost=" + in.ProxyHost,
				"-Dhttps.proxyPort=" + in.ProxyPort,
				"-Djdk.internal.httpclient.disableHostnameVerification=true",
			}
			plan.IntrusiveMethods = append(plan.IntrusiveMethods, "cli_arg:-javaagent", "cli_arg:-Dhttps.proxyHost")
		} else {
			plan.InjectedArgs = []string{"-javaagent:" + in.JavaAgentJar}
			plan.IntrusiveMethods = append(plan.IntrusiveMethods, "cli_arg:-javaagent")
		}
	}
}

func planJVMEnvMethods(in launchPlanInput, isJVM bool, plan *LaunchAttachPlan) {
	if isJVM && in.JavaAgentJar != "" {
		plan.IntrusiveMethods = appendUniqueStr(plan.IntrusiveMethods, "env:JAVA_TOOL_OPTIONS")
	}
}

func applyJVMLaunchEnv(
	in launchPlanInput,
	isJVM bool,
	plan *LaunchAttachPlan,
	env []string,
	setAndTrackEnv func(env []string, k, v string) []string,
) []string {
	if in.JavaAgentJar == "" {
		return env
	}
	javaOpt := "-javaagent:" + in.JavaAgentJar
	if existingJavaOpts := lookupEnvVar(env, "JAVA_TOOL_OPTIONS"); existingJavaOpts != "" {
		env = setAndTrackEnv(env, "JAVA_TOOL_OPTIONS", existingJavaOpts+" "+javaOpt)
	} else {
		env = setAndTrackEnv(env, "JAVA_TOOL_OPTIONS", javaOpt)
	}
	if isJVM {
		plan.IntrusiveMethods = appendUniqueStr(plan.IntrusiveMethods, "env:JAVA_TOOL_OPTIONS")
	}
	return env
}
