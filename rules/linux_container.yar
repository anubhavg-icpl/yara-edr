/*
    Linux Container & Cloud Security Rules
    Detection for container escapes, Kubernetes attacks, and cloud exploitation
    Author: YARA-EDR
*/

import "elf"

// ============================================================================
// Container Detection & Enumeration
// ============================================================================

rule Linux_Container_Enum_DeepCE {
    meta:
        description = "Detects DeepCE container enumeration and escape tool"
        author = "YARA-EDR"
        severity = "high"
        category = "container_tool"
    strings:
        $s1 = "deepce" ascii nocase
        $s2 = "Docker Enumeration" ascii
        $s3 = "Container Escape" ascii
        $s4 = "Privilege Mode" ascii
        $s5 = "Dangerous Capabilities" ascii
        $check1 = "/.dockerenv" ascii
        $check2 = "/proc/1/cgroup" ascii
    condition:
        3 of them
}

rule Linux_Container_Enum_CDK {
    meta:
        description = "Detects CDK (Container Penetration Toolkit)"
        author = "YARA-EDR"
        severity = "high"
        category = "container_tool"
    strings:
        $s1 = "cdk_" ascii
        $s2 = "CDK" ascii
        $s3 = "evaluate" ascii
        $s4 = "Exploit" ascii
        $exploit1 = "mount-cgroup" ascii
        $exploit2 = "cap-dac-read-search" ascii
        $exploit3 = "sock-escape" ascii
        // removed go
    condition:
        uint32(0) == 0x464c457f and (3 of ($s*) or 2 of ($exploit*))
}

rule Linux_Container_Enum_BOTB {
    meta:
        description = "Detects Break out the Box container escape tool"
        author = "YARA-EDR"
        severity = "high"
        category = "container_tool"
    strings:
        $s1 = "BOTB" ascii
        $s2 = "breakout" ascii nocase
        $s3 = "docker.sock" ascii
        $s4 = "metadata" ascii
        $s5 = "169.254.169.254" ascii
        $escape1 = "autopwn" ascii
        $escape2 = "pwnDocker" ascii
    condition:
        3 of them
}

// ============================================================================
// Docker Socket Exploitation
// ============================================================================

rule Linux_Container_Docker_Sock_Abuse {
    meta:
        description = "Detects Docker socket abuse for container escape"
        author = "YARA-EDR"
        severity = "critical"
        category = "container_escape"
    strings:
        $sock1 = "/var/run/docker.sock" ascii
        $sock2 = "docker.sock" ascii
        $sock3 = "/run/docker.sock" ascii
        $api1 = "/containers/create" ascii
        $api2 = "/containers/json" ascii
        $api3 = "/images/json" ascii
        $api4 = "/exec/" ascii
        $curl = "curl --unix-socket" ascii
        $priv = "Privileged" ascii
        $bind = "HostConfig" ascii
    condition:
        (any of ($sock*) and any of ($api*)) or ($curl and any of ($sock*)) or
        (any of ($sock*) and $priv and $bind)
}

rule Linux_Container_Docker_API_Exploit {
    meta:
        description = "Detects Docker Remote API exploitation"
        author = "YARA-EDR"
        severity = "critical"
        category = "container_escape"
    strings:
        $port1 = ":2375" ascii
        $port2 = ":2376" ascii
        $api1 = "containers/create" ascii
        $api2 = "exec/start" ascii
        $api3 = "images/create" ascii
        // removed host
        $priv1 = "\"Privileged\":true" ascii
        $priv2 = "\"Binds\":[\"/:/mnt" ascii
        $priv3 = "Mounts" ascii
    condition:
        (any of ($port*) and any of ($api*)) or any of ($priv*)
}

// ============================================================================
// Cgroup Escape Techniques
// ============================================================================

rule Linux_Container_Cgroup_Escape {
    meta:
        description = "Detects cgroup-based container escape techniques"
        author = "YARA-EDR"
        severity = "critical"
        category = "container_escape"
    strings:
        $cgroup1 = "/sys/fs/cgroup" ascii
        $cgroup2 = "cgroup" ascii
        $release1 = "release_agent" ascii
        $release2 = "notify_on_release" ascii
        $mount1 = "mount -t cgroup" ascii
        $mount2 = "mkdir /tmp/cgrp" ascii
        // removed trigger
        $shell = "/bin/sh" ascii
    condition:
        ($release1 and $release2) or
        (any of ($cgroup*) and any of ($mount*) and $shell)
}

rule Linux_Container_Cgroup_Notify_Escape {
    meta:
        description = "Detects cgroup notify_on_release escape"
        author = "YARA-EDR"
        severity = "critical"
        category = "container_escape"
    strings:
        $s1 = "notify_on_release" ascii
        $s2 = "release_agent" ascii
        $s3 = "/sys/fs/cgroup" ascii
        $s4 = "rdma" ascii
        // removed cmd1
        // removed cmd2
        $script = "#!/bin/sh" ascii
    condition:
        ($s1 and $s2) or (3 of ($s*)) or (2 of ($s*) and $script)
}

// ============================================================================
// Privileged Container Escape
// ============================================================================

rule Linux_Container_Privileged_Escape {
    meta:
        description = "Detects privileged container escape techniques"
        author = "YARA-EDR"
        severity = "critical"
        category = "container_escape"
    strings:
        $cap1 = "CAP_SYS_ADMIN" ascii
        $cap2 = "SYS_ADMIN" ascii
        $cap3 = "cap_sys_admin" ascii
        $dev1 = "/dev/sda" ascii
        $dev2 = "/dev/vda" ascii
        $dev3 = "/dev/nvme" ascii
        $mount1 = "mount /dev" ascii
        $mount2 = "debugfs" ascii
        $chroot = "chroot" ascii
        $nsenter = "nsenter" ascii
    condition:
        (any of ($cap*) and any of ($dev*) and any of ($mount*, $chroot, $nsenter)) or
        (any of ($cap*) and $nsenter)
}

rule Linux_Container_Device_Mount_Escape {
    meta:
        description = "Detects host device mount escape"
        author = "YARA-EDR"
        severity = "critical"
        category = "container_escape"
    strings:
        $dev1 = "/dev/sda1" ascii
        $dev2 = "/dev/vda1" ascii
        $dev3 = "/dev/xvda1" ascii
        $mount = "mount" ascii
        $mnt = "/mnt" ascii
        $root = "/etc/shadow" ascii
        $passwd = "/etc/passwd" ascii
        $key = "/root/.ssh" ascii
    condition:
        any of ($dev*) and $mount and ($mnt or any of ($root, $passwd, $key))
}

// ============================================================================
// Kubernetes Attacks
// ============================================================================

rule Linux_K8s_Service_Account_Abuse {
    meta:
        description = "Detects Kubernetes service account token abuse"
        author = "YARA-EDR"
        severity = "high"
        category = "kubernetes"
    strings:
        $token1 = "/var/run/secrets/kubernetes.io" ascii
        $token2 = "/serviceaccount/token" ascii
        $token3 = "ca.crt" ascii
        $token4 = "namespace" ascii
        $api1 = "api/v1" ascii
        $api2 = "apis/" ascii
        $api3 = "kubectl" ascii
        $curl = "curl -k" ascii
        $header = "Authorization: Bearer" ascii
    condition:
        (2 of ($token*) and any of ($api*)) or ($curl and $header and any of ($token*))
}

rule Linux_K8s_RBAC_Escalation {
    meta:
        description = "Detects Kubernetes RBAC privilege escalation"
        author = "YARA-EDR"
        severity = "high"
        category = "kubernetes"
    strings:
        $rbac1 = "clusterroles" ascii
        $rbac2 = "clusterrolebindings" ascii
        $rbac3 = "rolebindings" ascii
        $create = "create" ascii
        $bind = "bind" ascii
        $escalate = "escalate" ascii
        $impersonate = "impersonate" ascii
        $admin = "cluster-admin" ascii
    condition:
        (2 of ($rbac*) and any of ($create, $bind, $escalate, $impersonate)) or
        $admin
}

rule Linux_K8s_Kubectl_Proxy_Abuse {
    meta:
        description = "Detects kubectl proxy abuse for API access"
        author = "YARA-EDR"
        severity = "medium"
        category = "kubernetes"
    strings:
        $s1 = "kubectl proxy" ascii
        $s2 = "127.0.0.1:8001" ascii
        $s3 = "localhost:8001" ascii
        $api1 = "/api/v1/namespaces" ascii
        $api2 = "/api/v1/pods" ascii
        $api3 = "/api/v1/secrets" ascii
    condition:
        ($s1 or any of ($s2, $s3)) and any of ($api*)
}

rule Linux_K8s_Secrets_Extraction {
    meta:
        description = "Detects Kubernetes secrets extraction"
        author = "YARA-EDR"
        severity = "high"
        category = "kubernetes"
    strings:
        $cmd1 = "kubectl get secrets" ascii
        $cmd2 = "kubectl get secret" ascii
        $cmd3 = "-o yaml" ascii
        $cmd4 = "-o json" ascii
        $api1 = "/api/v1/secrets" ascii
        $api2 = "/api/v1/namespaces/default/secrets" ascii
        $decode = "base64 -d" ascii
        $decode2 = "base64 --decode" ascii
    condition:
        (any of ($cmd1, $cmd2) and any of ($cmd3, $cmd4)) or
        (any of ($api*) and any of ($decode*))
}

rule Linux_K8s_Pod_Escape {
    meta:
        description = "Detects Kubernetes pod escape techniques"
        author = "YARA-EDR"
        severity = "critical"
        category = "kubernetes"
    strings:
        $spec1 = "hostPID" ascii
        $spec2 = "hostNetwork" ascii
        $spec3 = "hostIPC" ascii
        $spec4 = "hostPath" ascii
        $priv = "privileged: true" ascii
        $cap = "SYS_ADMIN" ascii
        $mount = "mountPath: /" ascii
        $nsenter = "nsenter" ascii
    condition:
        (2 of ($spec*)) or ($priv and any of ($spec*)) or ($cap and $mount) or
        ($nsenter and any of ($spec*))
}

// ============================================================================
// Cloud Metadata Service Exploitation
// ============================================================================

rule Linux_Cloud_Metadata_SSRF {
    meta:
        description = "Detects cloud metadata service exploitation (SSRF)"
        author = "YARA-EDR"
        severity = "high"
        category = "cloud"
    strings:
        $ip1 = "169.254.169.254" ascii
        $ip2 = "metadata.google.internal" ascii
        $ip3 = "metadata.azure" ascii
        $aws1 = "/latest/meta-data" ascii
        $aws2 = "/latest/user-data" ascii
        $aws3 = "iam/security-credentials" ascii
        $gcp1 = "/computeMetadata/v1" ascii
        $gcp2 = "Metadata-Flavor: Google" ascii
        $azure = "/metadata/instance" ascii
        $wget = "wget" ascii
        $fetch = "curl" ascii
    condition:
        (any of ($ip*) and any of ($aws*, $gcp*, $azure)) or
        (any of ($fetch, $wget) and $ip1)
}

rule Linux_Cloud_AWS_Credential_Theft {
    meta:
        description = "Detects AWS credential theft from metadata service"
        author = "YARA-EDR"
        severity = "critical"
        category = "cloud"
    strings:
        $meta = "169.254.169.254" ascii
        $iam1 = "iam/security-credentials" ascii
        $iam2 = "iam/info" ascii
        $token1 = "AccessKeyId" ascii
        $token2 = "SecretAccessKey" ascii
        $token3 = "Token" ascii
        $env1 = "AWS_ACCESS_KEY" ascii
        $env2 = "AWS_SECRET" ascii
        $file1 = ".aws/credentials" ascii
        $file2 = ".aws/config" ascii
    condition:
        ($meta and any of ($iam*)) or (2 of ($token*)) or (any of ($env*) and any of ($file*))
}

rule Linux_Cloud_GCP_Credential_Theft {
    meta:
        description = "Detects GCP credential theft"
        author = "YARA-EDR"
        severity = "critical"
        category = "cloud"
    strings:
        $meta1 = "metadata.google.internal" ascii
        $meta2 = "computeMetadata" ascii
        $token1 = "access_token" ascii
        $token2 = "id_token" ascii
        $token3 = "service-accounts" ascii
        $file1 = "application_default_credentials" ascii
        $file2 = ".config/gcloud" ascii
        $env = "GOOGLE_APPLICATION_CREDENTIALS" ascii
    condition:
        (any of ($meta*) and any of ($token*)) or ($env and any of ($file*))
}

// ============================================================================
// Container Runtime Exploitation
// ============================================================================

rule Linux_Container_RunC_Exploit {
    meta:
        description = "Detects runc container escape exploit (CVE-2019-5736)"
        author = "YARA-EDR"
        severity = "critical"
        category = "container_exploit"
        cve = "CVE-2019-5736"
    strings:
        $s1 = "/proc/self/exe" ascii
        $s2 = "runc" ascii
        $s3 = "overwrite" ascii
        $s4 = "#!/proc/self/exe" ascii
        $payload = { 48 8D ?? ?? ?? ?? ?? 48 89 ?? BE 00 00 00 00 }
    condition:
        uint32(0) == 0x464c457f and (($s4) or (3 of ($s*)) or ($s1 and $s2 and $payload))
}

rule Linux_Container_ContainerD_Exploit {
    meta:
        description = "Detects containerd vulnerability exploitation"
        author = "YARA-EDR"
        severity = "critical"
        category = "container_exploit"
    strings:
        $s1 = "containerd" ascii
        $s2 = "containerd-shim" ascii
        $s3 = "/run/containerd" ascii
        $s4 = "io.containerd" ascii
        $sock = "containerd.sock" ascii
        $api = "grpc" ascii
        $escape = "/proc/self/exe" ascii
    condition:
        uint32(0) == 0x464c457f and (3 of ($s*) or ($sock and $api and $escape))
}

// ============================================================================
// Container Security Bypass
// ============================================================================

rule Linux_Container_Seccomp_Bypass {
    meta:
        description = "Detects seccomp filter bypass attempts"
        author = "YARA-EDR"
        severity = "high"
        category = "container_bypass"
    strings:
        $s1 = "seccomp" ascii
        $s2 = "SECCOMP_" ascii
        $s3 = "prctl" ascii
        $s4 = "PR_SET_SECCOMP" ascii
        $bypass1 = "SCMP_ACT_" ascii
        $bypass2 = "seccomp_rule" ascii
        $bypass3 = "syscall" ascii
        $x32 = "__NR_" ascii
    condition:
        uint32(0) == 0x464c457f and (3 of ($s*, $bypass*) and $x32)
}

rule Linux_Container_AppArmor_Bypass {
    meta:
        description = "Detects AppArmor bypass attempts"
        author = "YARA-EDR"
        severity = "high"
        category = "container_bypass"
    strings:
        $s1 = "apparmor" ascii
        $s2 = "AppArmor" ascii
        $s3 = "/sys/kernel/security/apparmor" ascii
        $s4 = "aa_change_profile" ascii
        $bypass1 = "unconfined" ascii
        $bypass2 = "complain" ascii
        $bypass3 = "/etc/apparmor.d" ascii
    condition:
        (2 of ($s*) and any of ($bypass*))
}

rule Linux_Container_Namespace_Escape {
    meta:
        description = "Detects container namespace escape techniques"
        author = "YARA-EDR"
        severity = "critical"
        category = "container_escape"
    strings:
        $ns1 = "setns" ascii
        $ns2 = "unshare" ascii
        $ns3 = "CLONE_NEW" ascii
        $ns4 = "/proc/1/ns" ascii
        $ns5 = "/proc/self/ns" ascii
        $nsenter = "nsenter" ascii
        $mnt = "mnt" ascii
        $pid = "pid" ascii
        $net = "net" ascii
    condition:
        uint32(0) == 0x464c457f and
        ((any of ($ns1, $ns2, $nsenter) and any of ($ns4, $ns5)) or
        ($ns3 and 2 of ($mnt, $pid, $net)))
}

// ============================================================================
// Serverless/Lambda Exploitation
// ============================================================================

rule Linux_Lambda_Credential_Extraction {
    meta:
        description = "Detects AWS Lambda credential extraction"
        author = "YARA-EDR"
        severity = "high"
        category = "serverless"
    strings:
        $env1 = "AWS_LAMBDA_FUNCTION_NAME" ascii
        $env2 = "AWS_ACCESS_KEY_ID" ascii
        $env3 = "AWS_SECRET_ACCESS_KEY" ascii
        $env4 = "AWS_SESSION_TOKEN" ascii
        $env5 = "_HANDLER" ascii
        $runtime = "/var/runtime" ascii
        $task = "/var/task" ascii
        // removed curl
    condition:
        (3 of ($env*)) or ((any of ($runtime, $task)) and 2 of ($env*))
}

// ============================================================================
// Kubernetes Attack Tools
// ============================================================================

rule Linux_K8s_Peirates {
    meta:
        description = "Detects Peirates Kubernetes exploitation tool"
        author = "YARA-EDR"
        severity = "critical"
        category = "kubernetes_tool"
    strings:
        $s1 = "peirates" ascii nocase
        $s2 = "Peirates" ascii
        $s3 = "attack-menu" ascii
        $func1 = "getServiceAccountToken" ascii
        $func2 = "execInPod" ascii
        $func3 = "getMountedSecrets" ascii
        $go = "runtime.gopanic" ascii
    condition:
        uint32(0) == 0x464c457f and (2 of ($s*) or 2 of ($func*) or $go)
}

rule Linux_K8s_Kubesploit {
    meta:
        description = "Detects Kubesploit post-exploitation framework"
        author = "YARA-EDR"
        severity = "critical"
        category = "kubernetes_tool"
    strings:
        $s1 = "kubesploit" ascii nocase
        $s2 = "Kubeletctl" ascii
        $s3 = "k8s exploitation" ascii nocase
        $mod1 = "containerEscape" ascii
        $mod2 = "mountBreakout" ascii
        $mod3 = "runcExploit" ascii
    condition:
        2 of ($s*) or 2 of ($mod*)
}
