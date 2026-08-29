"""取证分诊工具：pcap_triage / memory_triage / audio_steg / qr_decode / pdf_office_analyze

设计约定：
- 分诊工具一次调用覆盖该题型 80% 的常规操作，替代模型手写多步命令
- 所有提取产物写到 /tmp 并在输出里列出路径，供后续 read_file/file_tool 深挖
- 输出末尾自动 grep flag 模式写入 [FLAG]（发现即上报，防漏看）
"""
import os
import re
import shutil

from tools.base import register_tool, run_cmd, check_exec_cache, store_exec_cache

FLAG_RE = re.compile(r"(?:flag|FLAG|ctf|CTF)\{[^}]{4,200}\}")


def _which(binname):
    if binname not in _WHICH_CACHE:
        _WHICH_CACHE[binname] = shutil.which(binname)
    return _WHICH_CACHE[binname]


_WHICH_CACHE = {}


def _truncate(s, n=2500):
    s = (s or "").strip()
    return s if len(s) <= n else s[:n] + f"\n...[截断, 原文 {len(s)} 字符]..."


def _flags_footer(text, extra_files=None) -> str:
    """全文 grep flag + 检查提取产物文件名"""
    found = list(dict.fromkeys(FLAG_RE.findall(text or "")))
    for p in (extra_files or []):
        try:
            if os.path.isfile(p):
                with open(p, "rb") as f:
                    found += list(dict.fromkeys(
                        FLAG_RE.findall(f.read(500000).decode("utf-8", "ignore"))))
        except Exception:
            pass
    if found:
        return f"\n\n[FLAG] 发现疑似 flag: {list(dict.fromkeys(found))}\n[下一步] 直接 submit_flag 提交验证。"
    return ""


def _grep_in_dir(directory, pattern=FLAG_RE, max_files=50) -> list:
    """递归在提取目录里找 flag 模式（小文件读内存，大文件 strings）"""
    found = []
    try:
        for root, _, files in os.walk(directory):
            for fn in files:
                p = os.path.join(root, fn)
                try:
                    if os.path.getsize(p) > 2_000_000:
                        continue
                    with open(p, "rb") as f:
                        found += FLAG_RE.findall(f.read().decode("utf-8", "ignore"))
                except Exception:
                    continue
                if len(found) > 20:
                    return list(dict.fromkeys(found))
    except Exception:
        pass
    return list(dict.fromkeys(found))


# ── 1. pcap_triage：流量包一键分诊 ───────────────────────────────────────────

@register_tool(
    "pcap_triage",
    "流量包一键分诊：协议分布 + HTTP 请求列表 + DNS 查询 + TCP 会话排行 + "
    "HTTP 对象自动导出到 /tmp/pcap_extract/。取证题拿到 pcap 先调它，"
    "替代多次手写 tshark。",
    {
        "type": "object",
        "properties": {
            "pcap_path": {"type": "string", "description": "pcap/pcapng 文件路径"},
        },
        "required": ["pcap_path"],
    },
)
def pcap_triage(pcap_path: str) -> str:
    pcap_path = (pcap_path or "").strip()
    if not os.path.isfile(pcap_path):
        return f"[参数错误] 文件不存在: {pcap_path}"
    if not _which("tshark"):
        return "[MISSING] tshark 未安装（sudo apt install wireshark-cli）"

    cache_key = f"pcap:{pcap_path}"
    cached = check_exec_cache(cache_key)
    if cached:
        return cached

    extract_dir = "/tmp/pcap_extract"
    os.makedirs(extract_dir, exist_ok=True)
    sections = []
    all_text = ""

    phs = run_cmd(["tshark", "-r", pcap_path, "-q", "-z", "io,phs"], timeout=60)
    sections.append(f"[协议分布]\n{_truncate(phs, 2000)}")
    all_text += phs

    conv = run_cmd(["tshark", "-r", pcap_path, "-q", "-z", "conv,tcp"], timeout=60)
    sections.append(f"[TCP 会话排行]\n{_truncate(conv, 1500)}")
    all_text += conv

    http = run_cmd(["tshark", "-r", pcap_path, "-Y", "http.request", "-T", "fields",
                    "-e", "http.request.method", "-e", "http.host", "-e", "http.request.uri"],
                   timeout=60)
    http_lines = [l for l in http.splitlines() if l.strip()][:30]
    sections.append(f"[HTTP 请求 (前 30)]\n{_truncate(chr(10).join(http_lines), 1500) or '[无 HTTP 流量]'}")
    all_text += http

    dns = run_cmd(["tshark", "-r", pcap_path, "-Y", "dns.qry.name", "-T", "fields",
                   "-e", "dns.qry.name"], timeout=60)
    uniq_dns = list(dict.fromkeys(d for d in dns.splitlines() if d.strip()))[:30]
    sections.append(f"[DNS 查询 (去重前 30)]\n{chr(10).join(uniq_dns) or '[无]'}")
    all_text += dns

    # 导出 HTTP 对象
    run_cmd(["tshark", "-r", pcap_path, "--export-objects", f"http,{extract_dir}", "-q"],
            timeout=90)
    exported = []
    for root, _, files in os.walk(extract_dir):
        for fn in files:
            p = os.path.join(root, fn)
            try:
                exported.append(f"- {p} ({os.path.getsize(p)} B)")
            except OSError:
                continue
    if exported:
        sections.append(f"[HTTP 对象已导出]\n" + "\n".join(exported[:20]))

    # 上传数据（POST body / 文件传输常见藏 flag 处）
    post = run_cmd(["tshark", "-r", pcap_path, "-Y", "http.request.method==POST",
                    "-T", "fields", "-e", "http.file_data"], timeout=60)
    all_text += post
    if post.strip() and "[无输出]" not in post:
        sections.append(f"[POST 数据]\n{_truncate(post, 1200)}")

    footer = _flags_footer(all_text, extra_files=[os.path.join(extract_dir, f) for f in
                                                  os.listdir(extract_dir)[:20]] if os.path.isdir(extract_dir) else [])
    deep_hits = _grep_in_dir(extract_dir)
    if deep_hits and not footer:
        footer = f"\n\n[FLAG] 导出对象中发现疑似 flag: {deep_hits}\n[下一步] 直接 submit_flag 提交验证。"

    if footer:
        sections.append(footer.strip())
    else:
        sections.append(
            "[下一步] 表面分诊无 flag → 深挖方向："
            "① tshark -r <pcap> -Y 'tcp.stream eq N' -z follow,tcp,ascii,N 逐流读（挑大流量/异常端口）；"
            "② USB 流量（keyboard capture：tshark -Y 'usb.capdata' 提取击键）；"
            "③ 导出的 HTTP 对象用 analyze_file 深查；④ WiFi 包注意加密认证（eapol 握手 → 用 hashcat 跑）。"
        )
    result = "\n\n".join(sections)
    store_exec_cache(cache_key, result)
    return result


# ── 2. memory_triage：内存镜像一键分诊 ───────────────────────────────────────

@register_tool(
    "memory_triage",
    "内存镜像一键分诊：volatility3 可用时跑 info/pslist/cmdline/filescan 管道；"
    "不可用时降级为 strings 直接搜 flag 和敏感串。取证内存题先调它。",
    {
        "type": "object",
        "properties": {
            "dump_path": {"type": "string", "description": "内存 dump 文件路径 (raw/vmem/lime)"},
        },
        "required": ["dump_path"],
    },
)
def memory_triage(dump_path: str) -> str:
    dump_path = (dump_path or "").strip()
    if not os.path.isfile(dump_path):
        return f"[参数错误] 文件不存在: {dump_path}"

    cache_key = f"mem:{dump_path}"
    cached = check_exec_cache(cache_key)
    if cached:
        return cached

    sections = []
    finfo = run_cmd(["file", dump_path], timeout=15)
    sections.append(f"[file]\n{finfo}")
    all_text = finfo

    vol = _which("vol") or _which("volatility3") or _which("vol.py")
    if vol:
        for name, cmd_args in [
            ("系统信息", ["windows.info"]),
            ("进程列表", ["windows.pslist"]),
            ("进程命令行", ["windows.cmdline"]),
        ]:
            out = run_cmd([vol, "-f", dump_path, *cmd_args], timeout=180)
            sections.append(f"[{name}]\n{_truncate(out, 2000)}")
            all_text += out
        fs = run_cmd([vol, "-f", dump_path, "windows.filescan"], timeout=180)
        interesting = [l for l in fs.splitlines()
                       if re.search(r"(flag|desktop|documents|password|secret|\.txt$)", l, re.I)][:20]
        if interesting:
            sections.append("[可疑文件]\n" + "\n".join(interesting))
        all_text += fs
        tip = ("[下一步] 从 [可疑文件] 挑目标：vol -f <dump> windows.dumpfiles "
               "--virtaddr=<偏移> 导出后 read_file。")
    else:
        # 降级：strings 直搜
        flags = run_cmd(["bash", "-c",
                         f"strings -a '{dump_path}' | grep -aoE "
                         f"'(flag|FLAG|ctf|CTF)\\{{[^}}]{{4,200}}\\}}' | sort -u | head -10"],
                        timeout=120)
        secrets = run_cmd(["bash", "-c",
                           f"strings -a '{dump_path}' | grep -aiE "
                           f"'password|passwd|secret|token|apikey' | sort -u | head -20"],
                          timeout=120)
        sections.append(f"[strings 搜 flag]\n{_truncate(flags, 1500) or '[无]'}")
        all_text += flags
        sections.append(f"[strings 搜敏感串]\n{_truncate(secrets, 1500) or '[无]'}")
        all_text += secrets
        tip = ("[下一步] volatility3 未安装（pip install volatility3），当前仅 strings 级分析。"
               "无 flag 时关注：浏览器历史/剪贴板/注册表 SAM（装 vol3 后 windows.hashdump）。")

    footer = _flags_footer(all_text)
    sections.append(footer.strip() if footer else tip)
    result = "\n\n".join(sections)
    store_exec_cache(cache_key, result)
    return result


# ── 3. audio_steg：音频隐写分诊 ──────────────────────────────────────────────

@register_tool(
    "audio_steg",
    "音频文件隐写分诊：类型识别 + 元数据 + binwalk 嵌入提取 + strings + "
    "SSTV 检测（WAV 且装了 sstv 时自动解码）。音频取证题先调它。",
    {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "音频文件路径 (wav/mp3/flac/ogg)"},
        },
        "required": ["path"],
    },
)
def audio_steg(path: str) -> str:
    path = (path or "").strip()
    if not os.path.isfile(path):
        return f"[参数错误] 文件不存在: {path}"

    sections = []
    all_text = ""
    for name, cmd in [("file", ["file", path]),
                      ("元数据 exiftool", ["exiftool", path])]:
        out = run_cmd(cmd, timeout=30)
        sections.append(f"[{name}]\n{_truncate(out, 1200)}")
        all_text += out

    bw = run_cmd(["binwalk", path], timeout=60)
    sections.append(f"[binwalk 签名]\n{_truncate(bw, 1200) or '[无嵌入签名]'}")
    all_text += bw
    if re.search(r"\d+\s+0x", bw):
        run_cmd(["binwalk", "-e", "--run-as=root", "-C", "/tmp/audio_extract", path], timeout=120)
        if os.path.isdir("/tmp/audio_extract"):
            extracted = [f"/tmp/audio_extract/{f}" for f in os.listdir("/tmp/audio_extract")]
            if extracted:
                sections.append("[binwalk 已提取]\n" + "\n".join(extracted[:15]))

    strs = run_cmd(["bash", "-c", f"strings -a -n 6 '{path}' | head -30"], timeout=30)
    sections.append(f"[strings]\n{_truncate(strs, 1200) or '[无可见字符串]'}")
    all_text += strs

    # SSTV 检测：WAV 且时长短
    if path.lower().endswith(".wav"):
        if _which("sstv"):
            out = run_cmd(["sstv", "-d", path, "-o", "/tmp/sstv_out.png"], timeout=120)
            if os.path.isfile("/tmp/sstv_out.png"):
                sections.append("[SSTV] 已解码 → /tmp/sstv_out.png（用 read_file 查看）")
        else:
            sections.append("[SSTV] 若频谱图可见图像特征，需安装 sstv (pip install sstv) 解码")

    footer = _flags_footer(all_text)
    sections.append(footer.strip() if footer else
                    "[下一步] 无直接 flag → 查频谱图（audacity/python matplotlib 画 spectrogram，"
                    "文本常藏在频谱上）；摩斯电码（听节奏/tshark 无关，用 python 解）；LSB（run_python 逐通道查）。")
    return "\n\n".join(sections)


# ── 4. qr_decode：二维码识别 ─────────────────────────────────────────────────

@register_tool(
    "qr_decode",
    "识别图片中的二维码/条形码内容（zbarimg，缺失时降级 OpenCV）。",
    {
        "type": "object",
        "properties": {
            "image_path": {"type": "string", "description": "图片路径"},
        },
        "required": ["image_path"],
    },
)
def qr_decode(image_path: str) -> str:
    image_path = (image_path or "").strip()
    if not os.path.isfile(image_path):
        return f"[参数错误] 文件不存在: {image_path}"
    if _which("zbarimg"):
        out = run_cmd(["zbarimg", "-q", "--raw", image_path], timeout=30)
        if out and "[无输出]" not in out and out.strip():
            footer = _flags_footer(out)
            return (f"[QR 内容]\n{_truncate(out, 1500)}"
                    + (footer if footer else "\n[下一步] 内容是编码/URL → auto_decode 或 curl。"))
    # 降级 OpenCV
    try:
        import cv2  # noqa
        img = cv2.imread(image_path)
        det = cv2.QRCodeDetector()
        data, _, _ = det.detectAndDecode(img)
        if data:
            footer = _flags_footer(data)
            return f"[QR 内容 (OpenCV)]\n{data}" + (footer if footer else "")
    except ImportError:
        pass
    return ("[FAIL] 未识别出二维码。\n[下一步] 图像可能需预处理（放大/反色/二值化），"
            "用 run_python + PIL 处理后重试；或安装 zbarimg (sudo apt install zbar-tools)。")


# ── 4b. ocr_recognize：图片文字/验证码识别（b-03 类验证码题的缺口） ────────────

@register_tool(
    "ocr_recognize",
    "识别图片中的文字（验证码、截图里的 flag/密码、扫描件）。支持放大预处理"
    "（低分辨率验证码建议 scale=3 提高识别率）。需要 tesseract（未装时给出安装命令）。",
    {
        "type": "object",
        "properties": {
            "image_path": {"type": "string", "description": "图片路径"},
            "scale": {"type": "integer", "description": "放大倍数（验证码/小字建议 3，默认 1）"},
            "whitelist": {"type": "string", "description": "可选：限定字符集，如验证码用 '0123456789abcdefghijklmnopqrstuvwxyz'"},
        },
        "required": ["image_path"],
    },
)
def ocr_recognize(image_path: str, scale: int = 1, whitelist: str = "") -> str:
    image_path = (image_path or "").strip()
    if not os.path.isfile(image_path):
        return f"[参数错误] 文件不存在: {image_path}"
    tess = _which("tesseract")
    if not tess:
        return ("[工具未安装] tesseract 不在，OCR 无法进行（sudo apt install -y tesseract-ocr）。\n"
                "[替代] run_python + PIL 手写验证码识别；或先分析该验证码是否只是干扰项，"
                "转向其他攻击面。")
    cache_key = f"ocr:{image_path}:{scale}:{whitelist}"
    cached = check_exec_cache(cache_key)
    if cached:
        return cached

    work = image_path
    pre = ""
    try:
        if scale and scale > 1:
            from PIL import Image
            img = Image.open(image_path).convert("L")  # 灰度
            img = img.resize((img.width * scale, img.height * scale), Image.LANCZOS)
            work = f"/tmp/ocr_{os.getpid()}_{os.path.basename(image_path)}"
            img.save(work)
            pre = f"[预处理] 灰度 x{scale} 放大 → {work}\n"
    except Exception:
        work = image_path  # PIL 不可用/失败则直接原样 OCR

    cmd = [tess, work, "stdout"]
    if whitelist:
        cmd += ["-c", f"tessedit_char_whitelist={whitelist}"]
    out = run_cmd(cmd, timeout=60)
    if work != image_path:
        try:
            os.remove(work)
        except OSError:
            pass
    text = out.strip()
    if not text or text == "[无输出]":
        result = (pre + "[OCR 空结果] 未识别出文字。\n[下一步] 换 scale（2~4）、加 whitelist "
                  "限定字符集，或用 run_python + PIL 增强对比度/二值化后重试。")
    else:
        footer = _flags_footer(text)
        result = (pre + f"[OCR 结果]\n{_truncate(text, 1500)}"
                  + (footer if footer else "\n[下一步] 内容像验证码→带 cookie 回填表单重放；"
                     "像密码/编码→直接使用或 auto_decode。"))
    store_exec_cache(cache_key, result)
    return result


# ── 5. pdf_office_analyze：PDF/Office 文档取证 ──────────────────────────────

@register_tool(
    "pdf_office_analyze",
    "PDF/Office 文档取证：PDF→元数据+内嵌对象+图片提取；docx/xls/ppt→zip 结构"
    "+VBA 宏检测提取。钓鱼附件/宏隐藏 flag 题先调它。",
    {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "PDF 或 Office 文档路径"},
        },
        "required": ["path"],
    },
)
def pdf_office_analyze(path: str) -> str:
    path = (path or "").strip()
    if not os.path.isfile(path):
        return f"[参数错误] 文件不存在: {path}"
    ext = os.path.splitext(path)[1].lower()
    sections = []
    all_text = ""

    finfo = run_cmd(["file", path], timeout=15)
    sections.append(f"[file]\n{finfo}")
    all_text += finfo

    if ext == ".pdf" or "PDF document" in finfo:
        if _which("mutool"):
            info = run_cmd(["mutool", "info", path], timeout=30)
            sections.append(f"[PDF 元数据 mutool]\n{_truncate(info, 1500)}")
            all_text += info
            extract_dir = "/tmp/pdf_extract"
            os.makedirs(extract_dir, exist_ok=True)
            run_cmd(["mutool", "extract", "-q", extract_dir, path], timeout=60)
            files = sorted(os.listdir(extract_dir))[:20]
            if files:
                sections.append("[已提取对象]\n" + "\n".join(
                    f"- {extract_dir}/{f}" for f in files))
                all_text += "\n".join(files)
        if _which("pdfimages"):
            pdfdir = "/tmp/pdf_images"
            os.makedirs(pdfdir, exist_ok=True)
            run_cmd(["pdfimages", "-all", path, f"{pdfdir}/img"], timeout=60)
            imgs = sorted(os.listdir(pdfdir))[:15]
            if imgs:
                sections.append("[内嵌图片]\n" + "\n".join(f"{pdfdir}/{i}" for i in imgs))
        strs = run_cmd(["bash", "-c", f"strings -a '{path}' | grep -aiE 'flag|uri|javascript|"
                                      f"openaction|launch|embed' | head -30"], timeout=30)
        sections.append(f"[可疑字符串 (flag/js/launch)]\n{_truncate(strs, 1500) or '[无]'}")
        all_text += strs
        js = run_cmd(["bash", "-c", f"qpdf --qdf --object-streams=disable '{path}' /tmp/pdf_qdf.pdf 2>&1 && "
                                    f"strings -a /tmp/pdf_qdf.pdf | grep -aE '\\(.*\\)' | head -30"], timeout=30)
        if "qpdf" not in js.lower() or "cannot" not in js.lower():
            sections.append(f"[解压后内容流]\n{_truncate(js, 1500) or '[qpdf 缺失，跳过]'}")
            all_text += js
    elif ext in (".docx", ".xlsx", ".pptx", ".doc", ".xls", ".ppt") or "Microsoft" in finfo:
        vba = _which("olevba")
        if vba:
            out = run_cmd([vba, path], timeout=60)
            sections.append(f"[VBA 宏 olevba]\n{_truncate(out, 2500)}")
            all_text += out
        else:
            sections.append("[olevba 未安装] pip install oletools")
        # zip 结构（ooxml 是 zip）
        zl = run_cmd(["bash", "-c", f"unzip -l '{path}' 2>/dev/null | head -30"], timeout=20)
        if zl and "[无输出]" not in zl:
            sections.append(f"[OOXML zip 结构]\n{_truncate(zl, 1500)}")
            all_text += zl
        # 7z 全量解包
        exdir = "/tmp/office_extract"
        os.makedirs(exdir, exist_ok=True)
        run_cmd(["7z", "x", "-y", f"-o{exdir}", path], timeout=60)
        hits = _grep_in_dir(exdir)
        if hits:
            sections.append(f"[解包内容 flag 命中] {hits}")
        else:
            files = [f"{exdir}/{f}" for f in sorted(os.listdir(exdir))[:15]]
            if files:
                sections.append("[已解包]\n" + "\n".join(files))
    else:
        sections.append(f"[WARN] 未知文档类型，改用 analyze_file 通用分析")

    footer = _flags_footer(all_text,
                           extra_files=[f"/tmp/pdf_extract/{f}" for f in os.listdir("/tmp/pdf_extract")[:20]]
                           if os.path.isdir("/tmp/pdf_extract") else None)
    sections.append(footer.strip() if footer else
                    "[下一步] 关注 JS/OpenAction/Launch 动作（PDF 恶意行为）、宏代码里的编码块 "
                    "（base64 → auto_decode）、内嵌图片（qr_decode/analyze_file）。")
    return "\n\n".join(sections)
