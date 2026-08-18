FROM debian:bookworm-slim

# 防止 apt 卡在交互问询
ENV DEBIAN_FRONTEND=noninteractive

# 用 Debian 官方源（不走 Kali 分流镜像，避免 DNS 失败）
RUN sed -i 's|deb.debian.org|deb.debian.org|g' /etc/apt/sources.list.d/debian.sources 2>/dev/null || true && \
    apt-get update && apt-get install -y --no-install-recommends \
    # Python 基础
    python3 python3-venv python3-pip \
    # 文件分析 / Forensics
    file binutils binwalk foremost \
    libimage-exiftool-perl \
    steghide \
    # Web 渗透
    dirb \
    # 网络扫描 / 渗透
    nmap hydra \
    # 通用工具
    curl wget git jq unzip \
    # 编译依赖（pip 装 pwntools 等需要）
    gcc g++ make pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# sqlmap, gobuster, nikto, radare2 通过 git/pip 装（Debian 主源没有或不全）
# 用 || true 容错每步，避免某工具失败拖垮整条命令
RUN cd /opt && git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git 2>/dev/null && \
    ln -sf /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap && \
    chmod +x /opt/sqlmap/sqlmap.py || true

RUN cd /opt && git clone --depth 1 https://github.com/sullo/nikto.git 2>/dev/null && \
    (ls /opt/nikto/nikto.pl 2>/dev/null && ln -sf /opt/nikto/nikto.pl /usr/local/bin/nikto && chmod +x /opt/nikto/nikto.pl || \
     find /opt/nikto -name 'nikto*.pl' -exec ln -sf {} /usr/local/bin/nikto \; 2>/dev/null) || true

RUN cd /opt && git clone --depth 1 https://github.com/OJ/gobuster.git 2>/dev/null || true

RUN cd /opt && git clone --depth 1 https://github.com/radareorg/radare2.git 2>/dev/null && \
    cd /opt/radare2 && sys/install.sh 2>/dev/null || true

RUN rm -rf /opt/radare2/.git /opt/gobuster/.git /opt/nikto/.git /opt/sqlmap/.git 2>/dev/null || true

# zsteg (PNG LSB 隐写) 是 ruby 工具
RUN apt-get update && apt-get install -y --no-install-recommends ruby ruby-dev && \
    gem install zsteg --no-document 2>/dev/null || true && \
    rm -rf /var/lib/apt/lists/*

# 工作目录
WORKDIR /app

# 先装 Python 依赖（利用 docker 层缓存）
COPY requirements.txt .
RUN python3 -m venv /app/.venv && \
    /app/.venv/bin/pip install --no-cache-dir -r requirements.txt && \
    /app/.venv/bin/pip install --no-cache-dir sympy pycryptodome gmpy2 pwntools ropgadget

# 复制代码（.dockerignore 会挡住 .env 和本地数据）
COPY . /app/

# 输出目录
RUN mkdir -p /app/output /app/attachments /app/knowledge

# 默认环境变量（托管模式平台会覆盖）
ENV AUTO_START=true \
    GATEWAY_MODE=auto \
    PYTHONUNBUFFERED=1

# entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
