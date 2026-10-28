#!/bin/sh
# ==============================================================================
# 脚本名称: monitor_commands.sh
# 用途: Linux 无代理系统资源采集监控脚本（兼容 FinalShell / 运维终端无代理采集逻辑）
# 特性: 纯标准命令与 /proc 虚拟文件系统，无三方依赖，低系统开销，输出格式易于解析
# 支持模式:
#   1. 单次采样输出: ./monitor_commands.sh --once [采样间隔(秒，默认1)]
#   2. 持续循环输出: ./monitor_commands.sh --loop [采样间隔(秒，默认2)]
# ==============================================================================

INTERVAL=${2:-1}
MODE=${1:-"--once"}

# ------------------------------------------------------------------------------
# 辅助函数: 获取 /proc/stat CPU 时间片
# 返回: user nice system idle iowait irq softirq steal
# ------------------------------------------------------------------------------
get_cpu_stat() {
    grep '^cpu ' /proc/stat | awk '{print $2, $3, $4, $5, $6, $7, $8, $9}'
}

# ------------------------------------------------------------------------------
# 辅助函数: 计算 CPU 使用率 (两点采样法)
# ------------------------------------------------------------------------------
calc_cpu_usage() {
    stat1=$(get_cpu_stat)
    sleep "$INTERVAL"
    stat2=$(get_cpu_stat)

    # 计算 total 和 idle
    cpu_usage=$(awk -v s1="$stat1" -v s2="$stat2" 'BEGIN {
        split(s1, a); split(s2, b);
        idle1 = a[4] + a[5]; # idle + iowait
        idle2 = b[4] + b[5];
        
        total1 = 0; total2 = 0;
        for (i=1; i<=8; i++) {
            total1 += a[i];
            total2 += b[i];
        }
        
        diff_total = total2 - total1;
        diff_idle = idle2 - idle1;
        
        if (diff_total <= 0) {
            printf "0.00";
        } else {
            printf "%.2f", (diff_total - diff_idle) / diff_total * 100;
        }
    }')
    echo "$cpu_usage"
}

# ------------------------------------------------------------------------------
# 核心采集函数: 汇总并输出标准格式数据包
# ------------------------------------------------------------------------------
collect_metrics() {
    # 1. 采集时间戳
    TIMESTAMP=$(date +%s)
    
    # 2. 系统负载与运行时间 (读取 /proc/loadavg 与 /proc/uptime)
    LOAD_AVG=$(cat /proc/loadavg | awk '{print $1, $2, $3}')
    UPTIME_SEC=$(cat /proc/uptime | awk '{print int($1)}')
    UPTIME_STR=$(uptime 2>/dev/null | sed 's/.*up \([^,]*\), .*/\1/')

    # 3. CPU 使用率 (通过采样点差值计算)
    # 在采集开始记录第1个采样点
    CPU_STAT_1=$(get_cpu_stat)
    
    # 采集网卡初值
    NET_STAT_1=$(grep -v 'lo:' /proc/net/dev | awk -F: '/:/{print $1, $2}' | awk '{print $1, $2, $10}')

    # 睡眠采集间隔
    sleep "$INTERVAL"

    # CPU 采样点2并计算
    CPU_STAT_2=$(get_cpu_stat)
    CPU_USAGE=$(awk -v s1="$CPU_STAT_1" -v s2="$CPU_STAT_2" 'BEGIN {
        split(s1, a); split(s2, b);
        idle1 = a[4] + a[5];
        idle2 = b[4] + b[5];
        t1 = 0; t2 = 0;
        for (i=1; i<=8; i++) { t1 += a[i]; t2 += b[i]; }
        dt = t2 - t1; di = idle2 - idle1;
        if (dt <= 0) printf "0.00"; else printf "%.2f", (dt - di) / dt * 100;
    }')

    # 4. 内存及缓存详情 (/proc/meminfo)
    # 单位均为 KB
    MEM_METRICS=$(awk '
    /^MemTotal:/      {total=$2}
    /^MemFree:/       {free=$2}
    /^MemAvailable:/  {avail=$2}
    /^Buffers:/       {buffers=$2}
    /^Cached:/        {cached=$2}
    /^SReclaimable:/  {srec=$2}
    /^Shmem:/         {shmem=$2}
    /^SwapTotal:/     {stotal=$2}
    /^SwapFree:/      {sfree=$2}
    END {
        # 如果内核版本支持 MemAvailable (内核 >= 3.14)
        if (avail == "" || avail == 0) {
            # 传统计算公式: Available = Free + Buffers + Cached (修正 SReclaimable 与 Shmem)
            real_cached = cached + srec - shmem;
            if (real_cached < 0) real_cached = cached;
            avail = free + buffers + real_cached;
        }
        used = total - avail;
        if (used < 0) used = 0;
        usage_pct = (total > 0) ? (used / total * 100) : 0;

        swap_used = stotal - sfree;
        swap_usage_pct = (stotal > 0) ? (swap_used / stotal * 100) : 0;

        printf "total=%d free=%d avail=%d buffers=%d cached=%d used=%d usage_pct=%.2f swap_total=%d swap_used=%d swap_usage_pct=%.2f",
               total, free, avail, buffers, cached, used, usage_pct, stotal, swap_used, swap_usage_pct;
    }' /proc/meminfo)

    # 5. 网络流量与速率计算 (/proc/net/dev)
    NET_STAT_2=$(grep -v 'lo:' /proc/net/dev | awk -F: '/:/{print $1, $2}' | awk '{print $1, $2, $10}')
    NET_RATES=$(awk -v s1="$NET_STAT_1" -v s2="$NET_STAT_2" -v iv="$INTERVAL" 'BEGIN {
        # 解析初值
        split(s1, lines1, "\n");
        for (i in lines1) {
            if (split(lines1[i], f) >= 3) {
                rx1[f[1]] = f[2];
                tx1[f[1]] = f[3];
            }
        }
        # 解析终值并计算速率 (Byte/s)
        split(s2, lines2, "\n");
        for (i in lines2) {
            if (split(lines2[i], f) >= 3) {
                iface = f[1];
                rx2 = f[2]; tx2 = f[3];
                if (iface in rx1) {
                    rx_rate = (rx2 >= rx1[iface]) ? (rx2 - rx1[iface]) / iv : 0;
                    tx_rate = (tx2 >= tx1[iface]) ? (tx2 - tx1[iface]) / iv : 0;
                    printf "%s:rx_rate=%.0f,tx_rate=%.0f,rx_bytes=%s,tx_bytes=%s;", iface, rx_rate, tx_rate, rx2, tx2;
                }
            }
        }
    }')

    # 6. 磁盘挂载与容量 (采用 POSIX 规范参数 -P，防止换行错位)
    DISK_INFO=$(df -P -k 2>/dev/null | grep -E '^/dev/' | awk '{
        printf "%s:%s:%s:%s:%s:%s;", $1, $2, $3, $4, $5, $6
    }')

    # --------------------------------------------------------------------------
    # 格式化输出: 协议数据段 (便于终端解析器单次行读取或分段匹配)
    # --------------------------------------------------------------------------
    echo "===BEGIN_MONITOR_METRICS==="
    echo "TIMESTAMP: $TIMESTAMP"
    echo "UPTIME: $UPTIME_SEC (str: $UPTIME_STR)"
    echo "LOAD: $LOAD_AVG"
    echo "CPU_USAGE: $CPU_USAGE"
    echo "MEMORY: $MEM_METRICS"
    echo "NETWORK: $NET_RATES"
    echo "DISK: $DISK_INFO"
    echo "===END_MONITOR_METRICS==="
}

# ------------------------------------------------------------------------------
# 主执行入口
# ------------------------------------------------------------------------------
case "$MODE" in
    --once)
        collect_metrics
        ;;
    --loop)
        while true; do
            collect_metrics
            # 如需额外间歇可以在此调节
        done
        ;;
    --help|-h)
        echo "Usage: $0 [--once|--loop] [interval_seconds]"
        echo "  --once  采样一次并输出 (默认采样间隔: 1s)"
        echo "  --loop  持续采样循环输出 (默认采样间隔: 1s)"
        ;;
    *)
        collect_metrics
        ;;
esac
