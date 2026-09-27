<?php
declare(strict_types=1);

header('Content-Type: text/html; charset=UTF-8');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');

const DEFAULT_REFRESH = 5;
const MIN_REFRESH = 2;
const MAX_REFRESH = 300;

function h(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function readFileSafe(string $path): ?string
{
    $data = @file_get_contents($path);

    if ($data === false) {
        return null;
    }

    return $data;
}

function readFirstLine(string $path): ?string
{
    $handle = @fopen($path, 'rb');

    if ($handle === false) {
        return null;
    }

    $line = fgets($handle);
    fclose($handle);

    if ($line === false) {
        return null;
    }

    return trim($line);
}

function getClockTicks(): int
{
    static $ticks = null;

    if ($ticks !== null) {
        return $ticks;
    }

    $value = @shell_exec('getconf CLK_TCK 2>/dev/null');

    if (is_string($value)) {
        $value = trim($value);

        if (ctype_digit($value) && (int)$value > 0) {
            $ticks = (int)$value;
            return $ticks;
        }
    }

    $ticks = 100;

    return $ticks;
}

function getPageSize(): int
{
    static $pageSize = null;

    if ($pageSize !== null) {
        return $pageSize;
    }

    $value = @shell_exec('getconf PAGESIZE 2>/dev/null');

    if (is_string($value)) {
        $value = trim($value);

        if (ctype_digit($value) && (int)$value > 0) {
            $pageSize = (int)$value;
            return $pageSize;
        }
    }

    $pageSize = 4096;

    return $pageSize;
}

function getBootTime(): int
{
    static $bootTime = null;

    if ($bootTime !== null) {
        return $bootTime;
    }

    $stat = readFileSafe('/proc/stat');

    if ($stat !== null && preg_match('/^btime\s+(\d+)$/m', $stat, $matches)) {
        $bootTime = (int)$matches[1];
        return $bootTime;
    }

    $uptime = readFirstLine('/proc/uptime');

    if ($uptime !== null) {
        $parts = preg_split('/\s+/', $uptime);

        if (isset($parts[0]) && is_numeric($parts[0])) {
            $bootTime = time() - (int)(float)$parts[0];
            return $bootTime;
        }
    }

    $bootTime = time();

    return $bootTime;
}

function getUptime(): float
{
    $line = readFirstLine('/proc/uptime');

    if ($line === null) {
        return 0.0;
    }

    $parts = preg_split('/\s+/', $line);

    if (!isset($parts[0]) || !is_numeric($parts[0])) {
        return 0.0;
    }

    return (float)$parts[0];
}

function getCpuCount(): int
{
    static $count = null;

    if ($count !== null) {
        return $count;
    }

    $cpuInfo = readFileSafe('/proc/cpuinfo');

    if ($cpuInfo !== null) {
        preg_match_all('/^processor\s*:/m', $cpuInfo, $matches);

        if (count($matches[0]) > 0) {
            $count = count($matches[0]);
            return $count;
        }
    }

    $count = 1;

    return $count;
}

function parseMemInfo(): array
{
    $result = [
        'MemTotal' => 0,
        'MemAvailable' => 0,
        'MemFree' => 0,
        'Buffers' => 0,
        'Cached' => 0,
        'SwapTotal' => 0,
        'SwapFree' => 0,
    ];

    $data = readFileSafe('/proc/meminfo');

    if ($data === null) {
        return $result;
    }

    foreach (explode("\n", $data) as $line) {
        if (preg_match('/^([A-Za-z_()]+):\s+(\d+)\s+kB$/', trim($line), $matches)) {
            $key = $matches[1];

            if (array_key_exists($key, $result)) {
                $result[$key] = (int)$matches[2] * 1024;
            }
        }
    }

    if ($result['MemAvailable'] === 0) {
        $result['MemAvailable'] =
            $result['MemFree'] +
            $result['Buffers'] +
            $result['Cached'];
    }

    return $result;
}

function uidToUsername(int $uid): string
{
    static $cache = [];

    if (isset($cache[$uid])) {
        return $cache[$uid];
    }

    if (function_exists('posix_getpwuid')) {
        $info = @posix_getpwuid($uid);

        if (is_array($info) && isset($info['name'])) {
            $cache[$uid] = (string)$info['name'];
            return $cache[$uid];
        }
    }

    $passwd = readFileSafe('/etc/passwd');

    if ($passwd !== null) {
        foreach (explode("\n", $passwd) as $line) {
            if ($line === '') {
                continue;
            }

            $parts = explode(':', $line);

            if (count($parts) >= 3 && ctype_digit($parts[2]) && (int)$parts[2] === $uid) {
                $cache[$uid] = $parts[0];
                return $cache[$uid];
            }
        }
    }

    $cache[$uid] = (string)$uid;

    return $cache[$uid];
}

function parseStatus(string $path): array
{
    $result = [
        'uid' => 0,
        'threads' => 0,
        'vmrss' => 0,
        'vmsize' => 0,
    ];

    $data = readFileSafe($path);

    if ($data === null) {
        return $result;
    }

    foreach (explode("\n", $data) as $line) {
        if (str_starts_with($line, 'Uid:')) {
            $parts = preg_split('/\s+/', trim(substr($line, 4)));

            if (isset($parts[0]) && ctype_digit($parts[0])) {
                $result['uid'] = (int)$parts[0];
            }
        } elseif (str_starts_with($line, 'Threads:')) {
            $value = trim(substr($line, 8));

            if (ctype_digit($value)) {
                $result['threads'] = (int)$value;
            }
        } elseif (str_starts_with($line, 'VmRSS:')) {
            if (preg_match('/(\d+)/', $line, $matches)) {
                $result['vmrss'] = (int)$matches[1] * 1024;
            }
        } elseif (str_starts_with($line, 'VmSize:')) {
            if (preg_match('/(\d+)/', $line, $matches)) {
                $result['vmsize'] = (int)$matches[1] * 1024;
            }
        }
    }

    return $result;
}

function parseProcessStat(string $data): ?array
{
    $open = strpos($data, '(');
    $close = strrpos($data, ')');

    if ($open === false || $close === false || $close <= $open) {
        return null;
    }

    $pidPart = trim(substr($data, 0, $open));
    $name = substr($data, $open + 1, $close - $open - 1);
    $rest = trim(substr($data, $close + 1));

    if (!ctype_digit($pidPart) || $rest === '') {
        return null;
    }

    $fields = preg_split('/\s+/', $rest);

    if (!is_array($fields) || count($fields) < 22) {
        return null;
    }

    return [
        'pid' => (int)$pidPart,
        'name' => $name,
        'state' => $fields[0] ?? '?',
        'ppid' => isset($fields[1]) ? (int)$fields[1] : 0,
        'utime' => isset($fields[11]) ? (int)$fields[11] : 0,
        'stime' => isset($fields[12]) ? (int)$fields[12] : 0,
        'priority' => isset($fields[15]) ? (int)$fields[15] : 0,
        'nice' => isset($fields[16]) ? (int)$fields[16] : 0,
        'num_threads' => isset($fields[17]) ? (int)$fields[17] : 0,
        'starttime' => isset($fields[19]) ? (int)$fields[19] : 0,
        'vsize' => isset($fields[20]) ? (int)$fields[20] : 0,
        'rss_pages' => isset($fields[21]) ? (int)$fields[21] : 0,
    ];
}

function readCommandLine(int $pid, string $fallback): string
{
    $data = readFileSafe("/proc/$pid/cmdline");

    if ($data === null || $data === '') {
        return '[' . $fallback . ']';
    }

    $command = str_replace("\0", ' ', $data);
    $command = trim(preg_replace('/\s+/', ' ', $command) ?? '');

    return $command !== '' ? $command : '[' . $fallback . ']';
}

function readProcess(int $pid, float $uptime, int $clockTicks): ?array
{
    $base = "/proc/$pid";

    $statData = readFileSafe("$base/stat");

    if ($statData === null) {
        return null;
    }

    $stat = parseProcessStat($statData);

    if ($stat === null) {
        return null;
    }

    $status = parseStatus("$base/status");

    $ticks = $stat['utime'] + $stat['stime'];
    $cpuTime = $ticks / $clockTicks;

    $processAge = $uptime - ($stat['starttime'] / $clockTicks);

    if ($processAge < 0.01) {
        $processAge = 0.01;
    }

    $cpuPercent = ($cpuTime / $processAge) * 100.0;

    if (!is_finite($cpuPercent) || $cpuPercent < 0) {
        $cpuPercent = 0.0;
    }

    $rss = $status['vmrss'];

    if ($rss === 0 && $stat['rss_pages'] > 0) {
        $rss = $stat['rss_pages'] * getPageSize();
    }

    $vsize = $status['vmsize'];

    if ($vsize === 0) {
        $vsize = $stat['vsize'];
    }

    $startTimestamp = getBootTime() + (int)($stat['starttime'] / $clockTicks);

    return [
        'pid' => $stat['pid'],
        'ppid' => $stat['ppid'],
        'name' => $stat['name'],
        'state' => $stat['state'],
        'uid' => $status['uid'],
        'user' => uidToUsername($status['uid']),
        'threads' => $status['threads'] > 0 ? $status['threads'] : $stat['num_threads'],
        'priority' => $stat['priority'],
        'nice' => $stat['nice'],
        'cpu_time' => $cpuTime,
        'cpu_percent' => $cpuPercent,
        'rss' => $rss,
        'vsize' => $vsize,
        'start' => $startTimestamp,
        'age' => $processAge,
        'command' => readCommandLine($pid, $stat['name']),
    ];
}

function getProcesses(): array
{
    $entries = @scandir('/proc');

    if ($entries === false) {
        return [];
    }

    $processes = [];
    $uptime = getUptime();
    $clockTicks = getClockTicks();

    foreach ($entries as $entry) {
        if (!ctype_digit($entry)) {
            continue;
        }

        $pid = (int)$entry;

        if ($pid <= 0) {
            continue;
        }

        $process = readProcess($pid, $uptime, $clockTicks);

        if ($process !== null) {
            $processes[] = $process;
        }
    }

    return $processes;
}

function formatBytes(int|float $bytes): string
{
    $bytes = max(0, (float)$bytes);
    $units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
    $index = 0;

    while ($bytes >= 1024 && $index < count($units) - 1) {
        $bytes /= 1024;
        $index++;
    }

    if ($index === 0) {
        return number_format($bytes, 0) . ' ' . $units[$index];
    }

    return number_format($bytes, 1) . ' ' . $units[$index];
}

function formatDuration(float $seconds): string
{
    $seconds = max(0, (int)$seconds);

    $days = intdiv($seconds, 86400);
    $seconds %= 86400;

    $hours = intdiv($seconds, 3600);
    $seconds %= 3600;

    $minutes = intdiv($seconds, 60);
    $seconds %= 60;

    if ($days > 0) {
        return sprintf('%dd %02d:%02d:%02d', $days, $hours, $minutes, $seconds);
    }

    return sprintf('%02d:%02d:%02d', $hours, $minutes, $seconds);
}

function stateDescription(string $state): string
{
    return match ($state) {
        'R' => 'Running',
        'S' => 'Sleeping',
        'D' => 'Disk sleep',
        'Z' => 'Zombie',
        'T' => 'Stopped',
        't' => 'Tracing',
        'X', 'x' => 'Dead',
        'I' => 'Idle',
        'K' => 'Wakekill',
        'W' => 'Waking',
        'P' => 'Parked',
        default => 'Unknown',
    };
}

function stateClass(string $state): string
{
    return match ($state) {
        'R' => 'state-running',
        'Z' => 'state-zombie',
        'D' => 'state-disk',
        'T', 't' => 'state-stopped',
        default => 'state-normal',
    };
}

function requestString(string $key, string $default = ''): string
{
    $value = $_GET[$key] ?? $default;

    if (!is_string($value)) {
        return $default;
    }

    return trim($value);
}

function requestInt(string $key, int $default): int
{
    $value = $_GET[$key] ?? null;

    if (!is_string($value) && !is_int($value)) {
        return $default;
    }

    if (filter_var($value, FILTER_VALIDATE_INT) === false) {
        return $default;
    }

    return (int)$value;
}

$allowedSorts = [
    'pid',
    'ppid',
    'user',
    'name',
    'state',
    'cpu_percent',
    'cpu_time',
    'rss',
    'vsize',
    'threads',
    'priority',
    'nice',
    'start',
    'age',
    'command',
];

$filter = requestString('q');
$sort = requestString('sort', 'cpu_percent');
$direction = strtolower(requestString('dir', 'desc'));
$refresh = requestInt('refresh', DEFAULT_REFRESH);

if (!in_array($sort, $allowedSorts, true)) {
    $sort = 'cpu_percent';
}

if (!in_array($direction, ['asc', 'desc'], true)) {
    $direction = 'desc';
}

$refresh = max(MIN_REFRESH, min(MAX_REFRESH, $refresh));

$processes = getProcesses();
$totalProcesses = count($processes);

if ($filter !== '') {
    $needle = mb_strtolower($filter, 'UTF-8');

    $processes = array_values(array_filter(
        $processes,
        static function (array $process) use ($needle): bool {
            $haystack = implode(' ', [
                (string)$process['pid'],
                (string)$process['ppid'],
                $process['user'],
                $process['name'],
                $process['state'],
                $process['command'],
            ]);

            return str_contains(
                mb_strtolower($haystack, 'UTF-8'),
                $needle
            );
        }
    ));
}

usort(
    $processes,
    static function (array $a, array $b) use ($sort, $direction): int {
        $left = $a[$sort] ?? null;
        $right = $b[$sort] ?? null;

        if (is_string($left) && is_string($right)) {
            $result = strnatcasecmp($left, $right);
        } else {
            $result = $left <=> $right;
        }

        if ($result === 0) {
            $result = $a['pid'] <=> $b['pid'];
        }

        return $direction === 'asc' ? $result : -$result;
    }
);

$memInfo = parseMemInfo();
$memoryTotal = $memInfo['MemTotal'];
$memoryAvailable = $memInfo['MemAvailable'];
$memoryUsed = max(0, $memoryTotal - $memoryAvailable);
$memoryPercent = $memoryTotal > 0
    ? ($memoryUsed / $memoryTotal) * 100
    : 0.0;

$swapTotal = $memInfo['SwapTotal'];
$swapUsed = max(0, $swapTotal - $memInfo['SwapFree']);

$load = @sys_getloadavg();

if (!is_array($load)) {
    $load = [0.0, 0.0, 0.0];
}

$hostname = gethostname();

if ($hostname === false || $hostname === '') {
    $hostname = readFirstLine('/proc/sys/kernel/hostname') ?? 'Linux';
}

$kernel = php_uname('r');
$cpuCount = getCpuCount();
$uptime = getUptime();

$runningProcesses = 0;
$sleepingProcesses = 0;
$zombieProcesses = 0;
$totalThreads = 0;

foreach ($processes as $process) {
    $totalThreads += $process['threads'];

    if ($process['state'] === 'R') {
        $runningProcesses++;
    } elseif ($process['state'] === 'Z') {
        $zombieProcesses++;
    } elseif ($process['state'] === 'S') {
        $sleepingProcesses++;
    }
}

function sortUrl(string $column): string
{
    global $sort, $direction, $filter, $refresh;

    $newDirection = 'desc';

    if ($sort === $column) {
        $newDirection = $direction === 'asc' ? 'desc' : 'asc';
    } elseif (in_array($column, ['user', 'name', 'state', 'command'], true)) {
        $newDirection = 'asc';
    }

    return '?' . http_build_query([
        'q' => $filter,
        'sort' => $column,
        'dir' => $newDirection,
        'refresh' => $refresh,
    ]);
}

function sortIndicator(string $column): string
{
    global $sort, $direction;

    if ($sort !== $column) {
        return '';
    }

    return $direction === 'asc' ? ' ▲' : ' ▼';
}

$self = $_SERVER['PHP_SELF'] ?? '';
$self = is_string($self) ? $self : '';

$currentUrl = '?' . http_build_query([
    'q' => $filter,
    'sort' => $sort,
    'dir' => $direction,
    'refresh' => $refresh,
]);
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta http-equiv="refresh" content="<?= $refresh ?>;url=<?= h($currentUrl) ?>">
<title>ProcStat · <?= h($hostname) ?></title>
<style>
:root {
    color-scheme: dark;
    --bg: #0d1117;
    --panel: #161b22;
    --panel-2: #1c2128;
    --border: #30363d;
    --text: #e6edf3;
    --muted: #8b949e;
    --accent: #58a6ff;
    --green: #3fb950;
    --yellow: #d29922;
    --red: #f85149;
    --purple: #bc8cff;
}

* {
    box-sizing: border-box;
}

html {
    background: var(--bg);
}

body {
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font-family:
        Inter,
        ui-sans-serif,
        system-ui,
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        sans-serif;
    font-size: 14px;
}

a {
    color: inherit;
}

.container {
    width: 100%;
    max-width: 1900px;
    margin: 0 auto;
    padding: 24px;
}

header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 24px;
    margin-bottom: 22px;
}

.brand h1 {
    margin: 0;
    font-size: 28px;
    font-weight: 700;
    letter-spacing: -0.5px;
}

.brand h1 span {
    color: var(--accent);
}

.subtitle {
    margin-top: 5px;
    color: var(--muted);
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}

.refresh-info {
    color: var(--muted);
    text-align: right;
    line-height: 1.6;
}

.grid {
    display: grid;
    grid-template-columns: repeat(6, minmax(150px, 1fr));
    gap: 12px;
    margin-bottom: 18px;
}

.card {
    min-width: 0;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px;
}

.card-label {
    color: var(--muted);
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.7px;
    margin-bottom: 8px;
}

.card-value {
    font-size: 22px;
    font-weight: 650;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}

.card-detail {
    margin-top: 6px;
    color: var(--muted);
    font-size: 12px;
}

.toolbar {
    display: flex;
    gap: 10px;
    align-items: center;
    margin-bottom: 14px;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 12px;
}

.toolbar form {
    display: flex;
    gap: 10px;
    width: 100%;
    align-items: center;
}

input,
select,
button {
    border: 1px solid var(--border);
    background: var(--bg);
    color: var(--text);
    border-radius: 6px;
    height: 38px;
    padding: 0 12px;
    font: inherit;
}

input[type="search"] {
    flex: 1;
    min-width: 150px;
}

input:focus,
select:focus {
    outline: 1px solid var(--accent);
    border-color: var(--accent);
}

button {
    cursor: pointer;
    background: var(--panel-2);
}

button:hover {
    border-color: var(--accent);
}

.clear {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    height: 38px;
    padding: 0 12px;
    border: 1px solid var(--border);
    border-radius: 6px;
    text-decoration: none;
    background: var(--panel-2);
}

.clear:hover {
    border-color: var(--accent);
}

.table-panel {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
}

.table-scroll {
    width: 100%;
    overflow-x: auto;
}

table {
    width: 100%;
    min-width: 1500px;
    border-collapse: collapse;
    font-size: 13px;
}

thead {
    background: var(--panel-2);
}

th {
    position: sticky;
    top: 0;
    z-index: 2;
    background: var(--panel-2);
    border-bottom: 1px solid var(--border);
    text-align: left;
    white-space: nowrap;
    padding: 11px 10px;
    font-weight: 600;
}

th a {
    color: var(--muted);
    text-decoration: none;
}

th a:hover {
    color: var(--accent);
}

td {
    border-bottom: 1px solid rgba(48, 54, 61, 0.7);
    padding: 9px 10px;
    white-space: nowrap;
    vertical-align: middle;
}

tbody tr:hover {
    background: rgba(88, 166, 255, 0.055);
}

tbody tr:last-child td {
    border-bottom: none;
}

.num {
    text-align: right;
    font-variant-numeric: tabular-nums;
}

.pid {
    color: var(--accent);
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}

.user {
    color: var(--purple);
}

.process-name {
    font-weight: 600;
}

.command {
    max-width: 520px;
    overflow: hidden;
    text-overflow: ellipsis;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    color: #c9d1d9;
}

.state {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    min-width: 28px;
    height: 24px;
    border-radius: 5px;
    padding: 0 7px;
    font-weight: 700;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}

.state-running {
    color: var(--green);
    background: rgba(63, 185, 80, 0.12);
}

.state-zombie {
    color: var(--red);
    background: rgba(248, 81, 73, 0.12);
}

.state-disk {
    color: var(--yellow);
    background: rgba(210, 153, 34, 0.12);
}

.state-stopped {
    color: var(--purple);
    background: rgba(188, 140, 255, 0.12);
}

.state-normal {
    color: var(--muted);
    background: rgba(139, 148, 158, 0.10);
}

.cpu-hot {
    color: var(--yellow);
    font-weight: 600;
}

.cpu-very-hot {
    color: var(--red);
    font-weight: 700;
}

.footer {
    display: flex;
    justify-content: space-between;
    gap: 20px;
    color: var(--muted);
    margin-top: 14px;
    font-size: 12px;
}

.empty {
    padding: 40px;
    text-align: center;
    color: var(--muted);
}

.progress {
    height: 5px;
    background: var(--bg);
    border-radius: 999px;
    overflow: hidden;
    margin-top: 9px;
}

.progress > div {
    height: 100%;
    background: var(--accent);
    border-radius: inherit;
}

@media (max-width: 1200px) {
    .grid {
        grid-template-columns: repeat(3, 1fr);
    }
}

@media (max-width: 700px) {
    .container {
        padding: 14px;
    }

    header {
        flex-direction: column;
    }

    .refresh-info {
        text-align: left;
    }

    .grid {
        grid-template-columns: repeat(2, 1fr);
    }

    .toolbar form {
        flex-wrap: wrap;
    }

    input[type="search"] {
        width: 100%;
        flex-basis: 100%;
    }

    .footer {
        flex-direction: column;
    }
}

@media (max-width: 450px) {
    .grid {
        grid-template-columns: 1fr;
    }
}
</style>
</head>
<body>

<div class="container">

<header>
    <div class="brand">
        <h1>Proc<span>Stat</span></h1>
        <div class="subtitle">
            <?= h($hostname) ?> · Linux <?= h($kernel) ?> · <?= $cpuCount ?> CPU<?= $cpuCount === 1 ? '' : 's' ?>
        </div>
    </div>

    <div class="refresh-info">
        Auto-refresh: <?= $refresh ?>s<br>
        <?= h(date('Y-m-d H:i:s')) ?>
    </div>
</header>

<div class="grid">

    <div class="card">
        <div class="card-label">Processes</div>
        <div class="card-value"><?= number_format($totalProcesses) ?></div>
        <div class="card-detail">
            <?= $runningProcesses ?> running ·
            <?= $sleepingProcesses ?> sleeping ·
            <?= $zombieProcesses ?> zombie
        </div>
    </div>

    <div class="card">
        <div class="card-label">Threads</div>
        <div class="card-value"><?= number_format($totalThreads) ?></div>
        <div class="card-detail">
            visible processes
        </div>
    </div>

    <div class="card">
        <div class="card-label">Load Average</div>
        <div class="card-value">
            <?= number_format((float)$load[0], 2) ?>
        </div>
        <div class="card-detail">
            <?= number_format((float)$load[0], 2) ?> ·
            <?= number_format((float)$load[1], 2) ?> ·
            <?= number_format((float)$load[2], 2) ?>
        </div>
    </div>

    <div class="card">
        <div class="card-label">Memory</div>
        <div class="card-value">
            <?= number_format($memoryPercent, 1) ?>%
        </div>
        <div class="card-detail">
            <?= h(formatBytes($memoryUsed)) ?> /
            <?= h(formatBytes($memoryTotal)) ?>
        </div>
        <div class="progress">
            <div style="width: <?= min(100, max(0, $memoryPercent)) ?>%"></div>
        </div>
    </div>

    <div class="card">
        <div class="card-label">Swap</div>
        <div class="card-value">
            <?= h(formatBytes($swapUsed)) ?>
        </div>
        <div class="card-detail">
            of <?= h(formatBytes($swapTotal)) ?>
        </div>
    </div>

    <div class="card">
        <div class="card-label">Uptime</div>
        <div class="card-value">
            <?= h(formatDuration($uptime)) ?>
        </div>
        <div class="card-detail">
            boot <?= h(date('Y-m-d H:i', getBootTime())) ?>
        </div>
    </div>

</div>

<div class="toolbar">
    <form method="get" action="<?= h($self) ?>">

        <input
            type="search"
            name="q"
            value="<?= h($filter) ?>"
            placeholder="Filter PID, user, process or command..."
            autocomplete="off"
        >

        <input type="hidden" name="sort" value="<?= h($sort) ?>">
        <input type="hidden" name="dir" value="<?= h($direction) ?>">

        <select name="refresh" title="Auto-refresh interval">
            <?php foreach ([2, 5, 10, 15, 30, 60, 120, 300] as $seconds): ?>
                <option
                    value="<?= $seconds ?>"
                    <?= $refresh === $seconds ? 'selected' : '' ?>
                >
                    <?= $seconds ?>s refresh
                </option>
            <?php endforeach; ?>
        </select>

        <button type="submit">Apply</button>

        <a
            class="clear"
            href="?<?= h(http_build_query([
                'sort' => 'cpu_percent',
                'dir' => 'desc',
                'refresh' => $refresh,
            ])) ?>"
        >Reset</a>

    </form>
</div>

<div class="table-panel">
<div class="table-scroll">

<?php if ($processes === []): ?>

    <div class="empty">
        No processes matched the current filter.
    </div>

<?php else: ?>

<table>
<thead>
<tr>
    <th class="num">
        <a href="<?= h(sortUrl('pid')) ?>">
            PID<?= h(sortIndicator('pid')) ?>
        </a>
    </th>

    <th class="num">
        <a href="<?= h(sortUrl('ppid')) ?>">
            PPID<?= h(sortIndicator('ppid')) ?>
        </a>
    </th>

    <th>
        <a href="<?= h(sortUrl('user')) ?>">
            USER<?= h(sortIndicator('user')) ?>
        </a>
    </th>

    <th>
        <a href="<?= h(sortUrl('name')) ?>">
            PROCESS<?= h(sortIndicator('name')) ?>
        </a>
    </th>

    <th>
        <a href="<?= h(sortUrl('state')) ?>">
            STATE<?= h(sortIndicator('state')) ?>
        </a>
    </th>

    <th class="num">
        <a href="<?= h(sortUrl('cpu_percent')) ?>">
            CPU %<?= h(sortIndicator('cpu_percent')) ?>
        </a>
    </th>

    <th class="num">
        <a href="<?= h(sortUrl('cpu_time')) ?>">
            CPU TIME<?= h(sortIndicator('cpu_time')) ?>
        </a>
    </th>

    <th class="num">
        <a href="<?= h(sortUrl('rss')) ?>">
            RSS<?= h(sortIndicator('rss')) ?>
        </a>
    </th>

    <th class="num">
        <a href="<?= h(sortUrl('vsize')) ?>">
            VSZ<?= h(sortIndicator('vsize')) ?>
        </a>
    </th>

    <th class="num">
        <a href="<?= h(sortUrl('threads')) ?>">
            THR<?= h(sortIndicator('threads')) ?>
        </a>
    </th>

    <th class="num">
        <a href="<?= h(sortUrl('priority')) ?>">
            PRI<?= h(sortIndicator('priority')) ?>
        </a>
    </th>

    <th class="num">
        <a href="<?= h(sortUrl('nice')) ?>">
            NI<?= h(sortIndicator('nice')) ?>
        </a>
    </th>

    <th>
        <a href="<?= h(sortUrl('start')) ?>">
            START<?= h(sortIndicator('start')) ?>
        </a>
    </th>

    <th>
        <a href="<?= h(sortUrl('age')) ?>">
            AGE<?= h(sortIndicator('age')) ?>
        </a>
    </th>

    <th>
        <a href="<?= h(sortUrl('command')) ?>">
            COMMAND<?= h(sortIndicator('command')) ?>
        </a>
    </th>
</tr>
</thead>

<tbody>

<?php foreach ($processes as $process): ?>
<?php
$cpuClass = '';

if ($process['cpu_percent'] >= 80) {
    $cpuClass = 'cpu-very-hot';
} elseif ($process['cpu_percent'] >= 25) {
    $cpuClass = 'cpu-hot';
}
?>

<tr>

    <td class="num pid">
        <?= $process['pid'] ?>
    </td>

    <td class="num">
        <?= $process['ppid'] ?>
    </td>

    <td class="user">
        <?= h($process['user']) ?>
    </td>

    <td class="process-name">
        <?= h($process['name']) ?>
    </td>

    <td>
        <span
            class="state <?= h(stateClass($process['state'])) ?>"
            title="<?= h(stateDescription($process['state'])) ?>"
        >
            <?= h($process['state']) ?>
        </span>
    </td>

    <td class="num <?= h($cpuClass) ?>">
        <?= number_format($process['cpu_percent'], 1) ?>
    </td>

    <td class="num">
        <?= h(formatDuration($process['cpu_time'])) ?>
    </td>

    <td class="num">
        <?= h(formatBytes($process['rss'])) ?>
    </td>

    <td class="num">
        <?= h(formatBytes($process['vsize'])) ?>
    </td>

    <td class="num">
        <?= number_format($process['threads']) ?>
    </td>

    <td class="num">
        <?= $process['priority'] ?>
    </td>

    <td class="num">
        <?= $process['nice'] ?>
    </td>

    <td>
        <?= h(date('m-d H:i:s', $process['start'])) ?>
    </td>

    <td>
        <?= h(formatDuration($process['age'])) ?>
    </td>

    <td
        class="command"
        title="<?= h($process['command']) ?>"
    >
        <?= h($process['command']) ?>
    </td>

</tr>

<?php endforeach; ?>

</tbody>
</table>

<?php endif; ?>

</div>
</div>

<div class="footer">
    <div>
        Showing <?= number_format(count($processes)) ?>
        of <?= number_format($totalProcesses) ?> processes
        <?php if ($filter !== ''): ?>
            · filter: "<?= h($filter) ?>"
        <?php endif; ?>
    </div>

    <div>
        /proc · PHP <?= h(PHP_VERSION) ?> · Cybernetic Garden
    </div>
</div>

</div>

</body>
</html>
