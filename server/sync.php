<?php

$source = 'https://raw.githubusercontent.com/Tavaress21/tguard/updates/';
$target = getenv('TGUARD_UPDATES_DIR') ?: __DIR__ . '/../tguard.luis-tavares.pt/updates';

function context()
{
    return stream_context_create(['http' => ['timeout' => 120, 'user_agent' => 'TGuard-sync', 'ignore_errors' => true]]);
}

function ok($headers)
{
    return isset($headers[0]) && preg_match('{^HTTP/\S+\s+200\b}', $headers[0]);
}

function fetch($url)
{
    $data = @file_get_contents($url, false, context());
    $headers = function_exists('http_get_last_response_headers') ? http_get_last_response_headers() : ($http_response_header ?? []);
    return $data !== false && ok($headers) ? $data : null;
}

function download($url, $path, $sha256)
{
    $in = @fopen($url, 'rb', false, context());
    if ($in === false) {
        return false;
    }
    $headers = function_exists('http_get_last_response_headers') ? http_get_last_response_headers() : ($http_response_header ?? []);
    $tmp = $path . '.tmp';
    $out = ok($headers) ? fopen($tmp, 'wb') : false;
    $copied = $out !== false && stream_copy_to_stream($in, $out) !== false;
    fclose($in);
    if ($out !== false) {
        fclose($out);
    }
    if (!$copied || hash_file('sha256', $tmp) !== $sha256) {
        @unlink($tmp);
        return false;
    }
    return rename($tmp, $path);
}

function matches($path, $sha256)
{
    return is_file($path) && hash_file('sha256', $path) === $sha256;
}

function put($path, $data)
{
    if (matches($path, hash('sha256', $data))) {
        return 0;
    }
    $tmp = $path . '.tmp';
    if (file_put_contents($tmp, $data) === false || !rename($tmp, $path)) {
        @unlink($tmp);
        return 0;
    }
    return 1;
}

function signed($name)
{
    global $source;
    $data = fetch($source . $name);
    $signature = $data === null ? null : fetch($source . $name . '.sig');
    $json = $signature === null ? null : json_decode($data, true);
    return is_array($json) ? [$data, $signature, $json] : null;
}

if (!is_dir($target) && !mkdir($target, 0755, true)) {
    fwrite(STDERR, "cannot create $target\n");
    exit(1);
}

$changed = 0;
$errors = [];

if ($feeds = signed('feeds.json')) {
    [$data, $signature, $manifest] = $feeds;
    $complete = true;
    foreach (['signatures', 'urls', 'rules', 'allow'] as $key) {
        $entry = $manifest[$key] ?? null;
        if (!is_array($entry)) {
            continue;
        }
        $name = (string) ($entry['name'] ?? '');
        $sha256 = strtolower((string) ($entry['sha256'] ?? ''));
        if (!preg_match('/^[a-z]+\.(txt|json)$/', $name) || !preg_match('/^[a-f0-9]{64}$/', $sha256)) {
            $complete = false;
            break;
        }
        if (matches("$target/$name", $sha256)) {
            continue;
        }
        if (!download($source . $name, "$target/$name", $sha256)) {
            $errors[] = $name;
            $complete = false;
            break;
        }
        $changed++;
    }
    if ($complete) {
        $changed += put("$target/feeds.json", $data);
        $changed += put("$target/feeds.json.sig", $signature);
    }
} else {
    $errors[] = 'feeds.json';
}

if ($app = signed('app.json')) {
    [$data, $signature, $release] = $app;
    $file = (string) ($release['file'] ?? '');
    $sha256 = strtolower((string) ($release['sha256'] ?? ''));
    if (preg_match('/^TGuard-Setup-[0-9.]+\.exe$/', $file) && preg_match('/^[a-f0-9]{64}$/', $sha256)) {
        $ready = matches("$target/$file", $sha256);
        if (!$ready && download($source . $file, "$target/$file", $sha256)) {
            $ready = true;
            $changed++;
        }
        if ($ready) {
            $changed += put("$target/app.json", $data);
            $changed += put("$target/app.json.sig", $signature);
            foreach (glob("$target/TGuard-Setup-*.exe") ?: [] as $old) {
                if (basename($old) !== $file) {
                    unlink($old);
                }
            }
        } else {
            $errors[] = $file;
        }
    }
} else {
    $errors[] = 'app.json';
}

echo date('c') . " sync done, $changed file(s) updated" . ($errors ? ', failed: ' . implode(', ', $errors) : '') . "\n";
