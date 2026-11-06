<?php

$source  = 'https://raw.githubusercontent.com/Tavaress21/tguard/updates/';
$target  = getenv('TGUARD_UPDATES_DIR') ?: __DIR__ . '/../public_html/tguard/updates';
$files   = ['feeds.json', 'feeds.json.sig', 'signatures.txt', 'urls.txt', 'rules.json', 'app.json', 'app.json.sig'];

function fetch($url) {
    $ctx = stream_context_create(['http' => ['timeout' => 120, 'user_agent' => 'TGuard-sync', 'ignore_errors' => true]]);
    $data = @file_get_contents($url, false, $ctx);
    if ($data === false) return null;
    if (isset($http_response_header[0]) && strpos($http_response_header[0], '200') === false) return null;
    return $data;
}

function put($path, $data) {
    $tmp = $path . '.tmp';
    if (file_put_contents($tmp, $data) === false) return false;
    return rename($tmp, $path);
}

if (!is_dir($target) && !mkdir($target, 0755, true)) {
    fwrite(STDERR, "cannot create $target\n");
    exit(1);
}

$changed = 0;
foreach ($files as $name) {
    $data = fetch($source . $name);
    if ($data === null) continue;
    $path = "$target/$name";
    if (is_file($path) && hash_file('sha256', $path) === hash('sha256', $data)) continue;
    put($path, $data);
    $changed++;
}

$app = is_file("$target/app.json") ? json_decode(file_get_contents("$target/app.json"), true) : null;
if ($app && isset($app['file']) && preg_match('/^TGuard-Setup-[0-9.]+\.exe$/', $app['file'])) {
    $exe = "$target/{$app['file']}";
    if (!is_file($exe) || hash_file('sha256', $exe) !== strtolower($app['sha256'])) {
        $data = fetch($source . $app['file']);
        if ($data !== null && hash('sha256', $data) === strtolower($app['sha256'])) {
            put($exe, $data);
            $changed++;
        }
    }
    foreach (glob("$target/TGuard-Setup-*.exe") as $old) {
        if (basename($old) !== $app['file']) unlink($old);
    }
}

echo date('c') . " sync done, $changed file(s) updated\n";
