<?php
$app = @json_decode(@file_get_contents(__DIR__ . '/updates/app.json'), true);
$version = $app['version'] ?? null;
$file = $app['file'] ?? null;
$size = isset($app['size']) ? number_format($app['size'] / 1048576, 1, ',', '') . ' MB' : '';
?><!doctype html>
<html lang="pt-PT">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TGuard — antivírus gratuito</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Bagel+Fat+One&family=Outfit:wght@400;600;800&display=swap" rel="stylesheet">
<style>
  :root { --navy:#131A52; --royal:#2339D6; --sun:#FCD34D; --cream:#E9DCC0; --ink:#0F172A; --muted:#5B6478; }
  * { box-sizing: border-box; }
  body { margin:0; font-family:Outfit, system-ui, sans-serif; background:var(--cream); color:var(--ink); }
  main { max-width:880px; margin:0 auto; padding:72px 24px 48px; }
  h1 { font-family:'Bagel Fat One', sans-serif; color:var(--royal); font-size:clamp(48px, 9vw, 84px); margin:0; line-height:1; }
  .bar { width:180px; height:10px; border-radius:6px; background:var(--sun); margin:10px 0 26px; }
  p.lead { font-size:20px; max-width:620px; line-height:1.5; margin:0 0 32px; }
  .btn { display:inline-block; background:var(--sun); color:var(--navy); border:2px solid var(--royal); border-radius:999px;
         padding:14px 30px; font-weight:800; font-size:18px; text-decoration:none; }
  .btn:hover { background:#fde68a; }
  .meta { color:var(--muted); margin-top:12px; font-size:14px; }
  .grid { display:grid; grid-template-columns:repeat(auto-fit, minmax(240px, 1fr)); gap:16px; margin-top:56px; }
  .card { background:#fff; border:2px solid var(--royal); border-radius:20px; padding:20px; }
  .card h3 { margin:0 0 6px; color:var(--navy); }
  .card p { margin:0; color:var(--muted); line-height:1.45; }
  footer { margin-top:56px; color:var(--muted); font-size:14px; }
  footer a { color:var(--royal); }
</style>
</head>
<body>
<main>
  <h1>TGUARD</h1>
  <div class="bar"></div>
  <p class="lead">Antivírus gratuito e open-source para Windows, feito em Portugal. Trabalha em conjunto com o Microsoft Defender contra burlas, phishing, anexos maliciosos e ransomware.</p>
  <?php if ($file): ?>
    <a class="btn" href="updates/<?= htmlspecialchars($file) ?>">Descarregar para Windows</a>
    <div class="meta">Versão <?= htmlspecialchars($version) ?> · <?= $size ?> · Windows 10 e 11 (64 bits)</div>
  <?php else: ?>
    <p class="meta">A primeira versão estará disponível em breve.</p>
  <?php endif; ?>

  <div class="grid">
    <div class="card"><h3>Tempo real</h3><p>Analisa cada ficheiro novo e bloqueia programas maliciosos quando arrancam.</p></div>
    <div class="card"><h3>Burlas portuguesas</h3><p>Deteta imitações de MB WAY, CTT, Finanças e bancos portugueses.</p></div>
    <div class="card"><h3>Pens USB</h3><p>Analisa pens e discos externos assim que são ligados.</p></div>
    <div class="card"><h3>Sempre atualizado</h3><p>Novas assinaturas de hora a hora e atualizações automáticas e assinadas.</p></div>
  </div>

  <footer>
    O instalador ainda não tem certificado: se o Windows avisar, clica em "Mais informações" → "Executar mesmo assim".<br>
    Código-fonte no <a href="https://github.com/Tavaress21/tguard">GitHub</a> · <a href="https://luis-tavares.pt">luis-tavares.pt</a>
  </footer>
</main>
</body>
</html>
