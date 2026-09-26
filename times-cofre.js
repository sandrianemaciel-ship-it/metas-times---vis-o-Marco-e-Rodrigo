/* =====================================================================
   TIMES & METAS — dados protegidos por senha
   Os números ficam no arquivo dados.enc.json CRIPTOGRAFADOS (AES-256-GCM).
   Sem a senha, o arquivo é ilegível. A senha nunca fica no repositório.
   ===================================================================== */
(function () {
  "use strict";
  var ARQUIVO = "dados.enc.json";
  var CHAVE_LEMBRAR = "timesMetasSenha";
  var senhaAtual = null;

  function el(id) { return document.getElementById(id); }
  function b64(s) { return Uint8Array.from(atob(s), function (c) { return c.charCodeAt(0); }); }

  function telaSenha(msgErro) {
    el("timesContent").innerHTML =
      '<div style="max-width:380px;margin:70px auto;background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:26px 24px">' +
      '<div style="font-family:Fraunces,serif;font-size:20px;font-weight:700;margin-bottom:4px">🔒 Acesso restrito</div>' +
      '<div style="font-size:12.5px;color:var(--ink-3);margin-bottom:16px">Digite a senha do painel para ver os números.</div>' +
      '<form id="formSenha">' +
      '<input id="campoSenha" type="password" autocomplete="current-password" placeholder="Senha" ' +
      'style="width:100%;padding:10px 12px;border-radius:8px;border:1px solid var(--border-strong);background:var(--bg-2);color:var(--ink);font-size:14px">' +
      '<label style="display:flex;gap:8px;align-items:center;font-size:12px;color:var(--ink-2);margin:12px 0 16px">' +
      '<input id="lembrar" type="checkbox"> Lembrar neste computador</label>' +
      '<button class="pill active" style="width:100%;padding:10px;font-size:13px" type="submit">Entrar</button>' +
      (msgErro ? '<div style="color:var(--crimson);font-size:12px;margin-top:12px">' + msgErro + "</div>" : "") +
      "</form></div>";
    el("formSenha").onsubmit = function (ev) {
      ev.preventDefault();
      var s = el("campoSenha").value;
      if (el("lembrar").checked) { try { localStorage.setItem(CHAVE_LEMBRAR, s); } catch (e) {} }
      abrir(s);
    };
    setTimeout(function () { var c = el("campoSenha"); if (c) c.focus(); }, 50);
  }

  async function decifrar(pacote, senha) {
    var enc = new TextEncoder();
    var base = await crypto.subtle.importKey("raw", enc.encode(senha), "PBKDF2", false, ["deriveKey"]);
    var chave = await crypto.subtle.deriveKey(
      { name: "PBKDF2", salt: b64(pacote.salt), iterations: pacote.iter, hash: "SHA-256" },
      base, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
    var claro = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64(pacote.iv) }, chave, b64(pacote.dados));
    return JSON.parse(new TextDecoder().decode(claro));
  }

  async function abrir(senha, silencioso) {
    if (!silencioso) el("timesContent").innerHTML =
      '<div style="padding:60px 0;text-align:center;color:var(--ink-2)">Abrindo…</div>';
    var pacote;
    try {
      var r = await fetch(ARQUIVO + "?t=" + Date.now(), { cache: "no-store" });
      if (!r.ok) throw new Error("HTTP " + r.status);
      pacote = await r.json();
    } catch (e) {
      el("timesContent").innerHTML = '<div style="padding:60px 0;text-align:center;color:var(--ink-2)">' +
        "Os dados ainda não foram publicados (" + ARQUIVO + " não encontrado).</div>";
      return;
    }
    var dados;
    try {
      dados = await decifrar(pacote, senha);
    } catch (e) {
      try { localStorage.removeItem(CHAVE_LEMBRAR); } catch (x) {}
      senhaAtual = null;
      telaSenha("Senha incorreta.");
      return;
    }
    senhaAtual = senha;
    METAS = dados.metas;
    Object.keys(METAS).forEach(function (k) {
      if (!MES_NOMES[k]) {
        var p = k.split("-"), nomes = ["Janeiro", "Fevereiro", "Março", "Abril", "Maio", "Junho", "Julho",
          "Agosto", "Setembro", "Outubro", "Novembro", "Dezembro"];
        MES_NOMES[k] = nomes[+p[1] - 1] + " " + p[0];
      }
    });
    if (!MES_SELECIONADO || !METAS[MES_SELECIONADO]) MES_SELECIONADO = Object.keys(METAS).sort().pop();
    el("subtitulo").textContent = "Painel comercial · Previsto × Realizado · atualizado em " + dados.atualizado;
    window.trocarAba(ABA_ATIVA);
  }

  // antes da senha, os botões de aba não fazem nada
  var trocarOriginal = window.trocarAba;
  window.trocarAba = function (aba) { if (Object.keys(METAS).length) trocarOriginal(aba); };

  var salva = null;
  try { salva = localStorage.getItem(CHAVE_LEMBRAR); } catch (e) {}
  if (salva) abrir(salva); else telaSenha();

  // com a página aberta, busca a versão mais nova a cada 15 minutos
  setInterval(function () { if (senhaAtual) abrir(senhaAtual, true); }, 15 * 60 * 1000);
})();
