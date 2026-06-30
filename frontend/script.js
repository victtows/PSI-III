const WEBHOOK_URL = "http://localhost:5678/webhook-test/webguard-ia";

const dominioInput = document.getElementById("dominio");
const btnAnalisar = document.getElementById("btnAnalisar");
const loading = document.getElementById("loading");
const resultado = document.getElementById("resultado");

const resultadoDominio = document.getElementById("resultadoDominio");
const resultadoSSL = document.getElementById("resultadoSSL");
const resultadoCertificado = document.getElementById("resultadoCertificado");
const resultadoHeaders = document.getElementById("resultadoHeaders");
const resultadoResumo = document.getElementById("resultadoResumo");
const listaRecomendacoes = document.getElementById("listaRecomendacoes");
const riscoBadge = document.getElementById("riscoBadge");
const scoreTexto = document.getElementById("scoreTexto");
const scoreFill = document.getElementById("scoreFill");
const summarySSL = document.getElementById("summarySSL");
const summaryRisk = document.getElementById("summaryRisk");
const summaryDate = document.getElementById("summaryDate");
const criteriaList = document.getElementById("criteriaList");
const criteriaTotal = document.getElementById("criteriaTotal");
const repairList = document.getElementById("repairList");
const btnAnaliseCompleta = document.getElementById("btnAnaliseCompleta");
const analiseCompletaBox = document.getElementById("analiseCompletaBox");
const resultadoAnaliseCompleta = document.getElementById("resultadoAnaliseCompleta");
const sslValue = document.getElementById("sslValue");
const headersValue = document.getElementById("headersValue");
const certValue = document.getElementById("certValue");
const geralValue = document.getElementById("geralValue");

const sslBar = document.getElementById("sslBar");
const headersBar = document.getElementById("headersBar");
const certBar = document.getElementById("certBar");
const geralBar = document.getElementById("geralBar");
const btnFecharAnalise = document.getElementById("btnFecharAnalise");
const endpointsResumoTexto = document.getElementById("endpointsResumoTexto");
const btnEndpoints = document.getElementById("btnEndpoints");
const endpointsBox = document.getElementById("endpointsBox");
const endpointsTableBody = document.getElementById("endpointsTableBody");
const certificadoTecnico = document.getElementById("certificadoTecnico");
const protocolosTecnicos = document.getElementById("protocolosTecnicos");
const vulnerabilidadesTecnicas = document.getElementById("vulnerabilidadesTecnicas");

const cipherTecnico=document.getElementById("cipherTecnico");
const recursosTecnicos=document.getElementById("recursosTecnicos");
const gruposTecnicos=document.getElementById("gruposTecnicos");

btnAnalisar.addEventListener("click", analisarServidor);

async function analisarServidor() {
  try {
    loading.classList.remove("hidden");
    resultado.classList.add("hidden");

    const dominio = dominioInput.value.trim();

    const response = await fetch(WEBHOOK_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ dominio })
    });

    const texto = await response.text();

    if (!texto) {
      throw new Error("O n8n respondeu vazio. Verifique o Respond to Webhook.");
    }

    const dados = JSON.parse(texto);

    exibirResultado(dados);

  } catch (erro) {
    console.error(erro);
    alert(
      "Erro ao realizar análise. Verifique se o workflow do n8n está em execução.\n" +
      erro.message
    );
  } finally {
    loading.classList.add("hidden");
  }
}

function iniciarLoading() {
  loading.classList.remove("hidden");
  resultado.classList.add("hidden");
  btnAnalisar.disabled = true;
  btnAnalisar.textContent = "Analisando...";
}

function finalizarLoading() {
  loading.classList.add("hidden");
  btnAnalisar.disabled = false;
  btnAnalisar.textContent = "Analisar Servidor";
}

function definirCorRisco(risco) {
  const r = risco.toLowerCase();

  riscoBadge.style.color = "#fff";

  if (r.includes("baixo")) {
    riscoBadge.style.background = "#10B981";
  } else if (r.includes("médio") || r.includes("medio")) {
    riscoBadge.style.background = "#F59E0B";
  } else if (r.includes("alto")) {
    riscoBadge.style.background = "#EF4444";
  } else if (r.includes("crítico") || r.includes("critico")) {
    riscoBadge.style.background = "#7F1D1D";
  } else {
    riscoBadge.style.background = "#64748B";
  }
}

const btnRelatorio = document.getElementById("btnRelatorio");

let ultimoResultado = null;
let scoreChart = null;
let maturityChart = null;

btnRelatorio.addEventListener("click", gerarRelatorioPDF);

function exibirResultado(dados) {
  renderizarCriterios(dados.criterios || [], dados.score || 0);
  renderizarPlanoCorrecao(dados.planoCorrecao || []);
  renderizarMaturidade(dados.maturidade || {});

  ultimoResultado = dados;

  resultado.classList.remove("hidden");

  resultadoDominio.textContent = dados.dominio || dados.host || "Não informado";

  resultadoSSL.textContent =
    `Nota: ${dados.nota_ssl || "N/A"} | Status: ${dados.ssl_status || "N/A"}`;

  resultadoCertificado.textContent =
    dados.certificado || "Certificado avaliado";

  resultadoHeaders.innerHTML =
    dados.headersResumo || "Security Headers avaliados pela IA";

  resultadoResumo.textContent =
    dados.mensagem || "Análise realizada com sucesso pelo WebGuard IA.";

    resultadoAnaliseCompleta.innerHTML =
    formatarAnaliseCompletaHTML(
      dados.analiseCompleta ||
      dados.mensagem ||
      "Análise completa indisponível."
    );

  listaRecomendacoes.innerHTML = "";

  const recomendacoes = dados.recomendacoes || [];

  recomendacoes.forEach((item) => {
    const li = document.createElement("li");
    li.textContent = item;
    listaRecomendacoes.appendChild(li);
  });

  const risco = dados.risco || "Médio";
  riscoBadge.textContent = `Risco ${risco.toUpperCase()}`;
  definirCorRisco(risco);
  atualizarScore(dados.nota_ssl, risco);
  summarySSL.textContent = dados.nota_ssl || "N/A";
  summaryRisk.textContent = risco.toUpperCase();
  summaryDate.textContent = dados.dataAnalise || new Date().toLocaleString("pt-BR");
  atualizarScoreChart(dados.score || 0);
  atualizarMaturityChart(dados.maturidade || {});
  renderizarEndpoints(dados.endpointsResumo || {});
  renderizarDetalhesTecnicos(dados);
}

function gerarRelatorioPDF() {
  if (!ultimoResultado) {
    alert("Execute uma análise antes de gerar o relatório.");
    return;
  }

  const { jsPDF } = window.jspdf;
  const doc = new jsPDF("p", "mm", "a4");

  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();

  let pageNumber = 1;
  let y = 20;

  const margem = 18;
  const azulEscuro = [15, 23, 42];
  const azul = [37, 99, 235];
  const cinza = [100, 116, 139];
  const cinzaClaro = [248, 250, 252];

  function header(titulo = "Relatório Técnico de Auditoria SSL/TLS") {
    doc.setFillColor(...azulEscuro);
    doc.rect(0, 0, pageWidth, 22, "F");

    doc.setTextColor(255, 255, 255);
    doc.setFontSize(12);
    doc.setFont("helvetica", "bold");
    doc.text("WEBGUARD IA", margem, 14);

    doc.setFontSize(9);
    doc.setFont("helvetica", "normal");
    doc.text(titulo, pageWidth - margem, 14, { align: "right" });

    doc.setTextColor(0, 0, 0);
    y = 34;
  }

  function textoAnaliseFormatada(texto) {
    const linhas = String(texto || "Análise técnica completa indisponível.").split("\n");
  
    linhas.forEach((linha) => {
      const limpa = linha.trim();
  
      if (!limpa) {
        y += 3;
        return;
      }
  
      if (y > 270) novaPagina("Análise Técnica Completa");
  
      if (/^\d+\.\s/.test(limpa)) {
        doc.setFont("helvetica", "bold");
        doc.setFontSize(12);
        doc.setTextColor(...azulEscuro);
        doc.text(limpa, margem, y);
        y += 8;
      } else {
        doc.setFont("helvetica", "normal");
        doc.setFontSize(10);
        doc.setTextColor(30, 41, 59);
  
        const linhasTexto = doc.splitTextToSize(limpa, pageWidth - margem * 2);
        doc.text(linhasTexto, margem, y);
        y += linhasTexto.length * 5 + 2;
      }
    });
  
    y += 4;
  }
  
  function adicionarGraficoCanvas(titulo, canvasId, legenda = []) {
    const canvas = document.getElementById(canvasId);
  
    if (!canvas) return;
  
    novaPagina(titulo);
    tituloSecao(titulo);
  
    const img = canvas.toDataURL("image/png", 1.0);
  
    const largura = 90;
    const altura = 70;
    const x = (pageWidth - largura) / 2;
  
    doc.addImage(img, "PNG", x, y, largura, altura);
    y += altura + 12;
  
    if (legenda.length) {
      doc.setFontSize(10);
      doc.setFont("helvetica", "bold");
      doc.setTextColor(...azulEscuro);
      doc.text("Legenda", margem, y);
      y += 8;
  
      doc.setFont("helvetica", "normal");
      doc.setFontSize(9);
  
      legenda.forEach(item => {
        doc.setTextColor(30, 41, 59);
        doc.text(`• ${item}`, margem, y);
        y += 6;
      });
    }
  }

  function footer() {
    doc.setDrawColor(226, 232, 240);
    doc.line(margem, pageHeight - 15, pageWidth - margem, pageHeight - 15);

    doc.setFontSize(8);
    doc.setTextColor(...cinza);
    doc.text("WebGuard IA • Relatório Técnico de Auditoria SSL/TLS", margem, pageHeight - 8);
    doc.text(`Página ${pageNumber}`, pageWidth - margem, pageHeight - 8, { align: "right" });
    doc.setTextColor(0, 0, 0);
  }

  function novaPagina(titulo) {
    footer();
    doc.addPage();
    pageNumber++;
    header(titulo);
  }

  function tituloSecao(texto) {
    if (y > 260) novaPagina("Relatório Técnico de Auditoria SSL/TLS");

    doc.setFontSize(14);
    doc.setFont("helvetica", "bold");
    doc.setTextColor(...azulEscuro);
    doc.text(texto, margem, y);
    y += 8;

    doc.setDrawColor(...azul);
    doc.line(margem, y, pageWidth - margem, y);
    y += 8;
  }

  function textoLongo(texto) {
    const linhas = doc.splitTextToSize(texto || "Não informado.", pageWidth - margem * 2);

    linhas.forEach((linha) => {
      if (y > 270) novaPagina("Relatório Técnico de Auditoria SSL/TLS");
      doc.setFontSize(10);
      doc.setFont("helvetica", "normal");
      doc.setTextColor(30, 41, 59);
      doc.text(linha, margem, y);
      y += 5;
    });

    y += 4;
  }

  function tabelaSimples(headers, rows) {
    const colunas = headers.length;
    const largura = (pageWidth - margem * 2) / colunas;

    if (y > 260) novaPagina("Relatório Técnico de Auditoria SSL/TLS");

    doc.setFillColor(...azulEscuro);
    doc.rect(margem, y, pageWidth - margem * 2, 8, "F");

    doc.setTextColor(255, 255, 255);
    doc.setFontSize(8);
    doc.setFont("helvetica", "bold");

    headers.forEach((h, i) => {
      doc.text(String(h), margem + i * largura + 2, y + 5);
    });

    y += 8;

    rows.forEach((row, index) => {
      if (y > 270) {
        novaPagina("Relatório Técnico de Auditoria SSL/TLS");
      }

      if (index % 2 === 0) {
        doc.setFillColor(...cinzaClaro);
        doc.rect(margem, y, pageWidth - margem * 2, 8, "F");
      }

      doc.setTextColor(30, 41, 59);
      doc.setFontSize(8);
      doc.setFont("helvetica", "normal");

      row.forEach((cell, i) => {
        const texto = doc.splitTextToSize(String(cell ?? "-"), largura - 4);
        doc.text(texto.slice(0, 2), margem + i * largura + 2, y + 5);
      });

      y += 8;
    });

    y += 8;
  }

  function cardLinha(label, valor, x, yy, w, h) {
    doc.setFillColor(...cinzaClaro);
    doc.roundedRect(x, yy, w, h, 3, 3, "F");

    doc.setTextColor(...cinza);
    doc.setFontSize(8);
    doc.setFont("helvetica", "bold");
    doc.text(label, x + 4, yy + 7);

    doc.setTextColor(...azulEscuro);
    doc.setFontSize(13);
    doc.setFont("helvetica", "bold");
    doc.text(String(valor || "-"), x + 4, yy + 16);
  }

  const r = ultimoResultado;
  const data = r.dataAnalise || new Date().toLocaleString("pt-BR");
  const score = r.score ?? 0;
  const risco = r.risco || "N/A";

  // CAPA
  doc.setFillColor(...azulEscuro);
  doc.rect(0, 0, pageWidth, pageHeight, "F");

  doc.setTextColor(255, 255, 255);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(28);
  doc.text("WEBGUARD IA", pageWidth / 2, 70, { align: "center" });

  doc.setFontSize(13);
  doc.setFont("helvetica", "normal");
  doc.text("Sistema Inteligente de Auditoria SSL/TLS", pageWidth / 2, 82, { align: "center" });

  doc.setDrawColor(37, 99, 235);
  doc.line(50, 95, pageWidth - 50, 95);

  doc.setFontSize(18);
  doc.setFont("helvetica", "bold");
  doc.text("Relatório Técnico de Segurança", pageWidth / 2, 112, { align: "center" });

  doc.setFontSize(11);
  doc.setFont("helvetica", "normal");
  doc.text(`Domínio: ${r.host || "Não informado"}`, pageWidth / 2, 135, { align: "center" });
  doc.text(`Data: ${data}`, pageWidth / 2, 145, { align: "center" });
  doc.text(`Score: ${score}/100`, pageWidth / 2, 155, { align: "center" });
  doc.text(`Risco: ${risco}`, pageWidth / 2, 165, { align: "center" });
  doc.text(`Nota SSL Labs: ${r.nota_ssl || "N/A"}`, pageWidth / 2, 175, { align: "center" });

  doc.setFontSize(9);
  doc.text("Versão 1.0 • Gerado automaticamente", pageWidth / 2, 270, { align: "center" });

  doc.addPage();
  pageNumber++;
  header();

  // RESUMO EXECUTIVO
  tituloSecao("1. Resumo Executivo");

  cardLinha("Domínio", r.host || "-", margem, y, 40, 24);
  cardLinha("Nota SSL", r.nota_ssl || "-", margem + 45, y, 35, 24);
  cardLinha("Score", `${score}/100`, margem + 85, y, 35, 24);
  cardLinha("Risco", risco, margem + 125, y, 50, 24);
  y += 34;

  textoLongo(r.mensagem || "Resumo executivo não disponível.");

  // CRITÉRIOS
  tituloSecao("2. Critérios Avaliados");

  tabelaSimples(
    ["Critério", "Status", "Pontos", "Impacto"],
    (r.criterios || []).map(item => [
      item.nome,
      item.status ? "Aprovado" : "Ausente",
      `${item.pontos}/${item.maximo}`,
      item.impacto || "-"
    ])
  );

  // PLANO
  tituloSecao("3. Plano de Correção");

  const plano = r.planoCorrecao || [];

  if (plano.length === 0) {
    textoLongo("Nenhuma correção necessária.");
  } else {
    tabelaSimples(
      ["Prioridade", "Problema", "Impacto", "Ganho"],
      plano.map(item => [
        item.prioridade || "-",
        item.problema || "-",
        item.impacto || "-",
        item.ganhoEsperado || "-"
      ])
    );
  }

  // MATURIDADE
  tituloSecao("4. Índice de Maturidade");

  const m = r.maturidade || {};

  tabelaSimples(
    ["Indicador", "Resultado"],
    [
      ["SSL/TLS", `${m.sslTls ?? 0}%`],
      ["Security Headers", `${m.headers ?? 0}%`],
      ["Certificado", `${m.certificado ?? 0}%`],
      ["Proteção Geral", `${m.protecaoGeral ?? 0}%`]
    ]
  );

  adicionarGraficoCanvas("Gráfico do Score", "scoreChart", [
    "Verde: risco baixo ou pontuação satisfatória.",
    "Amarelo: risco médio ou atenção necessária.",
    "Vermelho: risco alto/crítico ou pontuação insuficiente."
  ]);
  
  adicionarGraficoCanvas("Gráfico de Maturidade", "maturityDonut", [
    "SSL/TLS: qualidade da configuração criptográfica.",
    "Headers: presença dos cabeçalhos de segurança.",
    "Certificado: validade e confiança da cadeia de certificados.",
    "Proteção Geral: resultado consolidado da auditoria."
  ]);

  // ENDPOINTS
  novaPagina("Servidores Analisados");

  tituloSecao("5. Servidores / Endpoints");

  const endpoints = r.endpointsResumo?.lista || [];

  if (endpoints.length === 0) {
    textoLongo("Nenhum endpoint retornado pela análise.");
  } else {
    tabelaSimples(
      ["#", "IP", "Servidor", "Status", "Nota"],
      endpoints.map(ep => [
        ep.numero,
        ep.ip,
        ep.servidor,
        ep.status,
        ep.grade
      ])
    );
  }

  // DETALHES TÉCNICOS
  novaPagina("Detalhes Técnicos SSL/TLS");

  tituloSecao("6. Detalhes Técnicos");

  const ssl = r.sslLabsTecnico || {};

  tabelaSimples(
    ["Certificado", "Valor"],
    [
      ["Status", ssl.certificado?.confiavel || "-"],
      ["Cadeias", ssl.certificado?.cadeias ?? "-"],
      ["Problemas", ssl.certificado?.problemas || "-"],
      ["Algoritmo", ssl.certificado?.algoritmoChave || "-"],
      ["Tamanho da chave", ssl.certificado?.tamanhoChave || "-"],
      ["Assinatura", ssl.certificado?.assinatura || "-"]
    ]
  );

  tabelaSimples(
    ["Protocolo", "Status"],
    (ssl.protocolos || []).map(p => [
      `${p.nome || ""} ${p.versao || ""}`,
      p.status || "-"
    ])
  );

  tabelaSimples(
    ["Cipher Suites", "Valor"],
    [
      ["Total", ssl.cipherSuites?.total ?? "-"],
      ["Legadas", ssl.cipherSuites?.legadas ?? "-"],
      ["AEAD", ssl.cipherSuites?.suportaAead || "-"],
      ["ChaCha20", ssl.cipherSuites?.preferenciaChaCha20 || "-"]
    ]
  );

  tabelaSimples(
    ["Recurso", "Status"],
    [
      ["Forward Secrecy", ssl.recursos?.forwardSecrecy || "-"],
      ["ALPN", ssl.recursos?.alpn || "-"],
      ["OCSP Stapling", ssl.recursos?.ocspStapling || "-"],
      ["RC4", ssl.recursos?.rc4 || "-"],
      ["Compressão TLS", ssl.recursos?.compressaoTLS || "-"],
      ["HTTP Status", ssl.recursos?.httpStatus || "-"]
    ]
  );

  tabelaSimples(
    ["Grupo Criptográfico", "Bits", "Tipo"],
    (ssl.gruposCriptograficos || []).map(g => [
      g.nome || "-",
      g.bits || "-",
      g.tipo || "-"
    ])
  );

  // ANÁLISE COMPLETA
  novaPagina("Análise Técnica Completa");

  tituloSecao("7. Análise Técnica Completa");

  textoAnaliseFormatada(r.analiseCompleta || "Análise técnica completa indisponível.");

  // RECOMENDAÇÕES
novaPagina("Recomendações");

tituloSecao("8. Recomendações");

(r.recomendacoes || []).forEach((rec, index) => {
  textoLongo(`${index + 1}. ${rec}`);
});

  // METADADOS
  novaPagina("Metadados da Auditoria");

  tituloSecao("9. Metadados");

  tabelaSimples(
    ["Campo", "Valor"],
    [
      ["Host", r.host || "-"],
      ["Status SSL Labs", r.ssl_status || "-"],
      ["Nota SSL", r.nota_ssl || "-"],
      ["Data da análise", data],
      ["Endpoints encontrados", r.endpointsResumo?.total ?? "-"],
      ["Tecnologias", "n8n, SSL Labs API, Security Headers API, Google Gemini, JavaScript, jsPDF"],
      ["Versão WebGuard IA", "1.0"]
    ]
  );

  footer();

  doc.save(`relatorio-webguard-${r.host || "servidor"}.pdf`);
}

function calcularScore(notaSSL, risco) {
    let score = 70;
  
    const nota = (notaSSL || "").toUpperCase();
  
    if (nota === "A+") score = 100;
    else if (nota === "A") score = 95;
    else if (nota === "B") score = 80;
    else if (nota === "C") score = 60;
    else if (nota === "D") score = 40;
    else if (nota === "E" || nota === "F") score = 20;
  
    const r = (risco || "").toLowerCase();
  
    if (r.includes("baixo")) score += 5;
    if (r.includes("médio") || r.includes("medio")) score -= 5;
    if (r.includes("alto")) score -= 15;
    if (r.includes("crítico") || r.includes("critico")) score -= 30;
  
    return Math.max(0, Math.min(100, score));
  }
  
  function atualizarScore(notaSSL, risco) {
    const score = ultimoResultado?.score ?? calcularScore(notaSSL, risco);
  
    scoreTexto.textContent = `${score}/100`;
    scoreFill.style.width = `${score}%`;
  
    if (score >= 85) {
      scoreFill.style.background = "#10B981";
    } else if (score >= 60) {
      scoreFill.style.background = "#F59E0B";
    } else {
      scoreFill.style.background = "#EF4444";
    }
  }

  function renderizarCriterios(criterios, score) {
    criteriaList.innerHTML = "";
    criteriaTotal.textContent = `${score}/100`;
    
  
    criterios.forEach((item) => {
      const div = document.createElement("div");
      div.className = "criteria-item";
  
      div.innerHTML = `
        <span class="criteria-name">${item.nome}</span>
        <span class="criteria-status ${item.status ? "ok" : "fail"}">
          ${item.status ? "Aprovado" : "Ausente"}
        </span>
        <span class="criteria-points">+${item.pontos}/${item.maximo}</span>
      `;
  
      criteriaList.appendChild(div);
    });
  }

  function renderizarPlanoCorrecao(plano){

    repairList.innerHTML = "";

    if(plano.length === 0){

        repairList.innerHTML = `
            <div class="repair-item">
                <span style="color:#16A34A;font-weight:bold;">
                    Nenhuma correção necessária.
                </span>
            </div>
        `;

        return;
    }

    plano.forEach(item=>{

        let classe="baixa";

        if(item.prioridade==="Alta"){
            classe="alta";
        }

        if(item.prioridade==="Média"){
            classe="media";
        }

        repairList.innerHTML += `
            <div class="repair-item">

                <div class="repair-priority ${classe}">
                    ${item.prioridade}
                </div>

                <div class="repair-problem">
                    ${item.problema}
                </div>

                <div class="repair-points">
                    ${item.ganhoEsperado}
                </div>

            </div>
        `;

    });

}

btnAnaliseCompleta.addEventListener("click", () => {
  analiseCompletaBox.classList.remove("hidden");
});

analiseCompletaBox.addEventListener("click", (e) => {
  if (e.target === analiseCompletaBox) {
      analiseCompletaBox.classList.add("hidden");
  }
});

function atualizarBarra(barra, texto, valor){
  valor = valor || 0;

  texto.textContent = `${valor}%`;
  barra.style.width = `${valor}%`;

  if(valor >= 80){
      barra.style.background = "#10B981";
  } else if(valor >= 50){
      barra.style.background = "#F59E0B";
  } else {
      barra.style.background = "#EF4444";
  }
}

function renderizarMaturidade(maturidade){
  atualizarBarra(sslBar, sslValue, maturidade.sslTls || 0);
  atualizarBarra(headersBar, headersValue, maturidade.headers || 0);
  atualizarBarra(certBar, certValue, maturidade.certificado || 0);
  atualizarBarra(geralBar, geralValue, maturidade.protecaoGeral || 0);
}

btnFecharAnalise.addEventListener("click", () => {
  analiseCompletaBox.classList.add("hidden");
  btnAnaliseCompleta.textContent = "Ver análise técnica completa";
});

function atualizarScoreChart(score){

  if(scoreChart){
      scoreChart.destroy();
  }

  const cor =
      score >= 80 ? "#10B981" :
      score >= 50 ? "#F59E0B" :
      "#EF4444";

  document.getElementById("scoreCenter").textContent = score;
  const status =
    score >= 80 ? "Excelente" :
    score >= 50 ? "Moderado" :
    "Crítico";

  document.getElementById("scoreStatus").textContent = status;

  scoreChart = new Chart(

      document.getElementById("scoreChart"),

      {

          type:"doughnut",

          data:{

              datasets:[{

                  data:[score,100-score],

                  backgroundColor:[
                      cor,
                      "#E5E7EB"
                  ],

                  borderWidth:0

              }]

          },

          options:{

              responsive:true,

              cutout:"82%",

              plugins:{
                  legend:{
                      display:false
                  },
                  tooltip:{
                      enabled:false
                  }
              }

          }

      }

  );

}

function atualizarMaturityChart(m){

  if(maturityChart){
      maturityChart.destroy();
  }

  maturityChart = new Chart(

      document.getElementById("maturityDonut"),

      {

          type:"doughnut",

          data:{

              labels:[
                  "SSL/TLS",
                  "Headers",
                  "Certificado",
                  "Proteção"
              ],

              datasets:[{

                  data:[
                      m.sslTls || 0,
                      m.headers || 0,
                      m.certificado || 0,
                      m.protecaoGeral || 0
                  ],

                  backgroundColor:[

                      "#2563EB",

                      "#EF4444",

                      "#10B981",

                      "#F59E0B"

                  ],

                  borderWidth:0

              }]

          },

          options:{

              responsive:true,

              plugins:{

                  legend:{
                      position:"bottom"
                  }

              }

          }

      }

  );

}

function renderizarEndpoints(endpointsResumo) {
  const total = endpointsResumo.total || 0;
  const grades = endpointsResumo.grades || {};
  const lista = endpointsResumo.lista || [];

  const gradesTexto = Object.entries(grades)
    .map(([grade, quantidade]) => `${grade}: ${quantidade}`)
    .join(" | ");

  endpointsResumoTexto.textContent =
    total > 0
      ? `${total} endpoint(s) analisado(s) • ${gradesTexto}`
      : "Nenhum endpoint retornado pela análise.";

  endpointsTableBody.innerHTML = "";

  lista.forEach((item) => {
    const tr = document.createElement("tr");

    tr.innerHTML = `
      <td>${item.numero}</td>
      <td>${item.ip}</td>
      <td>${item.servidor}</td>
      <td>${item.status}</td>
      <td><strong>${item.grade}</strong></td>
    `;

    endpointsTableBody.appendChild(tr);
  });

  endpointsBox.classList.add("hidden");
  btnEndpoints.textContent = "Ver endpoints";
}

btnEndpoints.addEventListener("click", () => {
  endpointsBox.classList.toggle("hidden");

  btnEndpoints.textContent = endpointsBox.classList.contains("hidden")
    ? "Ver endpoints"
    : "Ocultar endpoints";
});

function renderizarDetalhesTecnicos(dados) {
  const ssl = dados.sslLabsTecnico || {};
  const protocolos = ssl.protocolos || [];

  certificadoTecnico.innerHTML = `
    <strong>Status:</strong> ${ssl.certificado?.confiavel || "-"}<br>
    <strong>Cadeias:</strong> ${ssl.certificado?.cadeias || 0}<br>
    <strong>Problemas:</strong> ${ssl.certificado?.problemas || "Nenhum"}<br>
    <strong>Algoritmo:</strong> ${ssl.certificado?.algoritmoChave || "-"}<br>
    <strong>Tamanho da chave:</strong> ${ssl.certificado?.tamanhoChave || "-"}<br>
    <strong>Assinatura:</strong> ${ssl.certificado?.assinatura || "-"}
  `;

  protocolosTecnicos.innerHTML = protocolos.length
    ? protocolos
        .map(p => `<strong>${p.nome} ${p.versao}:</strong> ${p.status}`)
        .join("<br>")
    : "Protocolos não informados.";

  cipherTecnico.innerHTML = `
    <strong>Total:</strong> ${ssl.cipherSuites?.total || 0}<br>
    <strong>Legadas:</strong> ${ssl.cipherSuites?.legadas || 0}<br>
    <strong>AEAD:</strong> ${ssl.cipherSuites?.suportaAead || "-"}<br>
    <strong>ChaCha20:</strong> ${ssl.cipherSuites?.preferenciaChaCha20 || "-"}
  `;

  recursosTecnicos.innerHTML = `
    <strong>Forward Secrecy:</strong> ${ssl.recursos?.forwardSecrecy || "-"}<br>
    <strong>ALPN:</strong> ${ssl.recursos?.alpn || "-"}<br>
    <strong>OCSP Stapling:</strong> ${ssl.recursos?.ocspStapling || "-"}<br>
    <strong>RC4:</strong> ${ssl.recursos?.rc4 || "-"}<br>
    <strong>Compressão TLS:</strong> ${ssl.recursos?.compressaoTLS || "-"}
  `;

  gruposTecnicos.innerHTML = ssl.gruposCriptograficos?.length
    ? ssl.gruposCriptograficos
        .map(g => `• ${g.nome} (${g.bits} bits)`)
        .join("<br>")
    : "Nenhum grupo informado.";
}

document.addEventListener("DOMContentLoaded", () => {
  const btnAccordion = document.getElementById("btnDetalhesTecnicos");
  const conteudoAccordion = document.getElementById("conteudoDetalhes");

  if (!btnAccordion || !conteudoAccordion) return;

  btnAccordion.addEventListener("click", () => {
    conteudoAccordion.classList.toggle("open");

  });
});

function formatarAnaliseCompletaHTML(texto) {
  return String(texto)
    .split("\n")
    .map(linha => {
      const linhaLimpa = linha.trim();

      if (/^\d+\.\s/.test(linhaLimpa)) {
        return `<h4 class="analise-topico">${linhaLimpa}</h4>`;
      }

      if (!linhaLimpa) {
        return "<br>";
      }

      return `<p>${linhaLimpa}</p>`;
    })
    .join("");
}