/* ============================================================
   CIPHER_SYS v5.0 — script.js
   Una sola ruta de cifrado: el alfabeto siempre es explícito.
   Sin alfabeto custom → se usa A-Z por defecto.
   El cifrado opera SOLO sobre los caracteres del alfabeto activo.
   Caracteres fuera del alfabeto se copian intactos.
   ============================================================ */

/* ── Frecuencias del español para scoring (detección automática) ── */
var FREQ_ES = {
    A:12.53,B:1.42,C:4.68,D:5.86,E:13.68,F:0.69,G:1.01,H:0.70,
    I:6.25,J:0.44,K:0.02,L:4.97,M:3.15,N:6.71,O:8.68,P:2.51,
    Q:0.88,R:6.87,S:7.98,T:4.63,U:3.93,V:0.90,W:0.01,X:0.22,
    Y:0.90,Z:0.52
};

var ALPHA_DEFAULT = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

/* ── Sanitizar entrada para prevenir XSS ── */
function sanitizeInput(input) {
    var doc = new DOMParser().parseFromString(input, 'text/html');
    return doc.body.textContent || '';
}

/* ──────────────────────────────────────────────
   OBTENER ALFABETO ACTIVO
   Siempre devuelve una cadena válida:
   - Si el campo está vacío → ALPHA_DEFAULT (A-Z + a-z)
   - Si el campo tiene contenido → esos caracteres sin duplicados
   No hay "null", no hay rutas especiales. Un solo camino.
   ────────────────────────────────────────────── */
function getAlphabet() {
    var raw = document.getElementById('alfabeto').value;

    // Sin contenido → alfabeto por defecto
    if (!raw || raw.trim() === '') return ALPHA_DEFAULT;

    // Eliminar duplicados preservando orden de aparición
    var seen = {}, uniq = '';
    for (var i = 0; i < raw.length; i++) {
        if (!seen[raw[i]]) { seen[raw[i]] = true; uniq += raw[i]; }
    }

    // Mínimo 2 caracteres para que tenga sentido cifrar
    return uniq.length >= 2 ? uniq : ALPHA_DEFAULT;
}

/* ──────────────────────────────────────────────
   CIFRADO CÉSAR
   Desplaza cada carácter según su posición en `alpha`.
   Si el carácter NO está en el alfabeto → se copia tal cual.
   Funciona igual con cualquier alfabeto: letras, números,
   símbolos, emojis, lo que sea.
   ────────────────────────────────────────────── */
function cifradoCesar(texto, desplazamiento, alpha) {
    var n   = alpha.length;
    var out = '';

    for (var i = 0; i < texto.length; i++) {
        var ch  = texto[i];
        var pos = alpha.indexOf(ch);

        if (pos === -1) {
            out += ch;                              // fuera del alfabeto → intacto
        } else {
            out += alpha[((pos + desplazamiento) % n + n) % n];
        }
    }
    return out;
}

/* ──────────────────────────────────────────────
   CIFRADO ATBASH
   Invierte la posición de cada carácter dentro de `alpha`.
   Si el carácter NO está en el alfabeto → se copia tal cual.
   Es simétrico: cifrar == descifrar con el mismo alfabeto.
   ────────────────────────────────────────────── */
function cifradoAtbash(texto, alpha) {
    var n   = alpha.length;
    var out = '';

    for (var i = 0; i < texto.length; i++) {
        var ch  = texto[i];
        var pos = alpha.indexOf(ch);

        if (pos === -1) {
            out += ch;                              // fuera del alfabeto → intacto
        } else {
            out += alpha[n - 1 - pos];
        }
    }
    return out;
}

/* ──────────────────────────────────────────────
   SCORING DE LEGIBILIDAD para auto-detección
   Estrategia dual:
   1. Si el alfabeto contiene letras A-Z → usa chi-cuadrado
      contra las frecuencias del español (método Al-Kindi).
   2. Si el alfabeto es puramente no-alfabético (solo números,
      símbolos, etc.) → usa entropía de distribución de
      caracteres: cuanto más uniforme, más "cifrado"; cuanto
      más concentrado en pocos valores, más "legible".
   ────────────────────────────────────────────── */
function scoreResultado(texto, alpha) {
    // ¿El alfabeto contiene letras? → chi-cuadrado sobre español
    var tieneLetras = /[A-Za-z]/.test(alpha);

    if (tieneLetras) {
        return scoreChi2(texto);
    } else {
        // Alfabeto sin letras: menor varianza en distribución = más legible
        return scoreEntropia(texto, alpha);
    }
}

/* Chi-cuadrado contra frecuencias del español */
function scoreChi2(texto) {
    var conteo = {}, total = 0;
    var up = texto.toUpperCase();
    for (var i = 0; i < up.length; i++) {
        if (/[A-Z]/.test(up[i])) {
            conteo[up[i]] = (conteo[up[i]] || 0) + 1;
            total++;
        }
    }
    if (total === 0) return Infinity;
    var chi2 = 0;
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.split('').forEach(function(c) {
        var obs = ((conteo[c] || 0) / total) * 100;
        chi2 += Math.pow(obs - FREQ_ES[c], 2) / FREQ_ES[c];
    });
    return chi2;
}

/* Entropía de distribución para alfabetos no-alfabéticos */
function scoreEntropia(texto, alpha) {
    var conteo = {}, total = 0;
    for (var i = 0; i < texto.length; i++) {
        if (alpha.indexOf(texto[i]) !== -1) {
            conteo[texto[i]] = (conteo[texto[i]] || 0) + 1;
            total++;
        }
    }
    if (total === 0) return Infinity;
    // Entropía de Shannon: mayor entropía = más "cifrado" = peor score
    var h = 0;
    Object.keys(conteo).forEach(function(c) {
        var p = conteo[c] / total;
        h -= p * Math.log2(p);
    });
    return h; // menor = menos uniforme = más "legible" / predecible
}

/* ──────────────────────────────────────────────
   DETECCIÓN AUTOMÁTICA (Al-Kindi)
   Genera todos los candidatos:
     - César con cada desplazamiento posible (1 a N-1)
     - Atbash
   Los puntúa con el scoring apropiado para el alfabeto
   y devuelve únicamente el ganador.
   ────────────────────────────────────────────── */
function detectarCifrado(texto) {
    var alpha      = getAlphabet();
    var n          = alpha.length;
    var candidatos = [];

    // César: probar todos los desplazamientos posibles
    for (var d = 1; d < n; d++) {
        var intento = cifradoCesar(texto, -d, alpha);
        candidatos.push({
            metodo : 'César Δ' + d,
            texto  : intento,
            score  : scoreResultado(intento, alpha)
        });
    }

    // Atbash
    var atbashIntento = cifradoAtbash(texto, alpha);
    candidatos.push({
        metodo : 'Atbash',
        texto  : atbashIntento,
        score  : scoreResultado(atbashIntento, alpha)
    });

    // Ganador = menor score (más parecido a texto natural)
    candidatos.sort(function(a, b) { return a.score - b.score; });
    return candidatos[0];
}

/* ──────────────────────────────────────────────
   FUNCIÓN PRINCIPAL — cifrar()
   ────────────────────────────────────────────── */
function cifrar() {
    var texto = sanitizeInput(document.getElementById('texto').value);
    var tipo   = document.getElementById('cifrado').value;
    var accion = document.getElementById('accion').value;
    var alpha  = getAlphabet();

    if (texto === '') {
        alert('Por favor, ingresa un texto válido.');
        return;
    }

    /* ── MODO AUTO-DETECTAR ── */
    if (accion === 'auto') {
        var ganador    = detectarCifrado(texto);
        var confianza  = Math.round(100 / (1 + ganador.score));
        var esCustom   = document.getElementById('alfabeto').value.trim() !== '';

        document.getElementById('resultado').innerText = ganador.texto;
        actualizarFooter(
            '✔ DETECTADO: <span style="color:var(--c-cyan)">' + ganador.metodo + '</span>' +
            (esCustom ? ' <span style="color:var(--c-muted)">[alfabeto custom]</span>' : '') +
            ' &nbsp;|&nbsp; confianza: <span style="color:var(--c-green)">' + confianza + '%</span>'
        );
        var badge = document.getElementById('metodo-detectado');
        badge.textContent = '↳ Método: ' + ganador.metodo +
            ' · Alfabeto: ' + alpha.length + ' caracteres' +
            (esCustom ? ' (personalizado)' : ' (estándar)');
        badge.style.display = 'block';
        return;
    }

    /* ── MODOS CIFRAR / DESCIFRAR ── */
    document.getElementById('metodo-detectado').style.display = 'none';

    var desplazamiento = parseInt(document.getElementById('desplazamiento').value);
    if (tipo === 'cesar' && (isNaN(desplazamiento) || desplazamiento <= 0)) {
        alert('Por favor, ingresa un número válido para el desplazamiento.');
        return;
    }

    // Descifrar César = desplazamiento negativo (mismo algoritmo)
    if (accion === 'descifrar' && tipo === 'cesar') desplazamiento = -desplazamiento;

    var resultado = tipo === 'cesar'
        ? cifradoCesar(texto, desplazamiento, alpha)
        : cifradoAtbash(texto, alpha);

    document.getElementById('resultado').innerText = resultado;
    actualizarFooter('✔ PROCESO COMPLETADO · alfabeto: ' + alpha.length + ' caracteres');
}

/* ──────────────────────────────────────────────
   VALIDACIÓN Y VISTA PREVIA DEL ALFABETO
   ────────────────────────────────────────────── */
function validarAlfabeto() {
    var raw  = document.getElementById('alfabeto').value;
    var seen = {}, uniq = '';
    for (var i = 0; i < raw.length; i++) {
        if (!seen[raw[i]]) { seen[raw[i]] = true; uniq += raw[i]; }
    }

    var status = document.getElementById('alpha-status');
    var dupes  = raw.length - uniq.length;

    if (uniq.length === 0) {
        status.innerHTML  = '— Vacío — usando alfabeto estándar (' + ALPHA_DEFAULT.length + ' caracteres: A-Z + a-z)';
        status.className  = 'alpha-status neutral';
        renderAlphaMap(ALPHA_DEFAULT, false);
    } else if (uniq.length < 2) {
        status.innerHTML  = '✘ Mínimo 2 caracteres distintos para poder cifrar';
        status.className  = 'alpha-status err';
        renderAlphaMap('', false);
    } else {
        var dupeMsg = dupes > 0
            ? ' <span style="color:#ff9944">(' + dupes + ' duplicado(s) ignorado(s))</span>'
            : '';
        status.innerHTML = '✔ Alfabeto personalizado activo — <strong>' + uniq.length +
            '</strong> caracteres únicos' + dupeMsg;
        status.className = 'alpha-status ok';
        renderAlphaMap(uniq, true);
    }
}

/* Vista previa posición por posición */
function renderAlphaMap(alpha, isCustom) {
    var map = document.getElementById('alpha-map');
    if (!map) return;
    map.innerHTML = '';

    for (var i = 0; i < alpha.length; i++) {
        var ch        = alpha[i];
        var isSpecial = !/[A-Za-z0-9]/.test(ch);
        var display   = ch === ' ' ? '␣' : ch === '\t' ? '⇥' : ch;

        var cell = document.createElement('div');
        cell.className = 'alpha-cell' +
            (isCustom && isSpecial ? ' alpha-cell--special' : '') +
            (isCustom && !isSpecial ? ' alpha-cell--custom' : '');
        cell.innerHTML =
            '<span class="alpha-cell__idx">' + i + '</span>' +
            '<span class="alpha-cell__to">'  + escHtml(display) + '</span>';
        map.appendChild(cell);
    }
}

/* ── Helpers ── */
function actualizarFooter(msg) {
    var f = document.querySelector('.output__footer');
    if (f) f.innerHTML = msg;
}

function escHtml(s) {
    return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

/* Inicializar mapa al cargar */
document.addEventListener('DOMContentLoaded', function() {
    renderAlphaMap(ALPHA_DEFAULT, false);
});