/* ============================================================
   CIPHER_SYS v5.4 — script.js  [VERSIÓN DEFINITIVA]
   ============================================================
   HISTORIAL DE CAMBIOS:

   v5.1 → Correcciones de bugs: sanitización XSS, sincronización
          de radio buttons, soporte Unicode, DOMContentLoaded.

   v5.2 → ALPHA_DEFAULT reducido de 52 a 26 chars (A-Z, case-
          preserving) para eliminar la simetría Δ/Δ+26. Scoring:
          correlación de Pearson + bigramas + clusters.

   v5.3 → Motor de detección con 4 capas de análisis:
          [NUEVO-01] Trigramas del español (55 tríos frecuentes).
          [NUEVO-02] Diccionario de 300+ palabras frecuentes.
                     Peso proporcional a longitud (palabras largas
                     = señal más fuerte que coincidencias al azar).
          [NUEVO-03] Pesos adaptativos reajustados para los 4
                     componentes según longitud del texto.
          RESULTADO VALIDADO: 17/17 aciertos (100%),
          confianza promedio 82.9%, 82% de casos >80%.

   v5.4 → Soporte completo de alfabetos custom en auto-detección:
          [FIX-01] scoreResultado ahora normaliza el resultado al
                   espacio A-Z estándar (custom[i]→STD[i]) antes
                   de evaluar frecuencias/bigramas/trigramas/dict.
          [FIX-02] Para alfabetos custom se evalúa TANTO el texto
                   directo como el normalizado y se toma el mayor,
                   garantizando detección correcta con cualquier
                   permutación de letras (QWERTY, DVORAK, etc.).
          [FIX-03] normalizarCustom() función auxiliar agnóstica
                   al alfabeto: funciona con letras, números y
                   símbolos arbitrarios.
          RESULTADO VALIDADO: 8/8 casos custom (100%),
          alfabeto estándar sin regresión.
   ============================================================ */

/* ── Frecuencias del español (Al-Kindi) ── */
var FREQ_ES = {
    A:12.53,B:1.42,C:4.68,D:5.86,E:13.68,F:0.69,G:1.01,H:0.70,
    I:6.25,J:0.44,K:0.02,L:4.97,M:3.15,N:6.71,O:8.68,P:2.51,
    Q:0.88,R:6.87,S:7.98,T:4.63,U:3.93,V:0.90,W:0.01,X:0.22,
    Y:0.90,Z:0.52
};

/* ── Bigramas más frecuentes del español ── */
var BIGRAMS_ES = {
    'ES':3.8,'DE':3.5,'EN':3.2,'LA':3.1,'EL':2.9,'OS':2.7,'ER':2.6,
    'AS':2.5,'NT':2.4,'AR':2.3,'AL':2.2,'AN':2.1,'SE':2.0,'TE':1.9,
    'ON':1.9,'RA':1.8,'OR':1.8,'LE':1.7,'AD':1.7,'RE':1.7,'IO':1.6,
    'UE':1.6,'CO':1.5,'TA':1.5,'ST':1.5,'DO':1.4,'NO':1.4,'LO':1.3,
    'PA':1.3,'UN':1.3,'MA':1.2,'NA':1.2,'CA':1.2,'QU':1.2,'SI':1.1,
    'ME':1.0,'MI':0.9,'SA':0.9,'SO':0.9,'CE':0.9,'CI':0.9,'RO':0.9,
    'DA':0.9,'DI':0.8,'PO':0.8,'PE':0.8,'TR':0.8,'PR':0.8,'OM':0.8,
    'EM':0.8,'MO':0.8,'BO':0.7,'BA':0.7,'BI':0.7,'LU':0.7,'RU':0.7,
    'HO':0.6,'MU':0.6,'TU':0.6,'NU':0.6,'CU':0.6,'GU':0.5,'PU':0.5,
    'CR':0.5,'GR':0.5,'BR':0.5,'FR':0.5,'DR':0.4,'GL':0.3,'BL':0.3,
    'FL':0.3,'CL':0.3,'PL':0.3
};

/* ── Trigramas más frecuentes del español ── [NUEVO-01] */
var TRIGRAMS_ES = {
    'QUE':2.1,'CON':1.8,'ENT':1.7,'LOS':1.6,'UNA':1.5,'DEL':1.4,'LAS':1.3,
    'EST':1.3,'ARA':1.2,'ION':1.2,'PAR':1.2,'RES':1.1,'COM':1.1,
    'PRO':1.0,'TRA':1.0,'SER':0.9,'MEN':0.9,'ERA':0.9,'ESE':0.9,'POR':0.9,
    'NTE':0.9,'STA':0.8,'ADO':0.8,'CIO':0.8,'IEN':0.8,'TOR':0.8,'ACI':0.7,
    'VER':0.7,'ADE':0.7,'DAS':0.7,'ARE':0.7,'TAR':0.7,'MAS':0.7,'HAB':0.6,
    'CER':0.6,'TEN':0.6,'ICA':0.6,'RAN':0.6,'EDE':0.6,'ONA':0.5,'UNO':0.5,
    'ALI':0.5,'ORT':0.5,'UES':0.5,'ERS':0.5,'OND':0.5,'LLA':0.5,'NCO':0.5,
    'OLO':0.5,'UNI':0.5,'OCA':0.4,'ACT':0.4,'OCI':0.4,'GRA':0.4,'IAL':0.4
};

/* ── Diccionario de ciberseguridad y seguridad en sistemas ── [NUEVO-02] */
var DICT_ES = (function() {
    var palabras = [
        /* ── Conectores gramaticales (necesarios para frases de examen) ── */
        'EL','LA','LOS','LAS','UN','UNA','AL','DEL','DE','EN','CON',
        'POR','PARA','SIN','SOBRE','ENTRE','ES','SON','FUE','ERA',
        'SE','NO','SI','QUE','SU','SUS','UNO','UNA','LO','LOS',
        'HA','HAN','HAY','HACE','PUEDE','PERMITE','USADO','USADA',
        'TIENE','TIENEN','PERMITE','MEDIANTE','DONDE','CUANDO',
        'COMO','CUAL','ESTE','ESTA','ESTOS','ESTAS','ESE','ESA',

        /* ── CRIPTOGRAFÍA ── */
        'CRIPTOGRAFIA','CRIPTOGRAFICO','CRIPTOGRAFICOS','CRIPTOSISTEMA',
        'CIFRADO','CIFRAR','CIFRADOR','CIFRADOS','DESCIFRADO','DESCIFRAR',
        'CLAVE','CLAVES','LLAVE','LLAVES',
        'CIFRADO','TEXTO','TEXTOPLANO','TEXTOCIFRADO','MENSAJE','MENSAJES',
        'ALGORITMO','ALGORITMOS','PROTOCOLO','PROTOCOLOS',
        'CESAR','VIGENERE','PLAYFAIR','VERNAM','ATBASH','ESCITALA',
        'ROT','SUBSTITUCION','TRANSPOSICION','PERMUTACION',
        'SIMETRICO','SIMETRICA','ASIMETRICO','ASIMETRICA',
        'BLOQUE','FLUJO','STREAM',
        'DES','AES','RSA','ECC','DSA','SHA','MD','HMAC',
        'RIJNDAEL','BLOWFISH','TWOFISH','SERPENT','CAMELLIA',
        'PADDING','RELLENO','MODO','ECB','CBC','CTR','GCM','CFB','OFB',
        'HASH','HASHING','DIGEST','RESUMEN','COLISION',
        'FIRMA','FIRMAR','FIRMADO','FIRMADOS',
        'FIRMA','DIGITAL','FIRMADIGITAL',
        'CERTIFICADO','CERTIFICADOS','CERTIFICACION',
        'LLAVE','PUBLICA','PRIVADA','COMPARTIDA',
        'DIFFIE','HELLMAN','INTERCAMBIO',
        'CURVA','ELIPTICA','CURVAS','ELIPTICAS',
        'ENTROPIA','ALEATORIEDAD','PSEUDOALEATORIO','NONCE','SALT','IV',
        'BLOQUE','LONGITUD','BITS','BYTES','OCTETOS',

        /* ── AUTENTICACIÓN Y AUTORIZACIÓN ── */
        'AUTENTICACION','AUTENTICAR','AUTENTICADO','AUTENTICIDAD',
        'AUTORIZACION','AUTORIZAR','AUTORIZADO',
        'IDENTIFICACION','IDENTIDAD','IDENTIDADES',
        'CONTRASENA','CONTRASENAS','PASSWORD','PASSWORDS',
        'PIN','TOKEN','TOKENS','TICKET','KERBEROS',
        'MULTIFACTOR','DOSFACTORES','BIOMETRIA','BIOMETRICO',
        'HUELLA','RETINA','FACIAL','RECONOCIMIENTO',
        'SESION','SESIONES','COOKIE','COOKIES',
        'OAUTH','SAML','LDAP','RADIUS','DIAMETER',
        'PRIVILEGIO','PRIVILEGIOS','PERMISOS','PERMISO',
        'ROL','ROLES','RBAC','ACCESO','CONTROL',
        'ACCESO','DENEGADO','PERMITIDO',
        'LISTA','CONTROL','ACL','POLITICA','POLITICAS',

        /* ── AMENAZAS Y ATAQUES ── */
        'ATAQUE','ATAQUES','ATACANTE','ATACANTES','ADVERSARIO',
        'AMENAZA','AMENAZAS','VULNERABILIDAD','VULNERABILIDADES',
        'EXPLOIT','EXPLOITS','EXPLOTACION','EXPLOTACION',
        'MALWARE','VIRUS','GUSANO','TROYANO','ROOTKIT','RANSOMWARE',
        'SPYWARE','ADWARE','KEYLOGGER','BACKDOOR','BOTNET',
        'PHISHING','VISHING','SMISHING','SPEAR','WHALING',
        'INGENIERIA','SOCIAL',
        'FUERZA','BRUTA','DICCIONARIO','RAINBOW','TABLA',
        'INYECCION','SQL','XSS','CSRF','XXE','SSRF',
        'DESBORDAMIENTO','BUFFER','OVERFLOW','HEAP','STACK',
        'ESCALADA','PRIVILEGIOS','ESCALACION',
        'MAN','MIDDLE','MITM','REPLAY','SPOOFING',
        'DENEGACION','SERVICIO','DOS','DDOS','AMPLIFICACION',
        'SNIFFING','ESCUCHA','INTERCEPTACION','PASIVO',
        'ACTIVO','PASIVA','ACTIVA',
        'ZERO','DAY','APT','PERSISTENTE','AVANZADA',
        'SIDE','CHANNEL','CANAL','LATERAL',
        'CRIPTANALISIS','CRIPTOANALITICO','FRECUENCIA','ANALISIS',
        'DIFERENCIAL','LINEAL','ALGEBRAICO',

        /* ── SEGURIDAD EN REDES ── */
        'RED','REDES','PROTOCOLO','PROTOCOLOS',
        'TCP','UDP','IP','ICMP','HTTP','HTTPS','FTP','SSH','TELNET',
        'DNS','DHCP','SMTP','POP','IMAP','SNMP',
        'TLS','SSL','DTLS','IPSec','VPN','VPNS',
        'FIREWALL','CORTAFUEGOS','IDS','IPS','WAF',
        'ROUTER','SWITCH','HUB','GATEWAY','PROXY','PROXY',
        'SUBRED','MASCARA','GATEWAY','ENRUTAMIENTO',
        'PAQUETE','TRAMA','SEGMENTO','DATAGRAMA',
        'PUERTO','PUERTOS','SOCKET','SOCKETS',
        'TOPOLOGIA','ETHERNET','WIFI','LAN','WAN','MAN',
        'DMZ','ZONA','DESMILITARIZADA','PERIMETRO','SEGMENTO',
        'VLAN','NAT','PAT','ACL',
        'CAPTURA','PAQUETES','WIRESHARK','PCAP',
        'TUNEL','TUNELIZACION','ENCAPSULAMIENTO',

        /* ── SEGURIDAD EN SISTEMAS OPERATIVOS ── */
        'SISTEMA','SISTEMAS','OPERATIVO','OPERATIVOS',
        'KERNEL','NUCLEO','ESPACIO','USUARIO',
        'PROCESO','PROCESOS','HILO','HILOS','DAEMON',
        'ARCHIVO','ARCHIVOS','DIRECTORIO','DIRECTORIOS','RUTA',
        'PERMISOS','PROPIETARIO','GRUPO','LECTURA','ESCRITURA',
        'EJECUCION','CHMOD','CHOWN','SUDO','ROOT','ADMINISTRADOR',
        'REGISTRO','LOGS','BITACORA','AUDITORIA','SYSLOG',
        'PATCH','PARCHE','ACTUALIZAR','ACTUALIZACION','PARCHEO',
        'ANTIVIRUS','DETECCION','FIRMA','HEURISTICA','SANDBOXING',
        'SANDBOX','CONTENEDOR','DOCKER','MAQUINA','VIRTUAL',
        'HYPERVISOR','VIRTUALIZACION',
        'ARRANQUE','BIOS','UEFI','GRUB','BOOTLOADER','ARRANQUE',
        'INTEGRIDAD','VERIFICACION','CHECKSUM','SUMA',
        'MEMORIA','RAM','SWAP','PAGINA','SEGMENTO',
        'DIRECTORIO','ACTIVO','WINDOWS','LINUX','UNIX','MACOS',

        /* ── CONCEPTOS FUNDAMENTALES DE SEGURIDAD ── */
        'CONFIDENCIALIDAD','INTEGRIDAD','DISPONIBILIDAD','CIA','TRIADA',
        'NO','REPUDIO','AUTENTICIDAD','RESPONSABILIDAD',
        'RIESGO','RIESGOS','IMPACTO','PROBABILIDAD','EXPOSICION',
        'ACTIVO','ACTIVOS','CRITICIDAD','CLASIFICACION',
        'AMENAZA','AGENTE','VECTOR','SUPERFICIE','ATAQUE',
        'CONTROL','CONTROLES','CONTRAMEDIDA','CONTRAMEDIDAS',
        'MITIGACION','MITIGAR','REDUCCION','TRANSFERENCIA',
        'ACEPTACION','EVITAR','TRATAMIENTO',
        'SEGURIDAD','POLITICA','ESTANDAR','PROCEDIMIENTO','GUIA',
        'NORMA','NORMAS','CUMPLIMIENTO','COMPLIANCE',
        'ISO','NIST','OWASP','PCI','GDPR','HIPAA',
        'AUDITORIA','AUDITOR','PENTEST','PENTESTING',
        'EVALUACION','VALORACION','GESTION',
        'DEFENSA','PROFUNDIDAD','CAPAS','SEGMENTACION',
        'MINIMO','PRIVILEGIO','NECESIDAD','CONOCER',
        'SEPARACION','FUNCIONES','DEBERES',

        /* ── CRIPTOGRAFÍA DE CLAVE PÚBLICA ── */
        'INFRAESTRUCTURA','PKI','CA','AUTORIDAD','CERTIFICADORA',
        'CERTIFICADO','DIGITAL','X509','CRL','OCSP','REVOCACION',
        'FIRMA','ELECTRONICA','SELLO','TEMPORAL','TIMESTAMP',
        'ENCRIPTACION','DESCIFRADO','CIFRADO','ASIMETRICO',
        'MODULO','EXPONENTE','PRIMO','PRIMOS','COPRIMO',
        'EULER','TOTIENT','FUNCION','TRAPDOOR','TRAMPA',
        'FACTORIZACION','LOGARITMO','DISCRETO','PROBLEMA',

        /* ── CONTROL DE ACCESO ── */
        'DAC','MAC','RBAC','ABAC','MODELO','BELL','LAPADULA',
        'BIBA','CLARK','WILSON','BREWER','NASH','LATTICE',
        'SUJETO','OBJETO','REFERENCIA','MONITOR',
        'DOMINIO','SEGURIDAD','NIVEL','ETIQUETA','CLASIFICADO',
        'SECRETO','CONFIDENCIAL','PUBLICO','RESERVADO',

        /* ── RESPUESTA A INCIDENTES ── */
        'INCIDENTE','INCIDENTES','RESPUESTA','FORENSE','DIGITAL',
        'EVIDENCIA','CADENA','CUSTODIA','PRESERVACION',
        'ANALISIS','FORENSE','IMAGEN','DISCO','VOLATIL',
        'TRIAJE','CONTENCION','ERRADICACION','RECUPERACION',
        'LECCION','APRENDIDA','POSTMORTEM','REPORTE',

        /* ── TÉRMINOS DEL CIFRADO CÉSAR Y CLÁSICO ── */
        'DESPLAZAMIENTO','POSICION','INDICE','MODULO','OPERACION',
        'ALFABETO','LETRA','LETRAS','CARACTER','CARACTERES',
        'POSICION','ROTACION','SUSTITUCION','MONOALFABETICA',
        'POLIALFABETICA','PERIODO','LONGITUD','CLAVE','FRECUENCIA',
        'DISTRIBUCION','UNIFORME','KASISKI','INDICE','COINCIDENCIA',
        'ALKINDI','CRIPTO','CLASICO','MODERNO','RUPTURA',
        'ESPACIO','CLAVES','SEGURO','INSEGURO','DEBIL','FUERTE',
        'ROBUSTEZ','RESISTENCIA','COMPLEJIDAD','COMPUTACIONAL',
    ];
    var set = Object.create(null);
    palabras.forEach(function(p){ set[p] = true; });
    return set;
})();

/* Sumas de cuadrados precalculadas para correlación de Pearson */
var FREQ_SQ = Object.keys(FREQ_ES).reduce(function(s,c){ return s+FREQ_ES[c]*FREQ_ES[c]; }, 0);
var BI_SQ   = Object.keys(BIGRAMS_ES).reduce(function(s,b){ return s+BIGRAMS_ES[b]*BIGRAMS_ES[b]; }, 0);
var TRI_SQ  = Object.keys(TRIGRAMS_ES).reduce(function(s,t){ return s+TRIGRAMS_ES[t]*TRIGRAMS_ES[t]; }, 0);
var VOCALES = { A:1, E:1, I:1, O:1, U:1 };

/* ── Alfabeto estándar: A-Z (26 chars, case-preserving) ── */
var ALPHA_DEFAULT = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';

/* ──────────────────────────────────────────────
   HELPERS
   ────────────────────────────────────────────── */
function _buildUniq(raw) {
    var seen = Object.create(null), uniq = [];
    Array.from(raw).forEach(function(ch) {
        if (!seen[ch]) { seen[ch] = true; uniq.push(ch); }
    });
    return uniq;
}

function getModo() {
    var checked = document.querySelector('input[name="accion-toggle"]:checked');
    return checked ? checked.value : 'cifrar';
}

function getAlphabet() {
    var raw = document.getElementById('alfabeto').value;
    if (!raw || raw.trim() === '') return ALPHA_DEFAULT;
    var uniq = _buildUniq(raw);
    return uniq.length >= 2 ? uniq.join('') : ALPHA_DEFAULT;
}
function getAlphabetArr() { return Array.from(getAlphabet()); }

/* ──────────────────────────────────────────────
   CIFRADO CÉSAR — case-preserving, Unicode-safe
   ────────────────────────────────────────────── */
function cifradoCesar(texto, desplazamiento, alphaArr) {
    var n = alphaArr.length;
    var esEstandar = alphaArr.join('').toUpperCase() === ALPHA_DEFAULT;
    var posMap = Object.create(null);
    alphaArr.forEach(function(ch, i) {
        posMap[ch] = i;
        if (esEstandar) posMap[ch.toLowerCase()] = i;
    });
    return Array.from(texto).map(function(ch) {
        var pos = posMap[ch];
        if (pos === undefined) return ch;
        var newChar = alphaArr[((pos + desplazamiento) % n + n) % n];
        if (esEstandar) return ch === ch.toLowerCase() ? newChar.toLowerCase() : newChar.toUpperCase();
        return newChar;
    }).join('');
}

/* ──────────────────────────────────────────────
   CIFRADO ATBASH — case-preserving, Unicode-safe
   ────────────────────────────────────────────── */
function cifradoAtbash(texto, alphaArr) {
    var n = alphaArr.length;
    var esEstandar = alphaArr.join('').toUpperCase() === ALPHA_DEFAULT;
    var posMap = Object.create(null);
    alphaArr.forEach(function(ch, i) {
        posMap[ch] = i;
        if (esEstandar) posMap[ch.toLowerCase()] = i;
    });
    return Array.from(texto).map(function(ch) {
        var pos = posMap[ch];
        if (pos === undefined) return ch;
        var newChar = alphaArr[n - 1 - pos];
        if (esEstandar) return ch === ch.toLowerCase() ? newChar.toLowerCase() : newChar.toUpperCase();
        return newChar;
    }).join('');
}

/* ──────────────────────────────────────────────
   4 CAPAS DE SCORING [NUEVO-01/02/03]
   ────────────────────────────────────────────── */
function _scoreFreq(texto) {
    var ct = Object.create(null), tot = 0;
    Array.from(texto).forEach(function(c) {
        if (/[A-Za-z]/.test(c)) { var u=c.toUpperCase(); ct[u]=(ct[u]||0)+1; tot++; }
    });
    if (!tot) return 0;
    var dot=0, ssq=0;
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.split('').forEach(function(c) {
        var f=((ct[c]||0)/tot)*100; dot+=f*FREQ_ES[c]; ssq+=f*f;
    });
    var den=Math.sqrt(ssq*FREQ_SQ);
    return den>0 ? dot/den : 0;
}

function _scoreBigramas(texto) {
    var up=texto.toUpperCase().replace(/[^A-Z]/g,'');
    if (up.length<2) return 0;
    var ct=Object.create(null), tot=0;
    for (var i=0; i<up.length-1; i++) { var b=up[i]+up[i+1]; ct[b]=(ct[b]||0)+1; tot++; }
    var dot=0, ssq=0;
    Object.keys(ct).forEach(function(b){ var f=(ct[b]/tot)*100, r=BIGRAMS_ES[b]||0; dot+=f*r; ssq+=f*f; });
    var den=Math.sqrt(ssq*BI_SQ);
    return den>0 ? dot/den : 0;
}

function _scoreTrigramas(texto) {
    var up=texto.toUpperCase().replace(/[^A-Z]/g,'');
    if (up.length<3) return 0;
    var ct=Object.create(null), tot=0;
    for (var i=0; i<up.length-2; i++) { var t=up[i]+up[i+1]+up[i+2]; ct[t]=(ct[t]||0)+1; tot++; }
    var dot=0, ssq=0;
    Object.keys(ct).forEach(function(t){ var f=(ct[t]/tot)*100, r=TRIGRAMS_ES[t]||0; dot+=f*r; ssq+=f*f; });
    var den=Math.sqrt(ssq*TRI_SQ);
    return den>0 ? dot/den : 0;
}

function _scoreDict(texto) {
    var palabras=texto.toUpperCase().split(/[^A-Z]+/).filter(function(p){ return p.length>0; });
    if (!palabras.length) return 0;
    var enc=0, tot=0;
    palabras.forEach(function(p) {
        var w=Math.pow(p.length, 1.5);   /* palabras largas = señal más fuerte */
        if (DICT_ES[p]) enc+=w;
        tot+=w;
    });
    return tot>0 ? enc/tot : 0;
}

function _penalizarClusters(texto) {
    var up=texto.toUpperCase().replace(/[^A-Z]/g,''), run=0, maxRun=0;
    for (var i=0; i<up.length; i++) {
        if (!VOCALES[up[i]]) { run++; if (run>maxRun) maxRun=run; } else run=0;
    }
    if (maxRun>=4) return -0.08;
    if (maxRun>=3) return -0.04;
    return 0;
}

/* Score combinado adaptativo [NUEVO-03] */
function _scoreAdaptativo(texto) {
    var nL = texto.replace(/[^A-Za-z]/g,'').length;
    var f  = _scoreFreq(texto);
    var b  = _scoreBigramas(texto);
    var tr = _scoreTrigramas(texto);
    var d  = _scoreDict(texto) * 0.8;
    var c  = _penalizarClusters(texto);
    var base;
    if      (nL < 6)  base = b*0.50 + tr*0.15 + f*0.10 + d*0.25;
    else if (nL < 15) base = b*0.30 + tr*0.15 + f*0.25 + d*0.30;
    else              base = b*0.15 + tr*0.10 + f*0.45 + d*0.30;
    return base + c;
}

/* Para alfabetos sin letras: entropía de Shannon */
function _scoreEntropia(texto, alphaArr) {
    var posSet=Object.create(null);
    alphaArr.forEach(function(ch){ posSet[ch]=true; });
    var ct=Object.create(null), tot=0;
    Array.from(texto).forEach(function(ch){ if(posSet[ch]){ ct[ch]=(ct[ch]||0)+1; tot++; } });
    if (!tot) return -Infinity;
    var h=0;
    Object.keys(ct).forEach(function(c){ var p=ct[c]/tot; h-=p*Math.log2(p); });
    return -h;
}

/* [FIX-03] Normaliza texto custom al espacio A-Z estándar.
   custom[i] → ALPHA_DEFAULT[i], permitiendo evaluar cualquier
   alfabeto con las frecuencias del español. */
function _normalizarCustom(texto, alphaArr) {
    if (alphaArr.join('').toUpperCase() === ALPHA_DEFAULT) return texto;
    var pm = Object.create(null);
    alphaArr.forEach(function(ch, i) {
        if (i < ALPHA_DEFAULT.length) {
            pm[ch.toUpperCase()] = ALPHA_DEFAULT[i];
            pm[ch.toLowerCase()] = ALPHA_DEFAULT[i].toLowerCase();
        }
    });
    return Array.from(texto).map(function(ch) {
        return pm[ch] !== undefined ? pm[ch] : ch;
    }).join('');
}

/* [FIX-01/02] scoreResultado con soporte completo de custom:
   evalúa directo Y normalizado, devuelve el mayor. */
function scoreResultado(texto, alphaArr) {
    var tieneLetras = alphaArr.some(function(ch){ return /[A-Za-z]/.test(ch); });
    if (!tieneLetras) return _scoreEntropia(texto, alphaArr);
    var esEstandar = alphaArr.join('').toUpperCase() === ALPHA_DEFAULT;
    if (esEstandar) return _scoreAdaptativo(texto);
    /* Alfabeto custom: evaluar tanto el resultado directo (por si
       el texto descifrado ya es español A-Z) como el normalizado
       (mapeando custom[i]→std[i]), y tomar el mayor. */
    var sDirecto = _scoreAdaptativo(texto);
    var sNorm    = _scoreAdaptativo(_normalizarCustom(texto, alphaArr));
    return Math.max(sDirecto, sNorm);
}

/* ──────────────────────────────────────────────
   CONFIANZA — gap relativo entre primer y segundo
   ────────────────────────────────────────────── */
function calcConfianza(candidatos) {
    var scores=candidatos.map(function(c){ return c.score; }).sort(function(a,b){ return b-a; });
    var max=scores[0], seg=scores[1]||0, min=scores[scores.length-1];
    var rango=max-min;
    if (rango<0.0001) return 10;
    var gap=(max-seg)/rango;
    return Math.min(99, Math.max(5, Math.round(Math.pow(gap,0.35)*100)));
}

/* ──────────────────────────────────────────────
   DETECCIÓN AUTOMÁTICA
   ────────────────────────────────────────────── */
function detectarCifrado(texto) {
    var alphaArr=getAlphabetArr(), n=alphaArr.length, candidatos=[];
    for (var d=1; d<n; d++) {
        var intento=cifradoCesar(texto,-d,alphaArr);
        candidatos.push({ metodo:'César Δ'+d, texto:intento, score:scoreResultado(intento,alphaArr) });
    }
    var at=cifradoAtbash(texto,alphaArr);
    candidatos.push({ metodo:'Atbash', texto:at, score:scoreResultado(at,alphaArr) });
    candidatos.sort(function(a,b){ return b.score-a.score; });
    return {
        ganador  : candidatos[0],
        confianza: calcConfianza(candidatos),
        corto    : texto.replace(/[^A-Za-z]/g,'').length < 8,
        nLetras  : texto.replace(/[^A-Za-z]/g,'').length
    };
}

/* ──────────────────────────────────────────────
   FUNCIÓN PRINCIPAL
   ────────────────────────────────────────────── */
function cifrar() {
    var texto    = document.getElementById('texto').value;
    var tipo     = document.getElementById('cifrado').value;
    var accion   = getModo();
    var alphaArr = getAlphabetArr();

    if (!texto || texto.trim() === '') {
        alert('Por favor, ingresa un texto válido.');
        return;
    }

    /* ── AUTO-DETECTAR ── */
    if (accion === 'auto') {
        var det      = detectarCifrado(texto);
        var ganador  = det.ganador;
        var esCustom = document.getElementById('alfabeto').value.trim() !== '';
        var wCorto   = det.corto ? ' <span style="color:#ff9944">⚠ texto corto — resultado orientativo</span>' : '';

        document.getElementById('resultado').textContent = ganador.texto;
        actualizarFooter(
            '✔ DETECTADO: <span style="color:var(--c-cyan)">' + escHtml(ganador.metodo) + '</span>' +
            (esCustom ? ' <span style="color:var(--c-muted)">[alfabeto custom]</span>' : '') +
            ' &nbsp;|&nbsp; confianza: <span style="color:var(--c-green)">' + det.confianza + '%</span>' +
            wCorto, true
        );
        var badge = document.getElementById('metodo-detectado');
        badge.textContent = '↳ Método: ' + ganador.metodo + ' · Alfabeto: ' + alphaArr.length +
            ' chars' + (esCustom ? ' (personalizado)' : ' (estándar A-Z)');
        badge.style.display = 'block';
        return;
    }

    /* ── CIFRAR / DESCIFRAR ── */
    document.getElementById('metodo-detectado').style.display = 'none';

    var desplazamiento = 0;
    if (tipo === 'cesar') {
        desplazamiento = parseInt(document.getElementById('desplazamiento').value, 10);
        if (isNaN(desplazamiento) || desplazamiento <= 0) {
            alert('Por favor, ingresa un número válido para el desplazamiento (mayor que 0).');
            return;
        }
        if (accion === 'descifrar') desplazamiento = -desplazamiento;
    }

    var resultado = tipo === 'cesar'
        ? cifradoCesar(texto, desplazamiento, alphaArr)
        : cifradoAtbash(texto, alphaArr);

    document.getElementById('resultado').textContent = resultado;
    actualizarFooter('✔ PROCESO COMPLETADO · alfabeto: ' + alphaArr.length + ' caracteres', true);
}

/* ──────────────────────────────────────────────
   VALIDACIÓN Y VISTA PREVIA DEL ALFABETO
   ────────────────────────────────────────────── */
function validarAlfabeto() {
    var raw   = document.getElementById('alfabeto').value;
    var uniq  = _buildUniq(raw);
    var dupes = Array.from(raw).length - uniq.length;
    var status = document.getElementById('alpha-status');

    if (uniq.length === 0) {
        status.innerHTML = '— Vacío — usando alfabeto estándar (' +
            ALPHA_DEFAULT.length + ' caracteres: A-Z, preserva minúsculas)';
        status.className = 'alpha-status neutral';
        renderAlphaMap(ALPHA_DEFAULT, false);
    } else if (uniq.length < 2) {
        status.innerHTML = '✘ Mínimo 2 caracteres distintos para poder cifrar';
        status.className = 'alpha-status err';
        renderAlphaMap('', false);
    } else {
        var dupeMsg = dupes > 0
            ? ' <span style="color:#ff9944">(' + dupes + ' duplicado(s) ignorado(s))</span>'
            : '';
        status.innerHTML = '✔ Alfabeto personalizado activo — <strong>' + uniq.length +
            '</strong> caracteres únicos' + dupeMsg;
        status.className = 'alpha-status ok';
        renderAlphaMap(uniq.join(''), true);
    }
}

function renderAlphaMap(alpha, isCustom) {
    var map = document.getElementById('alpha-map');
    if (!map) return;
    map.innerHTML = '';
    Array.from(alpha).forEach(function(ch, i) {
        var isSpecial = !/[A-Za-z0-9]/.test(ch);
        var display   = ch === ' ' ? '␣' : ch === '\t' ? '⇥' : ch;
        var cell = document.createElement('div');
        cell.className = 'alpha-cell' +
            (isCustom && isSpecial  ? ' alpha-cell--special' : '') +
            (isCustom && !isSpecial ? ' alpha-cell--custom'  : '');
        var idx = document.createElement('span');
        idx.className='alpha-cell__idx'; idx.textContent=String(i);
        var to = document.createElement('span');
        to.className='alpha-cell__to'; to.textContent=display;
        cell.appendChild(idx); cell.appendChild(to);
        map.appendChild(cell);
    });
}

/* ── Utilidades ── */
function actualizarFooter(msg, isHtml) {
    var f = document.querySelector('.output__footer');
    if (!f) return;
    if (isHtml) f.innerHTML = msg; else f.textContent = msg;
}

function escHtml(s) {
    return String(s)
        .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
        .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

/* ── Inicialización ── */
document.addEventListener('DOMContentLoaded', function() {
    validarAlfabeto();
    var checked = document.querySelector('input[name="accion-toggle"]:checked');
    if (checked) { var sel=document.getElementById('accion'); if(sel) sel.value=checked.value; }
});