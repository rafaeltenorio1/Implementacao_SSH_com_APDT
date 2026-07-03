import json, struct, base64
from typing import List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet


# ── Cores ─────────────────────────────────────────────────────────
class C:
    RESET = "\033[0m"; BOLD = "\033[1m"; RED    = "\033[91m"
    GREEN = "\033[92m"; YELLOW = "\033[93m"; BLUE  = "\033[94m"
    CYAN  = "\033[96m"; GRAY   = "\033[90m"; PURPLE= "\033[95m"
    WHITE = "\033[97m"; ORANGE = "\033[33m"

def cor(t, c): return f"{c}{t}{C.RESET}"


# ── Tokens válidos (Σ) ─────────────────────────────────────────────
TOKENS_VALIDOS = {
    "chavesinit", "chaves_repassadas", "novaschaves",
    "servico_req", "servico_ok", "usuario_req", "usuario_ok",
    "canal_aberto", "canal_conf", "canal_falha", "canal_fechado",
    "requisicao", "req_falha", "dados", "req_finalizada",
    "disconectado",
}


# ── Rede ──────────────────────────────────────────────────────────
# Formato: [4 bytes tamanho big-endian][JSON body]

def empacotar(tipo, payload="", cifrado=False, canal="") -> bytes:
    """Transforma os dados num JSON e adiciona um cabeçalho de 4 bytes indicando o tamanho exato."""
    m = {"tipo": tipo,
         "payload": payload,
         "cifrado": cifrado
         }
    if canal: m["canal"] = canal
    raw = json.dumps(m).encode()
    return struct.pack(">I", len(raw)) + raw

def desempacotar(sock) -> Optional[dict]:
    """Lê exatamente a quantidade de bytes informada no cabeçalho, evitando ler pedaços misturados."""
    try:
        hdr = b""
        while len(hdr) < 4:
            c = sock.recv(4 - len(hdr))
            if not c: return None
            hdr += c
        tam = struct.unpack(">I", hdr)[0]
        if tam == 0 or tam > 1_000_000: return None
        corpo = b""
        while len(corpo) < tam:
            c = sock.recv(tam - len(corpo))
            if not c: return None
            corpo += c
        return json.loads(corpo.decode())
    except Exception:
        return None


# ── Criptografia: X25519 + AES-256 (Fernet) ───────────────────────
# X25519 é DH em curvas elípticas — mesmo algoritmo do SSH real (RFC 8731).
# Cada lado gera seu par independentemente; o segredo nunca trafega.

def gerar_par_dh() -> Tuple[X25519PrivateKey, str]:
    """Gera um par de chaves para o Diffie-Hellman usando curvas elípticas."""
    priv = X25519PrivateKey.generate()
    pub  = priv.public_key().public_bytes_raw().hex()
    return priv, pub

def derivar_chave(priv: X25519PrivateKey, pub_hex: str) -> Fernet:
    """Combina a chave privada local com a pública remota para gerar um segredo compartilhado.
    Usa HKDF para esticar esse segredo e gerar a chave simétrica AES-256 (Fernet)."""
    pub     = X25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
    segredo = priv.exchange(pub)
    chave   = HKDF(algorithm=hashes.SHA256(), length=32,
                   salt=None, info=b"ssh-apdt",
                   backend=default_backend()).derive(segredo)
    return Fernet(base64.urlsafe_b64encode(chave))

def cifrar(f: Fernet, t: str) -> str:
    return f.encrypt(t.encode()).decode()
def decifrar(f: Fernet, t: str) -> str:
    return f.decrypt(t.encode()).decode()


# ── APDT ──────────────────────────────────────────────────────────

class Status(Enum):
    EM_EXECUCAO = "em_execucao"
    ACEITO      = "aceito"
    COM_AVISO   = "com_aviso"

@dataclass
class Passo:
    """Estrutura para armazenar o histórico de transições do autômato."""
    numero:    int
    estado:    str
    token:     str
    pilha:     List[str]
    producao:  str
    aceito:    bool = False
    aviso:     bool = False
    msg_aviso: str  = ""


class APDT:
    """
    Autômato de Pilha Determinístico — Valida a sintaxe do protocolo.
    Usa aceitação por pilha vazia. Diferente de um compilador estrito,
    ele não "crasha" em caso de erro, apenas gera avisos visuais.
    """

    def __init__(self):
        self.estado  = "q0"
        self.pilha   : List[str] = ["$"]
        self.trace   : List[Passo] = []
        self.status  = Status.EM_EXECUCAO
        self._n      = 0
        self._chans  = 1
        self._reqs   = 1

    def topo(self) -> str:
        return self.pilha[0] if self.pilha else "∅"

    def pilha_str(self) -> str:
        return " | ".join(self.pilha) if self.pilha else "∅"

    def aceito(self) -> bool:
        return self.status == Status.ACEITO

    def tem_aviso(self) -> bool:
        return self.status == Status.COM_AVISO

    def _push(self, s):
        self.pilha.insert(0, s)

    def _pop(self):
        return self.pilha.pop(0)

    def _reg(self, token, prod, aceito=False, aviso=False, msg="") -> Passo:
        """Registra a transição no histórico (trace)."""
        self._n += 1
        p = Passo(self._n, self.estado, token, list(self.pilha), prod, aceito=aceito, aviso=aviso, msg_aviso=msg)
        self.trace.append(p)
        return p

    def _aviso(self, token, msg) -> Passo:
        """Registra uma transição inválida sem interromper a execução."""
        self.status = Status.COM_AVISO
        return self._reg(token, "—", aviso=True, msg=msg)

    def processar(self, token: str) -> Passo:
        """Avalia um token recebido/enviado e tenta transicionar o estado."""
        if self.status == Status.ACEITO and self.pilha == []:
            return self._aviso(token, "sessão já encerrada com sucesso")
        return self._trans(token)

    def _trans(self, t: str) -> Passo:
        """
        O 'Coração' do Autômato. Define as regras de transição Baseadas em Estado(q) + Token(t).
        """
        q = self.estado

        # ── CHAVES q0→q1→q2→q3 (P2) ──────────────────────────────
        if q == "q0":
            if t == "chavesinit":
                self.estado = "q1"
                return self._reg(t, "P2: CHAVES → chavesinit ...")
            return self._aviso(t, f"FALHA: esperado 'chavesinit'")

        elif q == "q1":
            if t == "chaves_repassadas":
                self.estado = "q2"
                return self._reg(t, "P2: CHAVES → ... chaves_repassadas ...")
            return self._aviso(t, f"FALHA: esperado 'chaves_repassadas'")

        elif q == "q2":
            if t == "novaschaves":
                self.estado = "q3"
                return self._reg(t, "P2: CHAVES → ... novaschaves")
            return self._aviso(t, f"FALHA: esperado 'novaschaves'")

        # ── AUTENTICACAO q3→q4→q5→q6→q7 (P3) ─────────────────────
        elif q == "q3":
            if t == "servico_req":
                self.estado = "q4"
                return self._reg(t, "P3: AUTENTICACAO → servico_req ...")
            return self._aviso(t, f"FALHA: esperado 'servico_req'")

        elif q == "q4":
            if t == "servico_ok":
                self.estado = "q5"
                return self._reg(t, "P3: AUTENTICACAO → ... servico_ok ...")
            return self._aviso(t, f"FALHA: esperado 'servico_ok'")

        elif q == "q5":
            if t == "usuario_req":
                self.estado = "q6"
                return self._reg(t, "P3: AUTENTICACAO → ... usuario_req ...")
            return self._aviso(t, f"FALHA: esperado 'usuario_req'")

        elif q == "q6":
            if t == "usuario_ok":
                self._push("SESSION")
                self.estado = "q7"
                return self._reg(t, "P3: AUTENTICACAO → ... usuario_ok  [push SESSION]")
            return self._aviso(t, f"FALHA: esperado 'usuario_ok'")

        # ── SESSION q7 — hub central (P4/P5/P6/P7) ─────────────────
        elif q == "q7":
            topo = self.topo()

            if t == "canal_aberto":
                if topo == "SESSION" or topo.startswith("CHAN"):
                    cid = f"CHAN:{self._chans}"
                    self._chans += 1
                    self._push(cid)
                    self.estado = "q8"
                    return self._reg(t, f"P5/P6: CANAL → canal_aberto ...  [push {cid}]")
                return self._aviso(t, f"canal_aberto inválido com '{topo}' no topo")

            elif t == "canal_fechado":
                if topo.startswith("CHAN"):
                    chan = self._pop()
                    self.estado = "q7"
                    return self._reg(t, f"P5: CANAL → ... canal_fechado  [pop {chan}]")
                return self._aviso(t, f"FALHA: 'canal_fechado' inválido pois não tem canal aberto (topo={topo})")

            elif t == "disconectado":
                if topo == "SESSION":
                    self._pop(); self._pop()   # pop SESSION + pop $
                    self.estado = "q12"
                    self.status = Status.ACEITO
                    return self._reg(t,
                        "P4: SESSAO → CANAL disconectado  [pop SESSION, pop $ → ∅]",aceito=True)

                elif topo.startswith("CHAN"):
                    return self._aviso(t,f"disconectado com canal ainda aberto: {topo}")
                return self._aviso(t, f"FALHA: pilha inesperada: {topo}")

            return self._aviso(t,f"'{t}' inválido em q7 — esperado: canal_aberto, canal_fechado ou disconectado")

        # ── CANAL q8 — aguarda conf/fail (P5/P6) ──────────────────
        elif q == "q8":
            if t == "canal_conf":
                self.estado = "q9"
                return self._reg(t, "P5: CANAL → ... canal_conf REQUISICAO CANAL canal_fechado")

            elif t == "canal_falha":
                if self.topo().startswith("CHAN"):
                    chan = self._pop()
                    self.estado = "q7"
                    return self._reg(t, f"P6: CANAL → canal_aberto canal_falha  [pop {chan}]")
                return self._aviso(t, "canal_falha sem CHANid na pilha")
            return self._aviso(t,f"FALHA: esperado 'canal_conf' ou 'canal_falha'")

        # ── CANAL_ESCOPO q9 — dentro do canal (P5/P7/P8/P9/P10) ──
        elif q == "q9":
            topo = self.topo()
            if t == "requisicao":
                rid = f"REQ:{self._reqs}"
                self._reqs += 1
                self._push(rid)
                self.estado = "q10"
                return self._reg(t, f"P8: REQUISICAO → requisicao dados ...  [push {rid}]")

            elif t == "canal_fechado":
                if topo.startswith("CHAN"):
                    chan = self._pop()
                    self.estado = "q7"
                    return self._reg(t, f"P5: ... canal_fechado  [pop {chan}]")
                return self._aviso(t, f"canal_fechado com req pendente (topo={topo})")

            elif t == "canal_aberto":
                if topo.startswith("CHAN"):
                    cid = f"CHAN:{self._chans}"
                    self._chans += 1
                    self._push(cid)
                    self.estado = "q8"
                    return self._reg(t, f"P5: CANAL aninhado → canal_aberto ...  [push {cid}]")
                return self._aviso(t, f"canal_aberto inválido (topo={topo})")
            return self._aviso(t,
                f"FALHA: esperado 'requisicao', 'canal_aberto' ou 'canal_fechado'")

        # ── REQUISICAO q10 — aguarda dados ou falha (P8/P9) ───────
        elif q == "q10":
            if t == "dados":
                self.estado = "q11"
                return self._reg(t, "P8: REQUISICAO → ... dados REQUISICAO req_finalizada")

            elif t == "req_falha":
                if self.topo().startswith("REQ:"):
                    req = self._pop()
                    self._reqs -= 1
                    self.estado = "q9"
                    return self._reg(t, f"P9: REQUISICAO → ... req_falha ...  [pop {req}]")
                return self._aviso(t, "req_falha sem REQid na pilha")
            return self._aviso(t,f"FALHA: esperado 'dados' ou 'req_falha'")

        # ── DADOS/REQ_ANINHADA q11 (P8 recursivo) ─────────────────
        elif q == "q11":
            if t == "dados":
                self.estado = "q11"
                return self._reg(t, "P8: DADOS_REQ → dados DADOS_REQ")

            elif t == "requisicao":
                rid = f"REQ:{self._reqs}"
                self._reqs += 1
                self._push(rid)
                self.estado = "q10"
                return self._reg(t, f"P8: REQUISICAO aninhada  [push {rid}]")

            elif t == "req_finalizada":
                if self.topo().startswith("REQ:"):
                    req = self._pop()
                    self.estado = "q11"
                    return self._reg(t, f"P8: req_finalizada  [pop {req}]")
                return self._aviso(t, "req_finalizada sem REQid na pilha")

            elif t == "canal_aberto":
                if self.topo().startswith("REQ:") or self.topo().startswith("CHAN:"):
                    cid = f"CHAN:{self._chans}"
                    self._chans += 1
                    self._push(cid)
                    self.estado = "q8"
                    return self._reg(t, f"P5: CANAL dentro de req  [push {cid}]")
                return self._aviso(t, f"canal_aberto inválido (topo={self.topo()})")
            return self._aviso(t,
                f"esperado 'dados', 'requisicao', 'req_finalizada' ou 'canal_aberto'")

        elif q == "q12":
            return self._aviso(t, "sessão já encerrada")

        return self._aviso(t, f"estado desconhecido: {q}")

    def resumo(self) -> str:
        """Imprime o relatório final da sessão com base no estado da pilha."""
        if self.aceito():
            s = cor("✓  SESSÃO ACEITA — pilha vazia", C.GREEN)
        elif self.tem_aviso():
            s = cor(f"⚠  SESSÃO COM AVISOS — estado={self.estado}  "
                    f"pilha=[{self.pilha_str()}]", C.YELLOW)
        else:
            s = cor(f"●  EM ANDAMENTO — estado={self.estado}  "
                    f"pilha=[{self.pilha_str()}]", C.CYAN)
        return f"\n  {'─'*52}\n  {s}\n  Passos APDT: {self._n}\n  {'─'*52}"