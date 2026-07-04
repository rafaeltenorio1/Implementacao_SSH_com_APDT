"""
cliente.py — Terminal 1.

Realiza KEX e AUTH automaticamente, depois entra em modo interativo.

Uso:
  python cliente.py --porta 9000 --usuario --senha
"""
import socket, argparse, sys, os, json, struct
sys.path.insert(0, os.path.dirname(__file__))
from protocolo import C, cor, empacotar, desempacotar, gerar_par_dh, derivar_chave, cifrar, decifrar, APDT

def log(msg, c=C.WHITE): print(f"  {cor('CLI', C.GREEN)}  {cor(msg, c)}")
def secao(t): print(f"\n  {cor('─'*50, C.GRAY)}\n  {cor(t, C.BOLD)}\n  {cor('─'*50, C.GRAY)}\n")

def mostrar_apdt(apdt, token):
    """Exibe o rastro do autômato de pilha em tempo real no terminal do cliente."""
    p = apdt.trace[-1] if apdt.trace else None
    if not p: return
    t_str = cor(token, C.YELLOW)
    if p.aviso:
        print(f"  {cor('APDT:', C.GRAY)}  {t_str:<22}  {cor('⚠  ' + p.msg_aviso, C.YELLOW)}")
    elif p.aceito:
        print(f"  {cor('APDT:', C.GRAY)}  {t_str:<22}  {cor(apdt.estado, C.CYAN):<14}  pilha=[{cor(apdt.pilha_str(), C.PURPLE)}]  {cor('✓ ACEITO', C.GREEN)}")
    else:
        print(f"  {cor('APDT:', C.GRAY)}  {t_str:<22}  {cor(apdt.estado, C.CYAN):<14}  pilha=[{cor(apdt.pilha_str(), C.PURPLE)}]")

AJUDA = """
    COMANDOS
  ────────────────────────────────────────────────────
  abrir canal             Abre um novo canal
  fechar canal            Fecha o canal do topo da pilha
  abrir req <recurso>     Requisição de recurso  ex: abrir req shell
  fechar req              Finaliza a requisição do topo
  msg <texto>             Envia dados cifrados   ex: msg ola mundo
  desconectar             Encerra a sessão
  ────────────────────────────────────────────────────
 
"""
"""
  TESTES DE ERRO:
  transicao <token>       Token fora de ordem (gera aviso, não para)
  pilha                   Mostra estado atual da pilha
  ──────────────────────────────────────────────────────────────────────
"""

def cliente(host, porta, usuario, senha):
    print(f"\n  {cor('CLIENTE SSH — Terminal 1', C.BOLD)}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((host, porta))
    except ConnectionRefusedError:
        log(f"Não conectou em {host}:{porta} — inicie servidor e interceptador", C.RED); return

    log(f"Conectado em {host}:{porta}", C.GREEN)
    apdt = APDT(); fernet = None

    def recv():
        return desempacotar(sock)

    def send_raw(d):
        raw = json.dumps(d).encode(); sock.sendall(struct.pack(">I", len(raw)) + raw)

    def send(tipo, payload="", cifrado=False, canal=""):
        sock.sendall(empacotar(tipo, payload, cifrado, canal))

    def tk(t):
        apdt.processar(t)
        mostrar_apdt(apdt, t)

    try:
        # ── FASE 1: TROCA DE CHAVES (automática) ─────────────────
        secao("Fase 1 — Troca de Chaves DH (automática)")
        priv, pub = gerar_par_dh()
        send("chavesinit", pub)
        tk("chavesinit")
        msg = recv()
        if not msg or msg["tipo"] != "chaves_repassadas":
            log("Esperava chaves_repassadas", C.RED)
            return
        tk("chaves_repassadas")
        fernet = derivar_chave(priv, msg["payload"])
        log("Canal cifrado com AES-256 ativo", C.GREEN)
        send("novaschaves"); tk("novaschaves")
        recv()

        # ── FASE 2: AUTENTICAÇÃO (automática) ────────────────────
        secao("Fase 2 — Autenticação (automática)")
        send("servico_req")
        tk("servico_req")
        recv()
        tk("servico_ok")
        send("usuario_req", cifrar(fernet, f"{usuario}:{senha}"), cifrado=True)
        log(f"Credenciais enviadas")
        tk("usuario_req")
        msg = recv()
        if not msg:
            log("Sem resposta", C.RED)
            return

        if msg["tipo"] == "usuario_falha":
            log("Senha incorreta", C.RED)
            return

        tk("usuario_ok")
        log(f"Autenticado como '{usuario}' ✓", C.GREEN)

        # ── FASE 3: SESSÃO INTERATIVA ─────────────────────────────
        secao("Fase 3 — Sessão Interativa")
        print(AJUDA)

        while True:
            try:
                linha = input(f"  {cor('ssh>', C.GREEN)} ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not linha:
                continue
            # Reconhece comandos de duas palavras: "abrir canal", "fechar req", etc.
            partes = linha.split(None, 2)
            if len(partes) >= 2 and partes[0].lower() in ("abrir", "fechar", "finalizar"):
                cmd = partes[0].lower() + " " + partes[1].lower()
                resto = partes[2] if len(partes) > 2 else ""
            else:
                cmd = partes[0].lower()
                resto = " ".join(partes[1:]) if len(partes) > 1 else ""

            def canal_do_topo():
                """O canal ativo é sempre o CHANid mais próximo do topo."""
                for s in apdt.pilha:
                    if s.startswith("CHAN:"): return s
                return None

            def req_do_topo():
                """A requisição ativa é o REQid no topo (se existir)."""
                return apdt.pilha[0] if apdt.pilha and apdt.pilha[0].startswith("REQ:") else None

            if cmd == "abrir canal":
                # ID gerado automaticamente pelo APDT (CHAN:0, CHAN:1...)
                cid = f"CHAN:{apdt._chans}"
                send_raw({"tipo": "canal_aberto", "payload": cid, "canal": cid, "cifrado": False})
                tk("canal_aberto")
                msg = recv()
                if msg:
                    tk(msg["tipo"])
                    chan = canal_do_topo()
                    if msg["tipo"] == "canal_conf":
                        log(f"Canal {cor(chan or cid, C.CYAN)} aberto ✓", C.GREEN)
                    else:
                        log("Canal recusado pelo servidor", C.RED)

            elif cmd == "fechar canal":
                chan = canal_do_topo()
                if not chan:
                    log("Nenhum canal aberto para fechar", C.YELLOW);
                    continue
                log(f"Fechando {cor(chan, C.CYAN)} (topo da pilha)")
                send_raw({"tipo": "canal_fechado", "payload": chan, "canal": chan, "cifrado": False})
                tk("canal_fechado")


            elif cmd == "abrir req":
                if not resto:
                    log("Uso: abrir req <recurso>   ex: abrir req shell", C.YELLOW);
                    continue
                recurso = resto
                chan = canal_do_topo()
                if not chan:
                    log("Abra um canal antes de fazer requisições", C.YELLOW);
                    continue
                log(f"→ requisicao [{chan}] recurso='{recurso}'")
                send_raw({"tipo": "requisicao", "payload": recurso, "canal": chan, "cifrado": False})
                tk("requisicao")
                msg = recv()
                if msg:
                    tk(msg["tipo"])
                    if msg["tipo"] == "dados" and msg.get("cifrado"):
                        log(f"← {cor(decifrar(fernet, msg['payload']), C.WHITE)}", C.GREEN)

            elif cmd == "finalizar req":
                req = req_do_topo()
                chan = canal_do_topo()
                if not req:
                    log("Nenhuma requisição aberta para finalizar", C.YELLOW)
                    continue
                log(f"Finalizando {cor(req, C.PURPLE)} no canal {cor(chan or '?', C.CYAN)}")
                send_raw({"tipo": "req_finalizada", "payload": "", "canal": chan or "", "cifrado": False})
                tk("req_finalizada")


            elif cmd == "msg":
                if not resto:
                    log("Uso: msg <texto>   ex: msg ola mundo", C.YELLOW);
                    continue
                chan = canal_do_topo()
                if not chan:
                    log("Abra um canal antes de enviar dados", C.YELLOW);
                    continue
                log(f"→ dados [{chan}] '{resto}' (cifrado)")
                send_raw({"tipo": "dados", "payload": cifrar(fernet, resto), "canal": chan, "cifrado": True})
                tk("dados")
                msg = recv()
                if msg and msg.get("tipo") == "dados":
                    tk("dados")
                    if msg.get("cifrado"):
                        log(f"← {cor(decifrar(fernet, msg['payload']), C.WHITE)}", C.GREEN)


            elif cmd == "desconectar":
                canais = [s for s in apdt.pilha if s.startswith("CHAN")]
                if canais:
                    log(f"Feche os canais antes: {canais}", C.YELLOW)
                    continue
                send_raw({"tipo":"desconectar","payload":"","cifrado":False})
                tk("desconectar")
                break


            elif cmd == "transicao":
                if not resto:
                    log("Uso: transicao <token>", C.YELLOW);
                    continue
                tok = resto.split()[0]
                log(f"Realizando transicao: {cor(tok, C.RED)}", C.RED)
                send_raw({"tipo": tok, "payload": "", "cifrado": False})
                tk(tok)
                log("Sistema continua — aviso registrado, não encerrado", C.YELLOW)


            elif cmd == "pilha":
                print(f"\n  Estado : {cor(apdt.estado, C.CYAN)}")
                print(f"  Pilha  : [{cor(apdt.pilha_str(), C.PURPLE)}]\n")

            elif cmd == "ajuda":
                print(AJUDA)

            else:
                log(f"Comando desconhecido: '{cmd}' (ajuda para ver opções)", C.YELLOW)

    except Exception as e:
        log(f"Erro: {e}", C.RED)
        import traceback; traceback.print_exc()
    finally:
        secao("Resultado"); print(apdt.resumo()); sock.close()

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--host",    default="localhost")
    p.add_argument("--porta",   type=int, default=9001, help="9001=interceptador, 9000=direto")
    p.add_argument("--usuario", default="joao")
    p.add_argument("--senha",   default="abc123")
    args = p.parse_args()
    cliente(args.host, args.porta, args.usuario, args.senha)