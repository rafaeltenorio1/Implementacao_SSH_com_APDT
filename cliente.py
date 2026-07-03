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
  ──────────────────────────────────────────────────────────────────────
  canal <id>                       Abre canal          ex: canal C0
  fecha <id>                       Fecha canal         ex: fecha C0
  req <id do canal> <recurso>      Requisição          ex: req C0 shell
  finaliza <id>                    Finaliza req        ex: finaliza C0
  desconectar                      Encerra sessão
  ────────────────────────────────────────────────────────────────────── 
"""
# msg <id> <texto>        Envia dados         ex: msg C0 ola mundo
"""
  TESTES DE ERRO:
  invalido <token>        Token fora de ordem (gera aviso, não para)
  sair                    Fecha sem disconectar (pilha não fica vazia)
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
            partes = linha.split(None, 2)
            cmd = partes[0].lower()

            if cmd == "canal":
                if len(partes) < 2:
                    log("Uso: canal <id>", C.YELLOW)
                    continue
                cid = partes[1]
                send_raw({"tipo":"canal_aberto","payload":cid,"canal":cid,"cifrado":False})
                tk("canal_aberto")
                msg = recv()
                if msg:
                    tk(msg["tipo"])
                log(f"Canal {cid} " + ("aberto ✓" if msg["tipo"]=="canal_conf" else "recusado"), C.GREEN if msg.get("tipo")=="canal_conf" else C.RED)

            elif cmd == "fecha":
                if len(partes) < 2:
                    log("Uso: fecha <id>", C.YELLOW)
                    continue
                cid = partes[1]
                send_raw({"tipo":"canal_fechado","payload":cid,"canal":cid,"cifrado":False})
                tk("canal_fechado")

            elif cmd == "req":
                if len(partes) < 3:
                    log("Uso: req <id> <recurso>", C.YELLOW)
                    continue
                cid, recurso = partes[1], partes[2]
                send_raw({"tipo":"requisicao","payload":recurso,"canal":cid,"cifrado":False})
                tk("requisicao")
                msg = recv()
                if msg:
                    tk(msg["tipo"])
                    if msg["tipo"] == "dados" and msg.get("cifrado"):
                        log(f"← {cor(decifrar(fernet, msg['payload']), C.WHITE)}", C.GREEN)

            elif cmd == "finaliza":
                if len(partes) < 2:
                    log("Uso: finaliza <id>", C.YELLOW)
                    continue
                cid = partes[1]
                send_raw({"tipo":"req_finalizada","payload":"","canal":cid,"cifrado":False})
                tk("req_finalizada")

            elif cmd == "msg":
                if len(partes) < 3:
                    log("Uso: msg <id> <texto>", C.YELLOW)
                    continue
                cid, texto = partes[1], partes[2]
                send_raw({"tipo":"dados","payload":cifrar(fernet,texto),"canal":cid,"cifrado":True})
                log(f"→ dados [{cid}] '{texto}' (cifrado)")
                tk("dados")
                msg = recv()
                if msg and msg.get("tipo") == "dados":
                    tk("dados")
                    if msg.get("cifrado"): log(f"← {cor(decifrar(fernet,msg['payload']), C.WHITE)}", C.GREEN)

            elif cmd == "desconectar":
                canais = [s for s in apdt.pilha if s.startswith("CHAN")]
                if canais:
                    log(f"Feche os canais antes: {canais}", C.YELLOW)
                    continue
                send_raw({"tipo":"disconectado","payload":"","cifrado":False})
                tk("disconectado"); break

            elif cmd == "transicao":
                if len(partes) < 2:
                    log("Uso: transicao <token>", C.YELLOW)
                    continue
                tok = partes[1]
                log(f"Testando Transição: {cor(tok, C.RED)}", C.RED)
                send_raw({"tipo":tok,"payload":"","cifrado":False})
                tk(tok)

            elif cmd == "pilha":
                print(f"\n  Estado : {cor(apdt.estado, C.CYAN)}")
                print(f"  Pilha  : [{cor(apdt.pilha_str(), C.PURPLE)}]\n")

            elif cmd == "ajuda":
                print(AJUDA)

            elif cmd == "sair":
                log("Saindo sem disconectar — pilha não ficará vazia", C.RED); break

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