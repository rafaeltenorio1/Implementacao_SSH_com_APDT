"""
cliente.py — Terminal 1.
"""
import socket, argparse, sys, os
sys.path.insert(0, os.path.dirname(__file__))
from protocolo import C, cor, empacotar, desempacotar, gerar_par_dh, derivar_chave, cifrar, decifrar, APDT

def log(msg, c=C.WHITE): print(f"  {cor('CLI', C.GREEN)}  {cor(msg, c)}")
def secao(t): print(f"\n  {cor('─'*50, C.GRAY)}\n  {cor(t, C.BOLD)}\n  {cor('─'*50, C.GRAY)}\n")

def mostrar_apdt(apdt, token):
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
  abrir req <recurso>     Requisição de recurso
  finalizar req           Finaliza a requisição do topo
  msg <texto>             Envia dados cifrados
  desconectar             Encerra a sessão
  ────────────────────────────────────────────────────
"""

def cliente(host, porta, usuario, senha):
    print(f"\n  {cor('CLIENTE SSH — Terminal 1', C.BOLD)}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try: sock.connect((host, porta))
    except ConnectionRefusedError:
        log(f"Não conectou em {host}:{porta}", C.RED); return

    log(f"Conectado em {host}:{porta}", C.GREEN)
    apdt = APDT(); fernet = None

    # NOVO: auto-descriptografa se flag cifrado=True
    def recv():
        msg = desempacotar(sock)
        if msg and msg.get("cifrado") and fernet:
            if msg.get("payload"): msg["payload"] = decifrar(fernet, msg["payload"])
            if msg.get("canal"): msg["canal"] = decifrar(fernet, msg["canal"])
        return msg

    # NOVO: auto-criptografa se flag cifrado=True
    def send(tipo, payload="", cifrado=False, canal=""):
        p, c = payload, canal
        if cifrado and fernet:
            if p: p = cifrar(fernet, p)
            if c: c = cifrar(fernet, c)
        sock.sendall(empacotar(tipo, p, cifrado, c))

    def tk(t):
        apdt.processar(t)
        mostrar_apdt(apdt, t)

    try:
        secao("Fase 1 — Troca de Chaves DH (automática)")
        priv, pub = gerar_par_dh()
        send("chavesinit", pub)
        tk("chavesinit")
        msg = recv()
        tk("chaves_repassadas")
        fernet = derivar_chave(priv, msg["payload"])
        log("Canal cifrado com AES-256 ativo", C.GREEN)
        send("novaschaves"); tk("novaschaves")
        recv()

        secao("Fase 2 — Autenticação (automática)")
        send("servico_req"); tk("servico_req")
        recv(); tk("servico_ok")
        # Envio de credenciais com flag cifrado=True ativada
        send("usuario_req", f"{usuario}:{senha}", cifrado=True)
        log(f"Credenciais enviadas")
        tk("usuario_req")
        msg = recv()

        if msg["tipo"] == "usuario_falha":
            log("Senha incorreta", C.RED); return

        tk("usuario_ok")
        log(f"Autenticado como '{usuario}' ✓", C.GREEN)

        secao("Fase 3 — Sessão Interativa")
        print(AJUDA)

        while True:
            try: linha = input(f"  {cor('ssh>', C.GREEN)} ").strip()
            except (EOFError, KeyboardInterrupt): break
            if not linha: continue

            partes = linha.split(None, 2)
            if len(partes) >= 2 and partes[0].lower() in ("abrir", "fechar", "finalizar"):
                cmd = partes[0].lower() + " " + partes[1].lower()
                resto = partes[2] if len(partes) > 2 else ""
            else:
                cmd = partes[0].lower()
                resto = " ".join(partes[1:]) if len(partes) > 1 else ""

            def canal_do_topo():
                for s in apdt.pilha:
                    if s.startswith("CHAN:"): return s
                return None

            def req_do_topo():
                return apdt.pilha[0] if apdt.pilha and apdt.pilha[0].startswith("REQ:") else None

            if cmd == "abrir canal":
                cid = f"CHAN:{apdt._chans}"
                # A mágica ocorre aqui: basta passar cifrado=True e o send faz o resto!
                send("canal_aberto", payload=cid, canal=cid, cifrado=True)
                tk("canal_aberto")
                msg = recv()
                if msg:
                    tk(msg["tipo"])
                    chan = canal_do_topo()
                    if msg["tipo"] == "canal_conf": log(f"Canal {cor(chan or cid, C.CYAN)} aberto ✓", C.GREEN)


            elif cmd == "fechar canal":
                topo_atual = apdt.topo()
                # Validação estrita: o topo absoluto da pilha DEVE ser um canal
                if not topo_atual.startswith("CHAN:"):
                    log(f"Aviso: Não é possível fechar o canal. O topo da pilha é '{cor(topo_atual, C.PURPLE)}'.",
                        C.YELLOW)
                    if topo_atual.startswith("REQ:"):
                        log("Finalize a requisição pendente ('finalizar req') antes de fechar o canal.", C.YELLOW)
                    continue
                chan = topo_atual
                log(f"Fechando {cor(chan, C.CYAN)} (topo da pilha)")
                send("canal_fechado", payload=chan, canal=chan, cifrado=True)
                tk("canal_fechado")

            elif cmd == "abrir req":
                if not resto: continue
                chan = canal_do_topo()
                if not chan: continue
                log(f"→ requisicao [{chan}] recurso='{resto}'")
                send("requisicao", payload=resto, canal=chan, cifrado=True)
                tk("requisicao")
                msg = recv()
                if msg:
                    tk(msg["tipo"])
                    if msg["tipo"] == "dados":
                        log(f"← {cor(msg['payload'], C.WHITE)}", C.GREEN)

            elif cmd == "finalizar req":
                req = req_do_topo()
                chan = canal_do_topo()
                if not req: continue
                log(f"Finalizando {cor(req, C.PURPLE)} no canal {cor(chan or '?', C.CYAN)}")
                send("req_finalizada", payload="", canal=chan or "", cifrado=True)
                tk("req_finalizada")

            elif cmd == "msg":
                if not resto: continue
                chan = canal_do_topo()
                if not chan: continue
                log(f"→ dados [{chan}] '{resto}' (cifrado)")
                send("dados", payload=resto, canal=chan, cifrado=True)
                tk("dados")
                msg = recv()
                if msg and msg.get("tipo") == "dados":
                    tk("dados")
                    log(f"← {cor(msg['payload'], C.WHITE)}", C.GREEN)

            elif cmd == "desconectar":
                # Validação estrita do topo da pilha antes de permitir a saída
                if apdt.topo() != "SESSION":
                    log(f"Aviso: Não é possível desconectar. O topo da pilha é '{cor(apdt.topo(), C.PURPLE)}', mas é esperado 'SESSION'.",
                        C.YELLOW)
                    log("Finalize todas as requisições e feche os canais ativos antes de sair.", C.YELLOW)
                    continue
                # Se o topo for SESSION, o envio e o encerramento são permitidos
                send("desconectar", payload="", cifrado=True)
                tk("desconectar")
                break

            elif cmd == "transicao":
                if not resto: continue
                tok = resto.split()[0]
                log(f"Realizando transicao: {cor(tok, C.RED)}", C.RED)
                send(tok, payload="", cifrado=True)
                tk(tok)

            elif cmd == "pilha":
                print(f"\n  Estado : {cor(apdt.estado, C.CYAN)}")
                print(f"  Pilha  : [{cor(apdt.pilha_str(), C.PURPLE)}]\n")
            elif cmd == "ajuda":
                print(AJUDA)

    except Exception as e:
        log(f"Erro: {e}", C.RED)
    finally:
        secao("Resultado"); print(apdt.resumo()); sock.close()

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="localhost")
    p.add_argument("--porta", type=int, default=9001)
    p.add_argument("--usuario", default="joao")
    p.add_argument("--senha", default="abc123")
    args = p.parse_args()
    cliente(args.host, args.porta, args.usuario, args.senha)