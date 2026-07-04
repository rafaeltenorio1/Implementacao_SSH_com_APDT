"""
servidor.py — Terminal 3.

Uso:
  python servidor.py --porta --senha
"""
import socket, argparse, sys, os
sys.path.insert(0, os.path.dirname(__file__))
from protocolo import C, cor, empacotar, desempacotar, gerar_par_dh, derivar_chave, cifrar, decifrar, APDT

def log(msg, c=C.WHITE): print(f"  {cor('SRV', C.BLUE)}  {cor(msg, c)}")
def secao(t): print(f"\n  {cor('─'*50, C.GRAY)}\n  {cor(t, C.BOLD)}\n  {cor('─'*50, C.GRAY)}\n")

def mostrar_apdt(apdt, token):
    """Exibe o rastro do APDT pelo lado do servidor."""
    p = apdt.trace[-1] if apdt.trace else None
    if not p:
        return
    t_str = cor(token, C.YELLOW)
    if p.aviso:
        print(f"  {cor('APDT', C.GRAY)}  {t_str:<22}  {cor('⚠  ' + p.msg_aviso, C.YELLOW)}")
    elif p.aceito:
        print(f"  {cor('APDT', C.GRAY)}  {t_str:<22}  {cor(apdt.estado, C.CYAN):<14}  pilha=[{cor(apdt.pilha_str(), C.PURPLE)}]  {cor('✓ ACEITO', C.GREEN)}")
    else:
        print(f"  {cor('APDT', C.GRAY)}  {t_str:<22}  {cor(apdt.estado, C.CYAN):<14}  pilha=[{cor(apdt.pilha_str(), C.PURPLE)}]")

def servidor(porta, senha):
    print(f"\n  {cor('SERVIDOR SSH — Terminal 3', C.BOLD)}")
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", porta))
    srv.listen(1)
    print(f"  Aguardando na porta {cor(str(porta), C.YELLOW)}...\n")
    conn, addr = srv.accept()
    log(f"Cliente: {addr[0]}:{addr[1]}", C.GREEN)

    apdt = APDT()
    fernet = None

    def recv():
        return desempacotar(conn)

    def send(tipo, payload="", cifrado=False, canal=""):
        conn.sendall(empacotar(tipo, payload, cifrado, canal))

    def tk(t):
        apdt.processar(t)
        mostrar_apdt(apdt, t)

    try:
        # ── FASE 1: TROCA DE CHAVES ──────────────────────────────
        secao("Fase 1 — Troca de Chaves DH")
        msg = recv()
        if not msg or msg["tipo"] != "chavesinit":
            log("Esperava chavesinit", C.RED)
            return
        pub_cli = msg["payload"]
        tk("chavesinit")

        priv_srv, pub_srv = gerar_par_dh()
        fernet = derivar_chave(priv_srv, pub_cli)
        send("chaves_repassadas", pub_srv)
        tk("chaves_repassadas")
        log("Canal cifrado com AES-256 ativo", C.GREEN)

        msg = recv()
        if not msg or msg["tipo"] != "novaschaves":
            log("Esperava novaschaves", C.RED)
            return
        tk("novaschaves")
        send("novaschaves")

        # ── FASE 2: AUTENTICAÇÃO ─────────────────────────────────
        secao("Fase 2 — Autenticação")
        msg = recv()
        if not msg or msg["tipo"] != "servico_req":
            log("Esperava servico_req", C.RED)
            return
        tk("servico_req")
        send("servico_ok")
        tk("servico_ok")

        msg = recv()
        if not msg or msg["tipo"] != "usuario_req":
            log("Esperava usuario_req", C.RED)
            return
        tk("usuario_req")
        usuario, senha_rec = decifrar(fernet, msg["payload"]).split(":", 1)
        log(f"Credenciais de '{usuario}' recebidas (cifradas)")
        if senha_rec != senha:
            log("Senha incorreta", C.RED)
            send("usuario_falha")
            return
        send("usuario_ok")
        tk("usuario_ok")
        log(f"Usuário '{usuario}' autenticado ✓", C.GREEN)

        # ── FASE 3: SESSÃO ───────────────────────────────────────
        secao("Fase 3 — Sessão ativa")
        log("Aguardando comandos...", C.YELLOW)
        print()
        canais_abertos = set()

        while True:
            msg = recv()
            if msg is None:
                log("Conexão encerrada", C.RED)
                break
            tipo = msg.get("tipo","")
            cid = msg.get("canal","")
            pay  = msg.get("payload","")
            cifr = msg.get("cifrado", False)
            log(f"← {cor(tipo, C.CYAN)}" + (f"  [{cid}]" if cid else ""))
            tk(tipo)

            if tipo == "canal_aberto":
                canais_abertos.add(cid)
                send("canal_conf", canal=cid)
                tk("canal_conf")

            elif tipo == "requisicao":
                if cid in canais_abertos:
                    resp = cifrar(fernet, f"requisição atendida")
                    send("dados", resp, cifrado=True, canal=cid)
                    tk("dados")
                else:
                    # Se houver erro, envia token de falha
                    log(f"Requisição recusada: Canal [{cid}] não está aberto", C.RED)
                    send("req_falha", payload="", cifrado=False, canal=cid)
                    tk("req_falha")

            elif tipo == "req_falha":
                pass  # servidor só confirma, sem resposta extra

            elif tipo == "dados":
                texto = decifrar(fernet, pay) if cifr else pay
                log(f"  [{cid}] {cor(texto, C.WHITE)}")
                send("dados", cifrar(fernet, f"eco: {texto}"), cifrado=True, canal=cid)
                tk("dados")

            elif tipo == "req_finalizada":
                pass  # encerramento da requisição, sem resposta extra

            elif tipo == "canal_fechado":
                canais_abertos.discard(cid)
                pass  # cliente fechou o canal

            elif tipo == "desconectar":
                break

            else:
                log(f"Tipo desconhecido: '{tipo}'", C.YELLOW)

    except Exception as e:
        log(f"Erro: {e}", C.RED)
    finally:
        secao("Resultado")
        print(apdt.resumo())
        conn.close()
        srv.close()

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--porta", type=int, default=9000)
    p.add_argument("--senha", default="abc123")
    args = p.parse_args()
    servidor(args.porta, args.senha)