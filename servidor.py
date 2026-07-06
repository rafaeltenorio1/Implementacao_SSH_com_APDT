"""
servidor.py — Terminal 3.
"""
import socket, argparse, sys, os
sys.path.insert(0, os.path.dirname(__file__))
from protocolo import C, cor, empacotar, desempacotar, gerar_par_dh, derivar_chave, cifrar, decifrar, APDT

def log(msg, c=C.WHITE): print(f"  {cor('SRV', C.BLUE)}  {cor(msg, c)}")
def secao(t): print(f"\n  {cor('─'*50, C.GRAY)}\n  {cor(t, C.BOLD)}\n  {cor('─'*50, C.GRAY)}\n")

def mostrar_apdt(apdt, token):
    p = apdt.trace[-1] if apdt.trace else None
    if not p: return
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

    apdt = APDT(); fernet = None

    # NOVO: auto-descriptografa
    def recv():
        msg = desempacotar(conn)
        if msg and msg.get("cifrado") and fernet:
            if msg.get("payload"): msg["payload"] = decifrar(fernet, msg["payload"])
            if msg.get("canal"): msg["canal"] = decifrar(fernet, msg["canal"])
        return msg

    # NOVO: auto-criptografa
    def send(tipo, payload="", cifrado=False, canal=""):
        p, c = payload, canal
        if cifrado and fernet:
            if p: p = cifrar(fernet, p)
            if c: c = cifrar(fernet, c)
        conn.sendall(empacotar(tipo, p, cifrado, c))

    def tk(t):
        apdt.processar(t)
        mostrar_apdt(apdt, t)

    try:
        secao("Fase 1 — Troca de Chaves DH")
        msg = recv()
        pub_cli = msg["payload"]
        tk("chavesinit")

        priv_srv, pub_srv = gerar_par_dh()
        fernet = derivar_chave(priv_srv, pub_cli)
        send("chaves_repassadas", pub_srv)
        tk("chaves_repassadas")
        log("Canal cifrado com AES-256 ativo", C.GREEN)

        recv(); tk("novaschaves")
        send("novaschaves")

        secao("Fase 2 — Autenticação")
        recv(); tk("servico_req")
        send("servico_ok"); tk("servico_ok")

        msg = recv(); tk("usuario_req")

        # Agora vem descriptografado da função recv()!
        usuario, senha_rec = msg["payload"].split(":", 1)
        log(f"Credenciais de '{usuario}' recebidas (cifradas)")

        if senha_rec != senha:
            log("Senha incorreta", C.RED)
            send("usuario_falha"); return

        send("usuario_ok")
        tk("usuario_ok")
        log(f"Usuário '{usuario}' autenticado ✓", C.GREEN)

        secao("Fase 3 — Sessão ativa")
        canais_abertos = set()

        while True:
            msg = recv()
            if msg is None: break

            tipo = msg.get("tipo","")
            cid  = msg.get("canal","")
            pay  = msg.get("payload","")

            log(f"← {cor(tipo, C.CYAN)}" + (f"  [{cid}]" if cid else ""))
            tk(tipo)

            if tipo == "canal_aberto":
                canais_abertos.add(cid)
                send("canal_conf", canal=cid, cifrado=True)
                tk("canal_conf")

            elif tipo == "requisicao":
                if cid in canais_abertos:
                    send("dados", "requisição atendida", cifrado=True, canal=cid)
                    tk("dados")
                else:
                    send("req_falha", payload="", cifrado=True, canal=cid)
                    tk("req_falha")

            elif tipo == "req_falha":
                pass

            elif tipo == "dados":
                log(f"  [{cid}] {cor(pay, C.WHITE)}")
                send("dados", f"eco: {pay}", cifrado=True, canal=cid)
                tk("dados")

            elif tipo == "req_finalizada":
                pass

            elif tipo == "canal_fechado":
                canais_abertos.discard(cid)

            elif tipo == "desconectar":
                break

    except Exception as e:
        log(f"Erro: {e}", C.RED)
    finally:
        secao("Resultado")
        print(apdt.resumo())
        conn.close(); srv.close()

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--porta", type=int, default=9000)
    p.add_argument("--senha", default="abc123")
    args = p.parse_args()
    servidor(args.porta, args.senha)