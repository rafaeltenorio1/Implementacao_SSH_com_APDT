"""
interceptador.py — Terminal 2 (MitM)
Monitora passivamente a comunicação entre Cliente e Servidor.
"""
import socket, threading, argparse, sys, os, json, struct
sys.path.insert(0, os.path.dirname(__file__))
from protocolo import C, cor

def ler_pacote(sock: socket.socket):
    try:
        cabecalho = b""
        while len(cabecalho) < 4:
            fragmento = sock.recv(4 - len(cabecalho))
            if not fragmento: return None, None
            cabecalho += fragmento
        tamanho = struct.unpack(">I", cabecalho)[0]
        if tamanho == 0 or tamanho > 1_000_000: return None, None
        corpo = b""
        while len(corpo) < tamanho:
            fragmento = sock.recv(tamanho - len(corpo))
            if not fragmento: return None, None
            corpo += fragmento
        return cabecalho + corpo, json.loads(corpo.decode("utf-8"))
    except Exception:
        return None, None

def interceptador(porta_escuta: int, srv_host: str, srv_porta: int):
    print(f"\n{cor('╔' + '═'*50 + '╗', C.YELLOW)}")
    print(cor("║" + "  INTERCEPTADOR MitM  (Terminal 2)".center(50) + "║", C.YELLOW))
    print(f"{cor('╚' + '═'*50 + '╝', C.YELLOW)}\n")
    print(f"  {cor('O QUE VOCÊ VÊ AQUI:', C.BOLD)}")
    print("  • Apenas o tráfego bruto repassado entre as pontas.")
    print(f"  • A confirmação de que os dados estão {cor('CIFRADOS', C.RED)}.\n")

    srv_listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv_listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv_listen.bind(("0.0.0.0", porta_escuta))
    srv_listen.listen(1)

    print(f"  Aguardando cliente na porta {cor(str(porta_escuta), C.YELLOW)}...")
    cli_sock, cli_addr = srv_listen.accept()

    try:
        srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv_sock.connect((srv_host, srv_porta))
    except ConnectionRefusedError:
        print(cor(f"  Servidor não encontrado em {srv_host}:{srv_porta}", C.RED))
        cli_sock.close(); return

    done = threading.Event()
    lock = threading.Lock()

    print(f"\n  {cor('─'*70, C.GRAY)}")
    print(f"  {cor('DIREÇÃO', C.GRAY):<20} {cor('TIPO', C.GRAY):<22} {cor('CONTEÚDO NA REDE', C.GRAY)}")
    print(f"  {cor('─'*70, C.GRAY)}")

    def exibir_trafego(direcao, tipo, payload, cifrado, canal):
        dir_str = cor("CLI → SRV", C.GREEN) if direcao == "c2s" else cor("SRV → CLI", C.BLUE)
        tipo_str = cor(tipo, C.CYAN)

        # Formata o que o MitM consegue ler
        conteudo = ""
        if canal:   conteudo += f"canal={canal[:10]}... " if len(canal)>10 else f"canal={canal} "
        if payload: conteudo += f"pay={payload[:20]}..."  if len(payload)>20 else f"pay={payload}"

        if tipo in {"chavesinit", "chaves_repassadas", "novaschaves"} and payload:
            pay_str = cor(f"[CHAVE DH] {conteudo}", C.ORANGE)
        elif cifrado:
            pay_str = cor(f"[CIFRADO] {conteudo}", C.RED)
        elif conteudo:
            pay_str = cor(f"[EM CLARO] {conteudo}", C.YELLOW)
        else:
            pay_str = cor("[sem conteúdo]", C.GRAY)

        print(f"  {dir_str:<28} {tipo_str:<22} {pay_str}")

    def encaminhar(src, dst, direcao):
        while not done.is_set():
            raw, msg = ler_pacote(src)
            if raw is None: break
            with lock:
                exibir_trafego(direcao, msg.get("tipo","?"), msg.get("payload",""), msg.get("cifrado",False), msg.get("canal",""))
            try: dst.sendall(raw)
            except Exception: break
        done.set()
        try: dst.shutdown(socket.SHUT_WR)
        except Exception: pass

    threading.Thread(target=encaminhar, args=(cli_sock, srv_sock, "c2s"), daemon=True).start()
    threading.Thread(target=encaminhar, args=(srv_sock, cli_sock, "s2c"), daemon=True).start()

    done.wait()
    cli_sock.close(); srv_sock.close(); srv_listen.close()
    print(f"\n  {cor('Sessão encerrada.', C.BOLD)}\n")

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--escuta", type=int, default=9001)
    p.add_argument("--servidor-host", default="localhost")
    p.add_argument("--servidor-porta", type=int, default=9000)
    args = p.parse_args()
    interceptador(args.escuta, args.servidor_host, args.servidor_porta)