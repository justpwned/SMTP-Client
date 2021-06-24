#!/usr/bin/env python3
import io
import ssl
import sys
import socket
import argparse
import base64
import re

VERBOSE = False


def connect_to_server(hostname, port):
    """Returns ready to use ssl socket"""
    ssl_context = ssl.create_default_context()
    ssl_socket = None
    for res in socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM, 0, 0):
        family, socktype, proto, canonname, address = res
        try:
            clientsocket = socket.socket(family, socktype, proto)
            ssl_socket = ssl_context.wrap_socket(clientsocket, server_hostname=hostname)
        except OSError:
            ssl_socket = None
            continue

        try:
            ssl_socket.connect(address)
        except OSError:
            ssl_socket.close()
            clientsocket.close()
            ssl_socket = None
            continue

        clientsocket.close()
        break

    if ssl_socket is None:
        print(f"Could not open a socket")
        sys.exit(1)

    return ssl_socket


def recv_message(sock, length=4096):
    """Receive utf-8 decoded message"""
    reply = sock.recv(length).decode().rstrip('\r\n')

    if VERBOSE:
        print(reply)

    return int(reply[:3]), reply


def send_message(sock, message, encode=True):
    """Send message automatically terminated with CRLF"""
    if encode:
        message = message.encode()

    if not message.endswith(b'\r\n'):
        message += b'\r\n'

    sock.sendall(message)


def exit_if(cond, message, exit_code=1):
    if cond:
        print(message)
        sys.exit(exit_code)


def strtob64(string):
    """Returns base64 encoded string"""
    return base64.b64encode(string.encode())


def auth(s, sender_address):
    password_prompt = 'Password: '
    while True:
        send_message(s, 'AUTH LOGIN')
        rc, message = recv_message(s)
        exit_if(rc != 334, message)

        base64_sender_address = strtob64(sender_address)
        send_message(s, base64_sender_address, encode=False)
        rc, message = recv_message(s)
        exit_if(rc != 334, message)

        password = input(password_prompt)

        base64_password = strtob64(password)
        send_message(s, base64_password, encode=False)
        rc, message = recv_message(s)

        if rc != 235:
            print(message)
            # Application-specific password is required

        if rc == 235:
            break


def set_recipients(s, sender_address, recips):
    send_message(s, f'MAIL FROM:<{sender_address}>')
    rc, message = recv_message(s)

    if rc == 530:
        print('Authentication required')
        return False

    exit_if(rc != 250, message)

    for r in recips:
        send_message(s, f'RCPT TO:<{r}>')
        rc, message = recv_message(s)

        if rc != 250:
            print(f'Something wrong with: {r}')

    return True


def send_email(s, email_message):
    send_message(s, 'DATA')
    rc, message = recv_message(s)
    exit_if(rc != 354, message)

    email_message += '\r\n.\r\n'
    send_message(s, email_message)
    rc, message = recv_message(s)

    exit_if(rc != 250, message)
    print('Email has been successfully sent!')


def send_greetings(s):
    host_fqdn = socket.getfqdn('')
    send_message(s, f'HELO {host_fqdn}')
    rc, message = recv_message(s)
    exit_if(rc != 250, message)


def stop_communication(s):
    send_message(s, 'QUIT')


def extract_sender_and_recips(email_message):
    header = ''
    str_stream = io.StringIO(email_message)

    sender = ''
    recips = []

    # For simplicity sake we are just lookoing for email addresses wrapped in <>
    email_regex = r'<([^@]+@[^@]+\.[^@]+)>'
    reg = re.compile(email_regex)
    while True:
        header = str_stream.readline()
        try:
            name, content = header.split(':')
        except Exception as ex:
            break

        name_casefold = name.casefold()

        if name_casefold == 'from':
            sender = reg.search(content)
            if sender is None:
                raise Exception('Sender has not been specified')
            sender = sender.group(1)
        elif name_casefold in ('to', 'cc'):
            res = reg.findall(content)
            if len(res) == 0 and name_casefold == 'to':
                raise Exception('Recipients have not been specified')

            recips.extend(res)

    return sender, recips


def read_email_from_file(file):
    if file == sys.stdin:
        print('Enter email message. Press Ctrl-d to send email when done.')

    email_message = ''
    while True:
        line = file.readline()
        if len(line) == 0:
            break
        email_message += line

    return email_message


def start_communication(s, email_message_file):
    rc, message = recv_message(s)
    exit_if(rc != 220, message)

    send_greetings(s)

    email_message = read_email_from_file(email_message_file)
    sender, recips = extract_sender_and_recips(email_message)

    if not set_recipients(s, sender, recips):
        auth(s, sender)

    set_recipients(s, sender, recips)

    send_email(s, email_message)


def is_vaild_email(string):
    return re.fullmatch(r'[^@]+@[^@]+\.[^@]+', string) is not None


def parse_args():
    def check_valid_email(string):
        if not is_vaild_email(string):
            raise argparse.ArgumentTypeError(f'{string} is not a valid e-mail address')
        return string

    parser = argparse.ArgumentParser(description='Simple SMTP client')
    parser.add_argument('server', help='smtp server address')
    parser.add_argument('port', type=int, help='smtp server listening port')
    parser.add_argument('sender', type=check_valid_email ,help='sender e-mail address')
    parser.add_argument('-v', '--verbose', help='increase output verbosity', action='store_true')
    parser.add_argument('-f', '--file',
                        help='read composed e-mail message from a file. If not specified, read standard input',
                        type=argparse.FileType('r'), default=sys.stdin)
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    VERBOSE = args.verbose

    ssl_sock = connect_to_server(args.server, args.port)

    with ssl_sock:
        start_communication(ssl_sock, args.file)
        stop_communication(ssl_sock)
