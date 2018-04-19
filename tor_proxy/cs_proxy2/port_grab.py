import socket
import time


def main():
    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    c.bind(('10.0.0.4', 1234))
    while True:
        c.connect(('1.2.3.4', 22222))
    print "@@@"
    while True:
        time.sleep(2)

if __name__ == '__main__':
    main()