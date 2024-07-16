#!/usr/bin/env python3

import argparse
import base64
import urllib.parse
import ipaddress

def ip_to_decimal(ip):
    try:
        return int(ipaddress.ip_address(ip))
    except ValueError:
        return "Invalid IP address"

def ip_to_binary(ip):
    try:
        return '.'.join(f'{int(octet):08b}' for octet in ip.split('.'))
    except ValueError:
        return "Invalid IP address"

def ip_to_hexadecimal(ip):
    try:
        return '.'.join(f'{int(octet):02x}' for octet in ip.split('.'))
    except ValueError:
        return "Invalid IP address"

def decimal_to_ip(decimal):
    try:
        return str(ipaddress.ip_address(int(decimal)))
    except ValueError:
        return "Invalid decimal value"

def binary_to_ip(binary):
    try:
        binary = binary.replace('.', '')
        return str(ipaddress.ip_address(int(binary, 2)))
    except ValueError:
        return "Invalid binary value"

def decimal_ip_to_binary(decimal):
    try:
        return ip_to_binary(decimal_to_ip(decimal))
    except ValueError:
        return "Invalid decimal value"

def binary_ip_to_decimal(binary):
    try:
        binary = binary.replace('.', '')
        return int(binary, 2)
    except ValueError:
        return "Invalid binary value"

def binary_ip_to_hexadecimal(binary):
    try:
        return ip_to_hexadecimal(binary_to_ip(binary))
    except ValueError:
        return "Invalid binary value"

def decimal_ip_to_hexadecimal(decimal):
    try:
        return ip_to_hexadecimal(decimal_to_ip(decimal))
    except ValueError:
        return "Invalid decimal value"

def hexadecimal_ip_to_decimal(hex_ip):
    try:
        hex_ip = hex_ip.replace('.', '')
        return int(hex_ip, 16)
    except ValueError:
        return "Invalid hexadecimal value"

def hexadecimal_ip_to_binary(hex_ip):
    try:
        return ip_to_binary(decimal_to_ip(hexadecimal_ip_to_decimal(hex_ip)))
    except ValueError:
        return "Invalid hexadecimal value"

def url_encode(string):
    return urllib.parse.quote(string)

def url_decode(string):
    return urllib.parse.unquote(string)

def base64_encode(string):
    return base64.b64encode(string.encode()).decode()

def base64_decode(string):
    try:
        return base64.b64decode(string).decode()
    except (ValueError, base64.binascii.Error):
        return "Invalid Base64 string"

def main():
    parser = argparse.ArgumentParser(description="Conversion tool for IP addresses, URL encoding/decoding, and Base64 encoding/decoding")

    parser.add_argument("-d", "--ip2dec", type=str, help="Convert IP address to Decimal")
    parser.add_argument("-b", "--ip2bin", type=str, help="Convert IP address to Binary (formatted)")
    parser.add_argument("-x", "--ip2hex", type=str, help="Convert IP address to Hexadecimal (formatted)")
    parser.add_argument("-i", "--dec2ip", type=int, help="Convert Decimal to IP address (formatted)")
    parser.add_argument("-B", "--bin2ip", type=str, help="Convert Binary to IP address (formatted)")
    parser.add_argument("-D", "--decip2bin", type=int, help="Convert Decimal IP address to Binary (formatted)")
    parser.add_argument("-a", "--binip2dec", type=str, help="Convert Binary IP address to Decimal (formatted)")
    parser.add_argument("-H", "--binip2hex", type=str, help="Convert Binary IP address to Hexadecimal (formatted)")
    parser.add_argument("-X", "--decip2hex", type=int, help="Convert Decimal IP address to Hexadecimal (formatted)")
    parser.add_argument("-A", "--hexip2dec", type=str, help="Convert Hexadecimal IP address to Decimal (formatted)")
    parser.add_argument("-I", "--hexip2bin", type=str, help="Convert Hexadecimal IP address to Binary (formatted)")
    parser.add_argument("-e", "--urlenc", type=str, help="URL Encode a string")
    parser.add_argument("-u", "--urldec", type=str, help="URL Decode a string")
    parser.add_argument("-E", "--b64enc", type=str, help="Base64 Encode a string")
    parser.add_argument("-U", "--b64dec", type=str, help="Base64 Decode a string")
    parser.add_argument("-c", "--collab", type=str, help="Combine multiple conversions (e.g., -c db for IP to Decimal and Binary)")

    args = parser.parse_args()

    if args.collab:
        for flag in args.collab:
            if flag == 'd' and args.ip2dec:
                print(f"Decimal: {ip_to_decimal(args.ip2dec)}")
            elif flag == 'b' and args.ip2bin:
                print(f"Binary: {ip_to_binary(args.ip2bin)}")
            elif flag == 'x' and args.ip2hex:
                print(f"Hexadecimal: {ip_to_hexadecimal(args.ip2hex)}")
            elif flag == 'i' and args.dec2ip:
                print(f"IP: {decimal_to_ip(args.dec2ip)}")
            elif flag == 'B' and args.bin2ip:
                print(f"IP: {binary_to_ip(args.bin2ip)}")
            elif flag == 'D' and args.decip2bin:
                print(f"Binary: {decimal_ip_to_binary(args.decip2bin)}")
            elif flag == 'a' and args.binip2dec:
                print(f"Decimal: {binary_ip_to_decimal(args.binip2dec)}")
            elif flag == 'H' and args.binip2hex:
                print(f"Hexadecimal: {binary_ip_to_hexadecimal(args.binip2hex)}")
            elif flag == 'X' and args.decip2hex:
                print(f"Hexadecimal: {decimal_ip_to_hexadecimal(args.decip2hex)}")
            elif flag == 'A' and args.hexip2dec:
                print(f"Decimal: {hexadecimal_ip_to_decimal(args.hexip2dec)}")
            elif flag == 'I' and args.hexip2bin:
                print(f"Binary: {hexadecimal_ip_to_binary(args.hexip2bin)}")
            elif flag == 'e' and args.urlenc:
                print(f"URL Encoded: {url_encode(args.urlenc)}")
            elif flag == 'u' and args.urldec:
                print(f"URL Decoded: {url_decode(args.urldec)}")
            elif flag == 'E' and args.b64enc:
                print(f"Base64 Encoded: {base64_encode(args.b64enc)}")
            elif flag == 'U' and args.b64dec:
                print(f"Base64 Decoded: {base64_decode(args.b64dec)}")
            else:
                print(f"Unknown shorthand flag: {flag}")
    else:
        if args.ip2dec:
            print(ip_to_decimal(args.ip2dec))
        elif args.ip2bin:
            print(ip_to_binary(args.ip2bin))
        elif args.ip2hex:
            print(ip_to_hexadecimal(args.ip2hex))
        elif args.dec2ip:
            print(decimal_to_ip(args.dec2ip))
        elif args.bin2ip:
            print(binary_to_ip(args.bin2ip))
        elif args.decip2bin:
            print(decimal_ip_to_binary(args.decip2bin))
        elif args.binip2dec:
            print(binary_ip_to_decimal(args.binip2dec))
        elif args.binip2hex:
            print(binary_ip_to_hexadecimal(args.binip2hex))
        elif args.decip2hex:
            print(decimal_ip_to_hexadecimal(args.decip2hex))
        elif args.hexip2dec:
            print(hexadecimal_ip_to_decimal(args.hexip2dec))
        elif args.hexip2bin:
            print(hexadecimal_ip_to_binary(args.hexip2bin))
        elif args.urlenc:
            print(url_encode(args.urlenc))
        elif args.urldec:
            print(url_decode(args.urldec))
        elif args.b64enc:
            print(base64_encode(args.b64enc))
        elif args.b64dec:
            print(base64_decode(args.b64dec))
        else:
            parser.print_help()

if __name__ == "__main__":
    main()
