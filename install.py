#!/usr/bin/env python3
# DESCRIPTION Installs and configures wireguard on an ubuntu machine with UFW already installed
# DESCRIPTION Uses systemd wg-quick service
# DESCRIPTION Make sure the server is accessible with ufw enabled before running this script

import subprocess
import shlex
import os
import pwd
import grp
import shutil
import time
import re
import random
import ubuntuutils;
import ubuntuutils.uu_io
from ubuntuutils.uu_run_command_container import RCC
import json


def main():
   #region INIT
   PATH_CONF = os.path.realpath("./config.private.json")
   PATH_CONF_TEMPLATE = os.path.realpath("./config.template.json")
   if not os.path.exists(PATH_CONF):
      if not os.path.exists(PATH_CONF_TEMPLATE):
         raise Exception(f"Template config file missing: {PATH_CONF_TEMPLATE}")
      shutil.copyfile(PATH_CONF_TEMPLATE, PATH_CONF)
      print(f"Fill out {PATH_CONF}, then run this app again.")
      return 0

   #read config
   ubuntuutils.uu_run_command_container.RCC
   conf = json.loads(ubuntuutils.uu_io.file_read(PATH_CONF))
   SERVER_ADDR = str(conf["server_address"])
   SERVER_PORT = int(conf["server_port"])
   SERVER_PEER_COUNT = int(conf["server_peer_count"])
   INTERFACE = str(conf["default_interface"])
   print(f"SERVER CREATION DATA: ")
   print(f"  -> SERVER_ADDR       \"{SERVER_ADDR}\"")
   print(f"  -> SERVER_PORT       \"{SERVER_PORT}\"")
   print(f"  -> SERVER_PEER_COUNT \"{SERVER_PEER_COUNT}\"")
   print(f"  -> INTERFACE         \"{INTERFACE}\"")
   #endregion

   # Install Wireguard
   if RCC("dpkg -l wireguard", True).return_code != 0:
      print(f"Wireguard is not installed")
      RCC("apt install wireguard -y").Check()
   else:
      print(f"Wireguard is installed -> wg down")
      RCC("wg-quick down wg0")
   
   # Install qrencode
   if RCC("dpkg -l qrencode", True).return_code != 0:
      print(f"qrencode is not installed")
      RCC("apt install qrencode -y").Check()
   
   # FIREWALL (UFW)
   if RCC("dpkg -l ufw", True).return_code != 0:
      raise Exception("THIS SCRIPT ONLY WORKS WITH UFW - missing")
   RCC(f"bash -c 'yes | ufw enable'")
   RCC(f"ufw delete allow {SERVER_PORT}").Check()
   RCC(f"ufw allow {SERVER_PORT} comment \"Wireguard\"").Check()
   
   # region SYSCTL
   # Read sysctl config 
   sysctl_path = "/etc/sysctl.conf"
   if not os.path.exists(sysctl_path):
      raise Exception(f"missing: \"{sysctl_path}\"")
   sysctl_contents = ubuntuutils.uu_io.file_read(sysctl_path)
   any_change = False
   # Write forwarding rules: IPv4
   if re.search(r"^ \s* net\.ipv4\.ip_forward \s* = \s* 1 \s* $", sysctl_contents, re.M | re.X) == None:
      sysctl_contents += "\n" + "net.ipv4.ip_forward = 1"
      any_change = True
   # Write forwarding rules: IPv6
   if re.search(r"^ \s* net\.ipv6\.conf\.all\.forwarding \s* = \s* 1 \s* $", sysctl_contents, re.M | re.X) == None:
      sysctl_contents += "\n" + "net.ipv6.conf.all.forwarding = 1"
      any_change = True
      
   if any_change:
      ubuntuutils.uu_io.file_write_utf8(sysctl_path, sysctl_contents)
      print(f"Wrote new sysctl config")
      RCC("sysctl -p").Check()
   #endregion
   
   # check provided interface in defaults
   iface_cmd = RCC("ip route list default", True).Check()
   if INTERFACE not in iface_cmd.std_out: 
      raise Exception(f"No such default interface: \"{INTERFACE}\"")
   
   # GRAB DNS
   dns_ip_list = RCC(f"resolvectl dns {INTERFACE}").Check().std_out
   dns_ip_list_match = re.match(r"Link \s* \d \s* \( [^\)]+ \)\:\s* (?P<di> .+? ) $", dns_ip_list, re.X | re.M)
   dns_ip_list = ", ".join( dns_ip_list_match.group("di").split(" ") )
   print(f"DNS IP LIST: \"{dns_ip_list}\"")
   
   #region Configure Wireguard
   RCC("systemctl stop wg-quick@wg0")
   wireguard_path = "/etc/wireguard"
   if not os.path.exists(wireguard_path):
      raise Exception(f"wireguard folder missing: {wireguard_path}")
   print(f"Removing contents of \"{wireguard_path}\" directory...")
   ubuntuutils.uu_io.clear_directory(wireguard_path)
   
   # Paths for level 0 items: conf, wireguard private, public keys
   conf_path = os.path.join(wireguard_path, "wg0.conf") # CONF DIR IS COMPLETELY REMOVED ON EVERY RUN
   private_key_path = os.path.join(wireguard_path, "private.key")
   public_key_path = os.path.join(wireguard_path, "public.key")
   # Write private and public keys
   private_key: str = RCC("wg genkey").Check().std_out.strip()
   public_key: str = RCC(f"bash -c 'echo \"{private_key}\" | wg pubkey'").Check().std_out.strip()
   ubuntuutils.uu_io.file_write_utf8(path=private_key_path, contents=private_key, permission_bits=0o600)
   ubuntuutils.uu_io.file_write_utf8(path=public_key_path, contents=public_key, permission_bits=0o600)
   print(f"SRV Private Key: {re.sub('.', '*', private_key)} | SRV Public Key: {public_key}")
   
   # ip_v4_str.PEER_NUM for ip generation
   ip_v4_str = "10." + ".".join( str(random.randint(0, 255)) for _ in range(2) )
   # String of the form fd0d:cd54:a67c -> ip_v6_str::PEER_NUM for ip generation
   ip_v6_str = "fd00:" + ':'.join( [ ''.join(random.choices('0123456789abcdef', k=4)) for _ in range(2) ] )
   
   wg0_conf = f"""
      [Interface]
      PrivateKey = {private_key}
      Address = {ip_v4_str}.1/24, {ip_v6_str}::1/64
      ListenPort = {SERVER_PORT}
      SaveConfig = true
      
      PostUp = ufw route allow in on wg0 out on {INTERFACE}
      PostUp = iptables -t nat -I POSTROUTING -o {INTERFACE} -j MASQUERADE
      PostUp = ip6tables -t nat -I POSTROUTING -o {INTERFACE} -j MASQUERADE
      
      PreDown = ufw route delete allow in on wg0 out on {INTERFACE}
      PreDown = iptables -t nat -D POSTROUTING -o {INTERFACE} -j MASQUERADE
      PreDown = ip6tables -t nat -D POSTROUTING -o {INTERFACE} -j MASQUERADE
   """
   wg0_conf = "\n".join( [l.strip() for l in wg0_conf.splitlines()] ).strip()
   wg0_conf_print= "\n".join(f"   CONF>  {l}" for l in wg0_conf.replace(private_key, "...PRIVATE_KEY...").splitlines())
   print(f"Writing config: \n{wg0_conf_print}")
   ubuntuutils.uu_io.file_write_utf8(path=conf_path, contents=wg0_conf)
   
  
   #endregion
   
   #region Configure Wireguard Peers
   for i in range(1, SERVER_PEER_COUNT + 1, 1):
      peer_dir = f"/etc/wireguard/peer{i}"
      peer_conf_path = os.path.join(peer_dir, f"peer{i}-wg0.conf")
      peer_private_key_path = os.path.join(peer_dir, f"peer{i}-private.key")
      peer_public_key_path = os.path.join(peer_dir, f"peer{i}-public.key")
      peer_conf_qr_path = os.path.join(peer_dir, f"peer{i}-conf.qr.ascii.txt")
      
      print(f"PEER {i}: creating")
      os.mkdir(peer_dir)
      
      # Public, Private keys
      peer_private_key = RCC("wg genkey").Check().std_out.strip()
      peer_public_key = RCC(f"bash -c 'echo \"{peer_private_key}\" | wg pubkey'").Check().std_out.strip()
      peer_ip4 = f"{ip_v4_str}.{(i+1)}"
      peer_ip6 = f"{ip_v6_str}::{(i+1)}"
      ubuntuutils.uu_io.file_write_utf8(path=peer_private_key_path, contents=peer_private_key, permission_bits=0o600)
      ubuntuutils.uu_io.file_write_utf8(path=peer_public_key_path, contents=peer_public_key, permission_bits=0o600)
      
      # Conf with dns
      # Note: 0.0.0.0/0, ::/0 means all traffic will must go through the vpn connection
      # Not specifying the server's dns will cause an ip leak
      # 0.0.0.0/0, ::/0 also means that the kill switch feature becomes active
      peer_conf = f"""
         [Interface]
         PrivateKey = {peer_private_key}
         Address = {peer_ip4}/24, {peer_ip6}/64
         DNS = {dns_ip_list}
         
         [Peer]
         PublicKey = {public_key}
         AllowedIPs = 0.0.0.0/0, ::/0
         Endpoint = {SERVER_ADDR}:{SERVER_PORT}
      """
      peer_conf = "\n".join( [l.strip() for l in peer_conf.splitlines()] ).strip()
      peer_conf_print= "\n".join(f"   CONF (P)>  {l}" for l in peer_conf.replace(private_key, "...PRIVATE_KEY...").splitlines())
      print(f"Writing config: \n{peer_conf_print}")
      ubuntuutils.uu_io.file_write_utf8(path=peer_conf_path, contents=peer_conf, permission_bits=0o600)
      
      RCC(f"wg set wg0 peer {peer_public_key} allowed-ips {peer_ip4},{peer_ip6}").Check()
      RCC(f"qrencode -t ansiutf8 -r \"{peer_conf_path}\" -o \"{peer_conf_qr_path}\"")
   #endregion

   RCC("systemctl enable wg-quick@wg0").Check()
   RCC("systemctl restart wg-quick@wg0").Check()
   
if __name__ == "__main__":
   main()
