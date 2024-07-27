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
import custom_cmd_util as ccu


if __name__ == "__main__":
   SRV_ADDR = "h-7788-9484.ddns.net"
   PORT = 51820
   PEER_COUNT = 5
   
   # Install Wireguard
   if ccu.RunCommandContainer("dpkg -l wireguard", True).return_code != 0:
      print(f"Wireguard is not installed")
      ccu.RunCommandContainer("apt install wireguard -y").Check()
   
   #region FIREWALL (UFW)
   ccu.RunCommandContainer(f"bash -c 'yes | ufw enable'")
   ccu.RunCommandContainer(f"ufw delete allow {PORT}").Check()
   ccu.RunCommandContainer(f"ufw allow {PORT} comment \"Wireguard\"").Check()
   #endregion
   
   # region SYSCTL
   # Read sysctl config 
   sysctl_path = "/etc/sysctl.conf"
   sysctl_contents = ccu.file_read(sysctl_path)
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
      ccu.file_write(sysctl_path, sysctl_contents)
      print(f"Wrote new sysctl config")
      ccu.RunCommandContainer("sysctl -p").Check()
   #endregion
   
   # region GRAB DEFAULT INTERFACE
   ip_cmd = ccu.RunCommandContainer("ip route list default", True).Check()
   ip_cmd_m = re.match(r"^ default \s via \s (?: \d{1,3}\.? ){4} \s dev \s (?P<iname> \w+ )", ip_cmd.std_out, re.M | re.X)
   if ip_cmd_m == None:
      raise Exception(f"Could not find default interface")
   default_interface_name = str(ip_cmd_m.group("iname"))
   print(f"default interface: \"{default_interface_name}\"")
   # endregion
   
   # region GRAB DNS
   dns_ip_list = ccu.RunCommandContainer(f"resolvectl dns {default_interface_name}").Check().std_out
   dns_ip_list_match = re.match(r"Link \s* \d \s* \( [^\)]+ \)\:\s* (?P<di> .+? ) $", dns_ip_list, re.X | re.M)
   dns_ip_list = ", ".join( ["10.19.49.10",  *(dns_ip_list_match.group("di").split(" ")[1:]) ] )
   print(f"DNS IP LIST (Modified): \"{dns_ip_list}\"")
   raise Exception("TEST THIS CHANGE")
   # endregion
   
   # region WG-CONFIG
   ccu.RunCommandContainer("systemctl stop wg-quick@wg0")
   # Write config
   wireguard_path = "/etc/wireguard"
   conf_path = os.path.join(wireguard_path, "wg0.conf")
   private_key_path = os.path.join(wireguard_path, "private.key")
   public_key_path = os.path.join(wireguard_path, "public.key")
   if not os.path.exists(wireguard_path):
      raise Exception(f"wireguard folder missing: {wireguard_path}")
   print(f"Removing contents of \"{wireguard_path}\" directory...")
   ccu.clear_directory(wireguard_path)
   
   private_key = ccu.RunCommandContainer("wg genkey").Check().std_out.strip()
   public_key = ccu.RunCommandContainer(f"bash -c 'echo \"{private_key}\" | wg pubkey'").Check().std_out.strip()
   ccu.file_write(path=private_key_path, contents=private_key, permission_bits=0o600)
   ccu.file_write(path=public_key_path, contents=public_key, permission_bits=0o600)
   print(f"Private Key: {re.sub('.', '*', private_key)} | Public Key: {public_key}")
   
   # ip_v4_str.PEER_NUM for ip generation
   ip_v4_str = "10.8.0"
   # String of the form fd0d:cd54:a67c -> ip_v6_str::PEER_NUM for ip generation
   ip_v6_str = "fd00:" + ':'.join( [ ''.join(random.choices('0123456789abcdef', k=4)) for _ in range(2) ] )
   wg0_conf = f"""
      [Interface]
      PrivateKey = {private_key}
      Address = {ip_v4_str}.1/24, {ip_v6_str}::1/64
      ListenPort = {PORT}
      SaveConfig = true
      
      PostUp = ufw route allow in on wg0 out on {default_interface_name}
      PostUp = iptables -t nat -I POSTROUTING -o {default_interface_name} -j MASQUERADE
      PostUp = ip6tables -t nat -I POSTROUTING -o {default_interface_name} -j MASQUERADE
      
      PreDown = ufw route delete allow in on wg0 out on {default_interface_name}
      PreDown = iptables -t nat -D POSTROUTING -o {default_interface_name} -j MASQUERADE
      PreDown = ip6tables -t nat -D POSTROUTING -o {default_interface_name} -j MASQUERADE
   """
   wg0_conf = "\n".join( [l.strip() for l in wg0_conf.splitlines()] ).strip()
   wg0_conf_print= "\n".join(f"   CONF>  {l}" for l in wg0_conf.replace(private_key, "...PRIVATE_KEY...").splitlines())
   print(f"Writing config: \n{wg0_conf_print}")
   ccu.file_write(path=conf_path, contents=wg0_conf)
   # endregion
   
   ccu.RunCommandContainer("systemctl enable wg-quick@wg0").Check()
   ccu.RunCommandContainer("systemctl restart wg-quick@wg0").Check()
   
   #region PEERS
   for i in range(1, PEER_COUNT + 1, 1):
      peer_dir = f"/etc/wireguard/peer{i}"
      peer_conf_path = os.path.join(peer_dir, f"peer{i}-wg0.conf")
      peer_private_key_path = os.path.join(peer_dir, f"peer{i}-private.key")
      peer_public_key_path = os.path.join(peer_dir, f"peer{i}-public.key")
      peer_conf_qr_path = os.path.join(peer_dir, f"peer{i}-conf.qr.ascii.txt")
      
      print(f"PEER {i}: creating")
      os.mkdir(peer_dir)
      
      # Public, Private keys
      peer_private_key = ccu.RunCommandContainer("wg genkey").Check().std_out.strip()
      peer_public_key = ccu.RunCommandContainer(f"bash -c 'echo \"{peer_private_key}\" | wg pubkey'").Check().std_out.strip()
      peer_ip4 = f"{ip_v4_str}.{(i+1)}"
      peer_ip6 = f"{ip_v6_str}::{(i+1)}"
      ccu.file_write(path=peer_private_key_path, contents=peer_private_key, permission_bits=0o600)
      ccu.file_write(path=peer_public_key_path, contents=peer_public_key, permission_bits=0o600)
      
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
         Endpoint = {SRV_ADDR}:{PORT}
      """
      peer_conf = "\n".join( [l.strip() for l in peer_conf.splitlines()] ).strip()
      peer_conf_print= "\n".join(f"   CONF (P)>  {l}" for l in peer_conf.replace(private_key, "...PRIVATE_KEY...").splitlines())
      print(f"Writing config: \n{peer_conf}")
      ccu.file_write(path=peer_conf_path, contents=peer_conf, permission_bits=0o600)
      
      ccu.RunCommandContainer(f"wg set wg0 peer {peer_public_key} allowed-ips {peer_ip4},{peer_ip6}").Check()
      ccu.RunCommandContainer(f"qrencode -t ansiutf8 -r \"{peer_conf_path}\" -o \"{peer_conf_qr_path}\"")
   # endregion
