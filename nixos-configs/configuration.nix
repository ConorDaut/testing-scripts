# NIXOS-PXE-SSH-HARDENED-CONFIG  (marker used by nixos-config-backup.sh; do not remove)
#
# NixOS 25.05 -- dnsmasq (DHCP/proxyDHCP + TFTP PXE + optional DNS), SSH,
# iptables firewall.
#
# Everything you are likely to change lives in the `let` block below.
# Search for CHANGEME before you run `nixos-rebuild switch`.
#
# BEFORE USING: run nixos-config-backup.sh backup   (saves the ORIGINAL config)

{ config, pkgs, lib, ... }:

let
  ###########################################################################
  # SETTINGS -- edit these
  ###########################################################################

  # --- identity -------------------------------------------------------------
  hostName     = "HOSTNAME-CHANGEME";            # CHANGEME
  timeZone     = "UTC";                          # CHANGEME (e.g. "America/Chicago")
  stateVersion = "25.05";                        # CHANGEME: match your ORIGINAL config's stateVersion

  # --- boot loader (copy whichever your ORIGINAL configuration.nix used) -----
  bootMode   = "uefi";                           # CHANGEME: "uefi" (systemd-boot) or "bios" (GRUB)
  grubDevice = "/dev/sda";                       # CHANGEME: only used when bootMode = "bios"

  # --- network (inside the competition network, i.e. the 192.168.220.x side) --
  lanInterface = "ens18";                        # CHANGEME: check with `ip -br a` (Proxmox VirtIO is usually ens18)
  useStaticIp  = true;                           # false = keep DHCP on this box
  hostIp       = "192.168.220.234";
  prefixLength = 24;
  lanNetAddr   = "192.168.220.0";
  lanNetmask   = "255.255.255.0";
  lanSubnet    = "192.168.220.0/24";             # used by firewall rules
  gateway      = "192.168.220.1";                # CHANGEME
  upstreamDns  = [ "192.168.220.1" ];            # CHANGEME: where dnsmasq/this host forwards DNS

  # --- dnsmasq / PXE ----------------------------------------------------------
  # true  = proxyDHCP: the existing DHCP server keeps handing out leases and this
  #         box ONLY adds PXE boot info (safest; does not disturb existing DHCP).
  # false = this box is a full DHCP server (uses the range below).
  proxyDhcp  = true;
  dhcpStart  = "192.168.220.100";                # CHANGEME (full-DHCP mode only)
  dhcpEnd    = "192.168.220.200";                # CHANGEME (full-DHCP mode only)
  dhcpLease  = "12h";

  enableDns  = true;                             # false = dnsmasq does DHCP/PXE only (port=0)
  tftpRoot   = "/srv/tftp";

  # Boot files served from tftpRoot. The defaults are symlinked from nixpkgs'
  # iPXE package, which then chain-loads boot.ipxe (a placeholder menu below).
  biosBootFile = "undionly.kpxe";
  efiBootFile  = "ipxe.efi";
  ipxeScript   = "boot.ipxe";

  # --- SSH ---------------------------------------------------------------------
  sshPort           = 22;
  # Who may reach SSH. "0.0.0.0/0" = anyone (rate-limited below). Tighten later,
  # but remember a scoring/monitoring system may need to reach this port.
  sshAllowedSources = [ "0.0.0.0/0" ];           # CHANGEME (e.g. [ "192.168.220.0/24" ])
  sshKeyOnly        = false;                     # true = disable passwords (needs a real key below)
  allowRootSsh      = false;                     # true only if root is your ONLY login
  adminUser         = "adminuser";               # CHANGEME (only created when sshKeyOnly = true)
  sshAuthorizedKeys = [
    "ssh-ed25519 AAAA-CHANGEME-PUBLIC-KEY user@host"   # CHANGEME
  ];

  # Extra TCP ports to open to the LAN only (e.g. [ 80 ] if you add HTTP boot).
  lanExtraTcpPorts = [ ];

  ###########################################################################
  # Derived values (no need to edit)
  ###########################################################################
  keyIsPlaceholder = lib.any (k: lib.hasInfix "CHANGEME" k) sshAuthorizedKeys;

  # Placeholder iPXE menu. Replace with real kernel/initrd entries.
  bootScript = pkgs.writeText "boot.ipxe" ''
    #!ipxe
    echo
    echo ==== ${hostName} PXE server ====
    echo Edit ${tftpRoot}/${ipxeScript} (or replace the symlink) to add boot entries.
    echo Example:
    echo   kernel tftp://${hostIp}/vmlinuz initrd=initrd.img
    echo   initrd tftp://${hostIp}/initrd.img
    echo   boot
    echo
    shell
  '';

  sshRules = lib.concatMapStrings (src: ''
    # SSH from ${src}: drop sources opening >=10 new connections in 60s, accept the rest
    iptables -w -A nixos-fw -s ${src} -p tcp --dport ${toString sshPort} -m conntrack --ctstate NEW -m recent --name SSH_BF --update --seconds 60 --hitcount 10 -j DROP
    iptables -w -A nixos-fw -s ${src} -p tcp --dport ${toString sshPort} -m conntrack --ctstate NEW -m recent --name SSH_BF --set -j ACCEPT
  '') sshAllowedSources;

  lanTcpRules = lib.concatMapStrings (p: ''
    iptables -w -A nixos-fw -s ${lanSubnet} -p tcp --dport ${toString p} -j ACCEPT
  '') lanExtraTcpPorts;

in
{
  imports = [ ./hardware-configuration.nix ];

  ###########################################################################
  # Basics
  ###########################################################################
  boot.loader =
    if bootMode == "uefi" then {
      systemd-boot.enable = true;
      efi.canTouchEfiVariables = true;
    } else {
      grub.enable = true;
      grub.device = grubDevice;
    };

  networking.hostName = hostName;
  time.timeZone = timeZone;
  services.qemuGuest.enable = true;              # Proxmox guest agent

  environment.systemPackages = with pkgs; [
    iptables
    tcpdump
    curl
    vim
  ];

  ###########################################################################
  # Networking
  ###########################################################################
  networking.useDHCP = lib.mkIf useStaticIp false;
  networking.interfaces = lib.mkIf useStaticIp {
    ${lanInterface}.ipv4.addresses = [
      { address = hostIp; inherit prefixLength; }
    ];
  };
  networking.defaultGateway = lib.mkIf useStaticIp gateway;
  networking.nameservers = upstreamDns;

  # Kernel network hardening
  boot.kernel.sysctl = {
    "net.ipv4.tcp_syncookies" = 1;
    "net.ipv4.conf.all.accept_redirects" = 0;
    "net.ipv4.conf.default.accept_redirects" = 0;
    "net.ipv4.conf.all.send_redirects" = 0;
    "net.ipv4.conf.all.accept_source_route" = 0;
    "net.ipv4.icmp_echo_ignore_broadcasts" = 1;
    "net.ipv4.conf.all.log_martians" = 1;
    "net.ipv6.conf.all.accept_redirects" = 0;
  };

  ###########################################################################
  # dnsmasq: DHCP/proxyDHCP + TFTP PXE (+ optional DNS)
  ###########################################################################
  services.dnsmasq = {
    enable = true;
    resolveLocalQueries = false;                 # don't hijack /etc/resolv.conf
    settings = {
      interface = lanInterface;
      bind-interfaces = true;
      domain-needed = true;
      bogus-priv = true;
      no-resolv = true;
      server = upstreamDns;
      port = if enableDns then 53 else 0;

      enable-tftp = true;
      tftp-root = tftpRoot;

      log-dhcp = true;

      # Client classification: iPXE (DHCP option 175) vs. firmware PXE, BIOS vs. EFI
      dhcp-match = [
        "set:ipxe,175"
        "set:bios,option:client-arch,0"
        "set:efi64,option:client-arch,7"
        "set:efi64,option:client-arch,9"
      ];
    }
    // (if proxyDhcp then {
      dhcp-range = [ "${lanNetAddr},proxy" ];
      pxe-prompt = ''"PXE boot (Enter for menu)",3'';
      pxe-service = [
        ''tag:!ipxe,x86PC,"PXE chainload to iPXE (BIOS)",${biosBootFile}''
        ''tag:!ipxe,BC_EFI,"PXE chainload to iPXE (UEFI)",${efiBootFile}''
        ''tag:!ipxe,X86-64_EFI,"PXE chainload to iPXE (UEFI)",${efiBootFile}''
        ''tag:ipxe,x86PC,"iPXE menu",${ipxeScript}''
        ''tag:ipxe,BC_EFI,"iPXE menu",${ipxeScript}''
        ''tag:ipxe,X86-64_EFI,"iPXE menu",${ipxeScript}''
      ];
    } else {
      dhcp-range = [ "${dhcpStart},${dhcpEnd},${lanNetmask},${dhcpLease}" ];
      dhcp-authoritative = true;
      dhcp-option = [
        "option:router,${gateway}"
        "option:dns-server,${hostIp}"
      ];
      dhcp-boot = [
        "tag:!ipxe,tag:bios,${biosBootFile},,${hostIp}"
        "tag:!ipxe,tag:efi64,${efiBootFile},,${hostIp}"
        "tag:ipxe,${ipxeScript},,${hostIp}"
      ];
    });
  };

  # Start dnsmasq only once the static address exists.
  systemd.services.dnsmasq = {
    after = [ "network-online.target" ];
    wants = [ "network-online.target" ];
  };

  # TFTP root: boot files come from nixpkgs' iPXE (verify with `ls ${tftpRoot}`).
  systemd.tmpfiles.rules = [
    "d ${tftpRoot} 0755 root root -"
    "L+ ${tftpRoot}/undionly.kpxe - - - - ${pkgs.ipxe}/undionly.kpxe"
    "L+ ${tftpRoot}/ipxe.efi - - - - ${pkgs.ipxe}/ipxe.efi"
    "L+ ${tftpRoot}/${ipxeScript} - - - - ${bootScript}"
  ];

  ###########################################################################
  # SSH
  ###########################################################################
  services.openssh = {
    enable = true;
    ports = [ sshPort ];
    openFirewall = false;                        # firewall rules below control access
    settings = {
      PermitRootLogin = if allowRootSsh then "yes" else "no";
      PasswordAuthentication = !sshKeyOnly;
      KbdInteractiveAuthentication = !sshKeyOnly;
      PermitEmptyPasswords = false;
      MaxAuthTries = 3;
      LoginGraceTime = 20;
      MaxStartups = "10:30:60";
      X11Forwarding = false;
      AllowAgentForwarding = false;
      ClientAliveInterval = 300;
      ClientAliveCountMax = 2;
      LogLevel = "VERBOSE";
    };
  };

  # Only defined when you switch to key-only auth. Set a password afterwards
  # from the console (`passwd ${adminUser}`) so sudo works.
  users.users = lib.mkIf sshKeyOnly {
    ${adminUser} = {
      isNormalUser = true;
      extraGroups = [ "wheel" ];
      openssh.authorizedKeys.keys = sshAuthorizedKeys;
    };
  };

  assertions = [
    {
      assertion = !(sshKeyOnly && keyIsPlaceholder);
      message = "sshKeyOnly = true but sshAuthorizedKeys still holds the CHANGEME placeholder. Paste a real public key or set sshKeyOnly = false to avoid locking yourself out.";
    }
  ];

  ###########################################################################
  # Firewall (iptables backend)
  #
  # Default: inbound DROP. Only the services below are reachable.
  # IPv6: no ports are opened, so IPv6 inbound stays closed apart from the
  # ICMPv6 NixOS needs for neighbor discovery.
  ###########################################################################
  networking.nftables.enable = false;            # force iptables backend
  networking.firewall = {
    enable = true;
    allowedTCPPorts = [ ];                       # everything is opened per-source below
    allowedUDPPorts = [ ];
    allowPing = true;                            # ICMP echo allowed
    pingLimit = "--limit 20/second --limit-burst 50";
    logRefusedConnections = true;
    logRefusedPackets = false;
    logReversePathDrops = true;

    extraCommands = ''
      # --- sanity filters (placed at the top of the chain) ---
      iptables -w -I nixos-fw 1 -m conntrack --ctstate INVALID -j DROP
      iptables -w -I nixos-fw 2 -p tcp --tcp-flags ALL NONE -j DROP
      iptables -w -I nixos-fw 3 -p tcp --tcp-flags ALL ALL -j DROP
      iptables -w -I nixos-fw 4 -p tcp ! --syn -m conntrack --ctstate NEW -j DROP

      # --- SSH (rate-limited, per allowed source) ---
      ${sshRules}

      # --- DHCP / proxyDHCP / PXE ---
      # DHCPDISCOVER arrives from 0.0.0.0 (broadcast); later packets from the client's IP
      iptables -w -A nixos-fw -p udp --dport 67 -s 0.0.0.0 -j ACCEPT
      iptables -w -A nixos-fw -p udp --dport 67 -s ${lanSubnet} -j ACCEPT
      iptables -w -A nixos-fw -p udp --dport 4011 -s ${lanSubnet} -j ACCEPT

      # --- TFTP (control port; data replies are covered by conntrack) ---
      iptables -w -A nixos-fw -p udp --dport 69 -s ${lanSubnet} -j ACCEPT

      ${lib.optionalString enableDns ''
      # --- DNS from the LAN only (avoid being an open resolver) ---
      iptables -w -A nixos-fw -p udp --dport 53 -s ${lanSubnet} -j ACCEPT
      iptables -w -A nixos-fw -p tcp --dport 53 -s ${lanSubnet} -j ACCEPT
      ''}

      # --- extra LAN-only TCP ports (e.g. HTTP boot) ---
      ${lanTcpRules}

      # Anything else falls through to NixOS's final log-and-drop rule.
    '';
  };

  ###########################################################################
  system.stateVersion = stateVersion;
}
