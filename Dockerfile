FROM kalilinux/kali-rolling

LABEL maintainer="NmapReconFlow" \
      description="Automated nmap reconnaissance workflow"

# Install nmap and common recon tools in a single layer, then clean up
RUN apt-get update -qq && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        bash \
        nmap \
        seclists \
        dirb \
        nikto \
        gobuster \
        ffuf \
        dnsutils \
        snmp \
        smbclient \
        ldap-utils \
        whatweb \
        wpscan \
        sslscan \
        curl \
        wget \
        net-tools && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy project files
COPY nmapReconFlow.sh nmapReconFlow.conf.example /opt/nmapReconFlow/
COPY lib/ /opt/nmapReconFlow/lib/

# Make the main script executable and create symlink
RUN chmod +x /opt/nmapReconFlow/nmapReconFlow.sh && \
    ln -s /opt/nmapReconFlow/nmapReconFlow.sh /usr/local/bin/nmapReconFlow

# Create output directory
RUN mkdir -p /output

WORKDIR /output

ENTRYPOINT ["/opt/nmapReconFlow/nmapReconFlow.sh"]
