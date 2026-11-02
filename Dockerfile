FROM kalilinux/kali-rolling

LABEL maintainer="NmapReconFlow" \
      description="Automated nmap reconnaissance workflow"

# nmap + the recon tools NmapReconFlow recommends, in one layer.
# perl provides process-group handling; xsltproc renders --html reports.
RUN apt-get update -qq && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        bash \
        perl \
        nmap \
        iputils-ping \
        dnsutils \
        xsltproc \
        curl \
        wget \
        net-tools \
        seclists \
        dirb \
        nikto \
        gobuster \
        ffuf \
        whatweb \
        wpscan \
        sslscan \
        snmp \
        smbclient \
        smbmap \
        enum4linux-ng \
        ldap-utils \
        dnsrecon \
        nfs-common \
        ssh-audit \
        exploitdb \
        hydra \
        nuclei && \
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

# Usage:
#   docker build -t nmapreconflow .
#   docker run --rm -it --net=host -v "$PWD:/output" nmapreconflow -H 10.10.10.10 -t All -a
#   docker run --rm -it -v "$PWD:/output" nmapreconflow --explore /output/10.10.10.10
ENTRYPOINT ["/opt/nmapReconFlow/nmapReconFlow.sh"]
