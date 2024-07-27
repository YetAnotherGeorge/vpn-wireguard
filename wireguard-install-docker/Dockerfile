FROM  "ubuntu-wg-base"
LABEL name="ih-wireguard"

COPY ./wireguard-install /wireguard-install

WORKDIR /wireguard-install
CMD [ "python", "-u", "install.py" ]