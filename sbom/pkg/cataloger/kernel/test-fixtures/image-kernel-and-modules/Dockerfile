FROM fedora:44@sha256:61bc3614a3aeae53af1817b0506e57d6b8ec9adf27203f6b1510c753b294b6f1

RUN dnf install 'dnf-command(download)' cpio xz -y
# https://dl.fedoraproject.org/pub/fedora/linux/releases/37/Everything/x86_64/os/Packages/k/kernel-6.0.7-301.fc37.x86_64.rpm
# https://dl.fedoraproject.org/pub/fedora/linux/releases/37/Everything/x86_64/os/Packages/k/kernel-modules-6.0.7-301.fc37.x86_64.rpm
RUN dnf download kernel-core-6.0.7-301.fc37 kernel-modules-6.0.7-301.fc37 -y

RUN rpm2cpio kernel-core-*.rpm | cpio -t && \
    rpm2cpio kernel-core-*.rpm | cpio -idmv ./lib/modules/6.0.7-301.fc37.x86_64/vmlinuz

RUN rpm2cpio kernel-modules-*.rpm | cpio -t && \
    rpm2cpio kernel-modules-*.rpm | cpio -idmv ./lib/modules/6.0.7-301.fc37.x86_64/kernel/drivers/tty/ttynull.ko.xz

RUN unxz /lib/modules/6.0.7-301.fc37.x86_64/kernel/drivers/tty/ttynull.ko.xz

FROM scratch

COPY --from=0 /lib/modules/6.0.7-301.fc37.x86_64/vmlinuz /lib/modules/6.0.7-301.fc37.x86_64/vmlinuz
COPY --from=0 /lib/modules/6.0.7-301.fc37.x86_64/kernel/drivers/tty/ttynull.ko /lib/modules/6.0.7-301.fc37.x86_64/kernel/drivers/tty/ttynull.ko
