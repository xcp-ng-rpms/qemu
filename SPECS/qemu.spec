%global package_speccommit 9af8f0927f79cacfed676465a44b35bfb099281e
%global usver 4.2.1
%global xsver 4.6.4
%global xsrel %{xsver}%{?xscount}%{?xshash}
%global package_srccommit v4.2.1

# submodule ui/keycodemapdb
%define keycodemapdb_cset 22b8996dba9041874845c7446ce89ec4ae2b713d
%define keycodemapdb_path ui/keycodemapdb

# Control whether we build with the address sanitizer.
%define with_asan 0

Summary: qemu-dm device model
Name: qemu
Epoch: 2
Version: 4.2.1
Release: %{?xsrel}.2%{?dist}
License: GPL
Requires: xcp-clipboardd
Requires: xengt-userspace
## We broke an interface used by xenopsd-xc without version signalling
## so we have to carry a conflicts line to say we broke it.
Conflicts: xenopsd-xc < 0.123.0
Source0: qemu-4.2.1.tar.gz
Source1: qemu_trad_image.py
Source2: keycodemapdb-22b8996dba9041874845c7446ce89ec4ae2b713d.tar.gz
Patch0: 0001-usb-fix-setup_len-init-CVE-2020-14364.patch
Patch1: 0001-scripts-qmp-Fix-shebang-and-imports.patch
Patch2: 0001-xen-rework-pci_piix3_xen_ide_unplug.patch
Patch3: 0001-hw-ehci-destroy-sglist-in-error-path.patch
Patch4: 0002-hw-ehci-check-return-value-of-usb_packet_map.patch
Patch5: 0003-usb-hcd-ehci-Fix-error-handling-on-missing-device-fo.patch
Patch6: 0001-pci-assert-configuration-access-is-within-bounds.patch
Patch7: 0006-block-Avoid-stale-pointer-dereference-in-blk_get_aio.patch
Patch8: 0001-ide-atapi-assert-that-the-buffer-pointer-is-in-range.patch
Patch9: 0001-xen-bus-reduce-scope-of-backend-watch.patch
Patch10: 0001-ide-atapi-check-logical-block-address-and-read-size-.patch
Patch11: 0001-ui-update-keycodemapdb-submodule-commit.patch
Patch12: 0001-e1000-fail-early-for-evil-descriptor.patch
Patch13: 0001-net-introduce-qemu_receive_packet.patch
Patch14: 0002-e1000-switch-to-use-qemu_receive_packet-for-loopback.patch
Patch15: 0003-rtl8139-switch-to-use-qemu_receive_packet-for-loopba.patch
Patch16: 0001-input-Add-lang1-and-lang2-to-QKeyCode.patch
Patch17: 0001-aio-posix-fix-use-after-leaving-scope-in-aio_poll.patch
Patch18: 0001-xen-mapcache-avoid-a-race-on-memory-map-while-using-.patch
Patch19: 0001-xen-hvm-Allow-disabling-buffer_io_timer.patch
Patch20: 0001-xen-mapcache-Avoid-entry-lock-overflow.patch
Patch21: hw-ide__check_null_block_before__cancel_dma_sync.patch
Patch22: xen-platform-add-device-id-property.patch
Patch23: xen-platform-add-class-id-property.patch
Patch24: xen-platform-add-revision-property.patch
Patch25: 0001-xen-platform-Handle-write-of-four-byte-build-number-.patch
Patch26: 0002-xen-platform-Provide-QMP-query-commands-for-XEN-PV-d.patch
Patch27: 0003-xen-platform-Emit-XEN_PLATFORM_PV_DRIVER_INFO-after-.patch
Patch28: dont-set-a20-on-xen.patch
Patch29: dont-init-cpus-on-xen.patch
Patch30: 0001-xen-Emit-RTC_CHANGE-upon-TIMEOFFSET-ioreq.patch
Patch31: remove-ioapic.patch
Patch32: ignore-rtc-century-changes.patch
Patch33: 0001-CP-33348-Allow-media-replace-qmp-command-to-take-a-n.patch
Patch34: token-bucket-event-throttling.patch
Patch35: xen-hvm-Avoid-livelock-while-handling-buffered-ioreq.patch
Patch36: 0001-pc-Do-not-expect-to-have-a-fw_cfg-device.patch
Patch37: 0003-xen-apic-Implement-unrealize.patch
Patch38: 0004-hotplug-Implement-legacy-CPU-hot-unplug.patch
Patch39: igd-upt.patch
Patch40: check-unmigratable-devices-when-saving.patch
Patch41: query-migratable.patch
Patch42: 0001-nvme-simplify-namespace-code.patch
Patch43: 0002-nvme-move-device-parameters-to-separate-struct.patch
Patch44: 0003-nvme-fix-lpa-field.patch
Patch45: 0004-nvme-add-missing-fields-in-identify-controller.patch
Patch46: 0005-nvme-populate-the-mandatory-subnqn-and-ver-fields.patch
Patch47: 0006-nvme-support-completion-queue-in-cmb.patch
Patch48: 0007-nvme-support-Abort-command.patch
Patch49: 0008-nvme-refactor-device-realization.patch
Patch50: 0009-nvme-support-Asynchronous-Event-Request-command.patch
Patch51: 0010-nvme-support-Get-Log-Page-command.patch
Patch52: 0011-nvme-add-missing-mandatory-Features.patch
Patch53: 0012-nvme-bump-supported-NVMe-revision-to-1.3d.patch
Patch54: 0013-nvme-simplify-dma-cmb-mappings.patch
Patch55: 0014-nvme-support-multiple-block-requests-per-request.patch
Patch56: 0015-nvme-support-scatter-gather-lists.patch
Patch57: 0016-nvme-support-multiple-namespaces.patch
Patch58: nvme-ns-fix-null.patch
Patch59: nvme-ns-allow-inactive.patch
Patch60: nvme-close-backend.patch
Patch61: 0001-Add-qemu-qcode-support-for-keys-F13-to-F24.patch
Patch62: 0001-ps2-Don-t-send-key-release-event-for-Lang1-Lang2-key.patch
Patch63: 0001-CP-20436-Introduce-a-config-option-for-machines-comp.patch
Patch64: pci-add-subsystem-id-properties.patch
Patch65: pci-add-revision_id-property.patch
Patch66: force-lba-geometry.patch
Patch67: 0001-CP-21767-Don-t-accidently-unplug-ourselves-if-PCI_CL.patch
Patch68: 0001-CP-21434-Implement-VBE-LFB-physical-address-register.patch
Patch69: 0001-CA-256542-Workaround-unassigned-accesses-caused-by-b.patch
Patch70: match-xen-pvdevice-location.patch
Patch71: 0001-CA-289906-Use-legacy-HID-descriptors-for-USB-Tablet-.patch
Patch72: revert_hw-i386__remove_deprecated_machines_pc-0.10_and_pc-0.11.patch
Patch73: 0001-CP-17697-Initial-port-of-NVIDIA-VGPU-support-from-QEMU-trad.patch
Patch74: usb-batch-frames.patch
Patch75: 0001-CP-23753-Talk-to-new-clipboard-daemon.patch
Patch76: gvt-g.patch
Patch77: 0001-Update-fd-handlers-to-support-sysfs_notify.patch
Patch78: 0002-Fix-up-PCI-command-register-for-AMD-ATI-GPU-VFs.patch
Patch79: 0003-Add-interception-layer-for-BAR-ops.patch
Patch80: 0004-Add-AMD-code.patch
Patch81: allocate-vram-reserved.patch
Patch82: unplug-nvme-devices.patch
Patch83: do_not_register_xen_backend_for_qdisk.patch
Patch84: add-an-ide-read-cache.patch
Patch85: disable-dirty-vram-tracking.patch
Patch86: build-configuration.patch

# XCP-ng patches
Patch1000: qemu-4.2.1-CVE-2023-3354.backport.patch

BuildRequires: gcc
BuildRequires: python2-devel
BuildRequires: libaio-devel glib2-devel
BuildRequires: libjpeg-devel libpng-devel pixman-devel xenserver-libdrm-devel
BuildRequires: xen-dom0-libs-devel xen-libs-devel libusbx-devel
BuildRequires: libseccomp-devel
%if %{with_asan} == 0
BuildRequires: jemalloc-devel
%else
BuildRequires: libasan
%endif
%{?_cov_buildrequires}

%description
This package contains Qemu.

%prep
%autosetup -p1
%{?_cov_prepare}

# submodule ui/keymapcodedb
tar xzf %{SOURCE2}

%build
%if %{with_asan}
extra_configure_argument+=('--enable-sanitizers')
extra_configure_argument+=('--enable-debug')
# Help to get better stack trace
extra_configure_argument+=('--extra-cflags=-fno-omit-frame-pointer')
# avoid: "WARNING: ASan doesn't fully support makecontext/swapcontext functions and may produce false positives in some cases!"
# extra_configure_argument+=('--with-coroutine=sigaltstack')

%else
extra_configure_argument+=('--enable-jemalloc')
%endif

./configure --cc=gcc --cxx=/dev/null --enable-xen --target-list=i386-softmmu \
    --prefix=%{_prefix} --bindir=%{_libdir}/xen/bin --datadir=%{_datarootdir} \
    --localstatedir=%{_localstatedir} --libexecdir=%{_libexecdir} --sysconfdir=%{_sysconfdir} \
    --enable-werror --enable-libusb --enable-trace-backend=log \
    --disable-kvm --disable-docs --disable-guest-agent --disable-sdl \
    --disable-curses --disable-curl --disable-gtk --disable-bzip2 \
    --disable-strip --disable-gnutls --disable-nettle --disable-gcrypt \
    --disable-vhost-net --disable-vhost-scsi --disable-vhost-vsock --disable-vhost-user \
    --disable-lzo --disable-tpm --disable-virtfs --disable-tcg --disable-tcg-interpreter \
    --disable-replication --disable-qom-cast-debug --disable-slirp \
    --audio-drv-list= --disable-coroutine-pool --disable-live-block-migration \
    --disable-bochs --disable-cloop --disable-dmg --disable-vvfat --disable-qed \
    --disable-parallels --disable-sheepdog \
    --without-default-devices \
    --enable-seccomp "${extra_configure_argument[@]}"

%if %{with_asan}
# Check that address sanitizers is enabled, because QEMU's ./configure will not fail
grep -qe '-fsanitize=address' config-host.mak
%endif

%{?_cov_wrap} %{__make} %{?_smp_mflags} all

%install
mkdir -p %{buildroot}%{_libdir}/xen/bin

rm -rf %{buildroot}
%{__make} %{?_smp_mflags} install DESTDIR=%{buildroot}
rm -rf %{buildroot}/usr/include %{buildroot}%{_libdir}/pkgconfig %{buildroot}%{_libdir}/libcacard.*a \
       %{buildroot}/usr/share/locale
rm -rf %{buildroot}/usr/share/icons/
rm -rf %{buildroot}/usr/share/applications/
%{__install} -D -m 644 %{SOURCE1} %{buildroot}%{_libdir}/xen/bin/qemu_trad_image.py

# QMP scripts
%{__install} -d -m 755 %{buildroot}%{python2_sitelib}/
cp -r python/qemu %{buildroot}%{python2_sitelib}/
cp -r scripts/qmp %{buildroot}%{_datarootdir}/qemu
%{?_cov_install}

%files
%{_libdir}/xen/bin
%{_datarootdir}/qemu
%{_libexecdir}/*
%{python2_sitelib}/qemu

%{?_cov_results_package}

%changelog
* Tue Feb 11 2025 Lucas Ravagnier <lucas.ravagnier@vates.tech> - 4.2.1-4.6.4.2
- Add qemu-4.2.1-CVE-2023-3354.backport.patch to fix a CVE
  of a NULL pointer dereference that can cause a DOS

* Tue Jun 11 2024 Gael Duperrey <gduperrey@vates.tech> - 4.2.1-4.6.4.1
- Sync to hotfix XS82ECU1068
- *** Upstream changelog ***
- * Thu May 30 2024 Ross Lagerwall <ross.lagerwall@citrix.com> - 4.2.1-4.6.4
- - CP-42792: Backport a patch to avoid unncessary buffered ioreq polling
- - CA-391031: Reinstate rate limiting of RTC_CHANGE events
- - CA-391069: Avoid livelock due to buffered ioreqs

* Fri May 05 2023 Gael Duperrey <gduperrey@vates.fr> - 4.2.1-4.6.3.1
- Sync to hotfix XS82ECU1031
- *** Upstream changelog ***
- * Thu Apr 20 2023 Ross Lagerwall <ross.lagerwall@citrix.com> - 4.2.1-4.6.3
- - Convert to Koji-based build
- - CA-374355: Fix use of Lang1/Lang2 keys
- - CA-376325: XSI-1393: Backport: xen-bus: reduce scope of backend watch

* Wed Jul 20 2022 Gael Duperrey <gduperrey@vates.fr> - 4.2.1-4.6.2.1
- Sync to hotfix XS82ECU1013
- *** Upstream changelog ***
- * Wed May 25 2022 Ross Lagerwall <ross.lagerwall@citrix.com> - 4.2.1-4.6.2
- - CA-366527: Fix passthrough of multiple different devices
- - CA-362592: Fix mapcache/iothread SIGBUS

* Fri Dec 17 2021 Samuel Verschelde <stormi-xcp@ylix.fr> - 4.2.1-4.6.1.1
- Sync with CH 8.2.1
- *** Upstream changelog ***
- * Fri Jul 16 2021 Anthony PERARD <anthony.perard@citrix.com> - 4.2.1-4.6.1
- - CP-36452: Import patch queue from trunk / QEMU 4.2

* Wed Jun 23 2021 Samuel Verschelde <stormi-xcp@ylix.fr> - 2.10.2-4.5.4
- Security update, synced from XS82E025

* Tue Aug 25 2020 Samuel Verschelde <stormi-xcp@ylix.fr> - 2.10.2-4.5.3
- Security update
- See http://xenbits.xen.org/xsa/advisory-335.html

* Thu Apr 30 2020 Ross Lagerwall <ross.lagerwall@citrix.com> - 2.10.2-4.5.2
- CA-3216958: Move vgpu fifo to tempfs

* Mon Apr 20 2020 Ross Lagerwall <ross.lagerwall@citrix.com> - 2.10.2-4.5.1
- CA-337460 - Allow commit lists to be imported chronologically.
- CP-33051 - Forward port preopened sockets in monitor fdset.
- Fix patch context
- CP-33348 - Allow preopend nbd sockets to be passed to running qemu instance via qmp command.

* Thu Mar 26 2020 Ross Lagerwall <ross.lagerwall@citrix.com> - 2.10.2-4.5.0
- Fix patch context
- CA-336055: nvme: Disassociate block driver state during unplug
- CA-299551: Fix sporadic cpu_physical_memory_snapshot_get_dirty assertion

* Fri Feb 21 2020 Steven Woods <steven.woods@citrix.com> - 2.10.2-4.4.2
- CP33120: Add Coverity build macros

* Thu Nov 07 2019 Ross Lagerwall <ross.lagerwall@citrix.com> - 2.10.2-4.4.1
- CA-330047: Fix QEMU crash with discontiguous NVME namespaces

* Sat Aug 24 2019 Ross Lagerwall <ross.lagerwall@citrix.com> - 2.10.2-4.4.0
- CA-320079: Add NVME namespace support

* Wed Mar 27 2019 Ross Lagerwall <ross.lagerwall@citrix.com> - 2.10.2-4.3.0
- CA-309161: make the import script work with the new planex

* Tue Dec 18 2018 Edwin Török <edvin.torok@citrix.com> - 2.10.2-4.1.4
- CP-29626: Call blk_drain in NVMe reset code to avoid lockups
- CP-29898: Implement NVME migration workaround
- CP-29935: Add a command to allow querying whether the VM is migratable
- CP-29827: Don't conflate RTC_CENTURY bit with trad-compat
- CP-29827: Make legacy CPU unplug work for all machine types
- Fix patch context
- Backport NVMe fixes from upstream, including a CVE
- CA-303616: Expose LFB address when GVT-g is enabled

* Fri Nov 23 2018 Simon Rowe <simon.rowe@citrix.com> - 2.10.2-4.1.3
- CP-29194: Tidy up the patchqueue

* Tue Nov 06 2018 Simon Rowe <simon.rowe@citrix.com> - 2.10.2-4.1.2
- CP-28652: enable nvme for guest uefi

* Fri Oct 12 2018 Simon Rowe <simon.rowe@citrix.com> - 2.10.2-4.1.1
- Revert "CA-290135: Add debug patch to catch the unhandled access"

* Fri Sep 28 2018 Ross Lagerwall <ross.lagerwall@citrix.com> - 2.10.2-4.1.0
- CA-293487: Allocate VRAM in a reserved area
- CA-290135: Add debug patch to catch the unhandled access
- Enable the ISA debug device for OVMF logging

* Thu Aug 16 2018 Igor Druzhinin <igor.druzhinin@citrix.com> - 2.10.2-4.0.4
- CA-290647 50% regression in vm<->vm intrahost network throughput

* Fri Jul 27 2018 Ross Lagerwall <ross.lagerwall@citrix.com> - 2.10.2-4.0.3
- CA-290135: Make the debug message more obvious
- CA-294052: Recreate PCIBUS section properly on upgrade

* Thu Jul 12 2018 Simon Rowe <simon.rowe@citrix.com> - 2.10.2-4.0.2
- CA-290135 Reinforce unhandled unassigned access processing

* Tue Jul 03 2018 Simon Rowe <simon.rowe@citrix.com> - 2.10.2-4.0.1
- CA-293221: Fix upgrade from Clearwater

* Thu Jun 28 2018 Ross Lagerwall <ross.lagerwall@citrix.com> - 2.10.2-4.0.0
- CA-289906: Fix USB Tablet failure on every even migration during live-upgrade

* Mon Jun 25 2018 Simon Rowe <simon.rowe@citrix.com> - 2.10.2-3.0.8
- CA-286948: Fix resume when PV device location changes

* Wed May 30 2018 Simon Rowe <simon.rowe@citrix.com> - 2.10.2-3.0.7
- Print error code on foreign map failure

* Tue May 15 2018 Simon Rowe <simon.rowe@citrix.com> - 2.10.2-3.0.6
- CA-288638: Correct reporting of modified VRAM during migration
- CP-27696: Accomodate customised xen-pvdevice and NIC device ids into live-upgrade script
- CA-289321: Fix PCI passthrough edge cases
- CP-27572: vGPU should use shmem instead of xenstore+buffer hackery.

* Tue May 15 2018 Simon Rowe <simon.rowe@citrix.com> - 2.10.2-3.0.5
- CA-288638: Correct reporting of modified VRAM during migration
- CP-27696: Accomodate customised xen-pvdevice and NIC device ids into live-upgrade script
- CA-289321: Fix PCI passthrough edge cases
- CP-27572: vGPU should use shmem instead of xenstore+buffer hackery.

* Fri Apr 20 2018 Simon Rowe <simon.rowe@citrix.com> - 2.10.2-3.0.4
- CA-288286: Avoid built-in QEMU crypto

* Wed Apr 18 2018 marksy <mark.syms@citrix.com> - 2.10.2-3.0.3
- IDE read cache

* Mon Apr 16 2018 Simon Rowe <simon.rowe@citrix.com> - 2.10.2-3.0.2
- Return swallowed error messages
- CA-285493: Fix unmap issues with NVIDIA GPU passthrough

* Wed Mar 28 2018 Ross Lagerwall <ross.lagerwall@citrix.com> - 2.10.2-3.0.0
- Adjust dmops patch after backporting final version
- CA-266841: Improve VNC performance over long, thin pipes
- migration: Check return value of qemu_fclose
- CP-25629: Don't record QEMU's state in xenstore
- CA-267326: Backport VGA fixes including CVE-2018-5683
- CP-26998: Reintroduce QEMU vCPU hot-(un)plug patches
- CA-283664: Fix using QEMU upstream with libxl
- CP-23325: GVT-g: Save errno earlier
- CP-23325: Fix error handling issues in AMD GPU patch
- CP-23325: GVT-g: Check for allocation failure
- CP-23325: vgpu: Log sendto errors
- CP-24243: GVT-d: Use UPT instead of legacy mode
- CA-284366: Fix use of MSI-X with passthrough devices
- CP-23969 Introduce xen-pvdevice save state and upgrade into it
- CA-267326: Fix cirrus crash found by fuzzing
- CA-285409: Fix Windows RTC issues
- Enable e1000 device model for debug purposes
- CP-27303: Change QEMU vGPU communication with DEMU to fifo
- CA-285385: Backport qemu-trad vgpu-migrate patch, to allow vgpu migration
- CA-285493: Turn on PCI passthrough permissive mode

* Thu Aug 31 2017 Ross Lagerwall <ross.lagerwall@citrix.com> - 2.10.0-1
- Update to QEMU v2.10.0.

* Tue Jun 16 2015 Ross Lagerwall <ross.lagerwall@citrix.com>
- Update for Xen 4.5.

* Tue Apr 8 2014 Frediano Ziglio <frediano.ziglio@citrix.com>
- First packaging

