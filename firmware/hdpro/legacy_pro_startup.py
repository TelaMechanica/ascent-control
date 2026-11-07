"""Experimental HD Pro application routing for the exact 19.2.14 donor.

Installs name/mode/startup routing, optionally a diagnostic capture table.
This module must not be added to runnable AC targets before profile admission.
"""
from __future__ import annotations
import hashlib


def install(builder, bootstrap, exports, capture=False):
    import z40_build as Z
    donor = builder.N
    # Verify complete identity, not merely a handful of instruction sites.
    if hashlib.sha256(donor.data).hexdigest() != "8aef873e2a3f9893ae6462c4daa9e5700c1deb53d2a92c6d6066b9c415213ece":
        raise ValueError("HD Pro startup requires the reviewed 19.2.14 donor")
    capture_report=None
    if capture:
        from legacy_pro_capture import install as install_capture
        bootstrap,capture_report=install_capture(builder,bootstrap,exports['g_sns_legacy_pro_obj'])
    name = builder.rx_alloc(b"imx385\0", align=1)
    ext = {"s_name": name, "bootstrap": bootstrap,
           "clock_prepare": exports["lp_cv610_prepare_clock"],
           "driver_error": exports["lp_cv610_last_error"],
           "vendor_isp_init": donor.syms["ss_mpi_isp_init"][0],
           "get_fpv_gctx": donor.syms["get_fpv_gctx"][0],
           "enable_sensor": donor.syms["vi_set_enable_sensor_clk_and_reset"][0],
           "strcmp_arm": donor.plt_target("strcmp", to_arm=True),
           "strcpy_arm": donor.plt_target("strcpy", to_arm=True),
           "usleep_arm": donor.plt_target("usleep", to_arm=True),
           "exit_arm": donor.plt_target("exit", to_arm=True),
           "gst_cont": 0x66900 | 1, "fsgst_cont": 0x5aaee | 1,
           "ivv_copy": 0x67014 | 1, "ivv_error": 0x66fee | 1,
           "main_join": 0x5a6fc | 1}
    message, _ = builder.pic_target(0x67138, 0x6713a)
    ext["ivv_msg"] = message
    source = {
        # The SDK sensor-init callback is void. Promote our recorded transport
        # error into the application's existing ISP-init failure path.
        "hdpro_isp_init":
            "push {r4,lr}\nbl vendor_isp_init\ncmp r0,#0\nbne 1f\n"
            "movs r0,#0\nbl driver_error\n1: pop {r4,pc}\n",
        # Dedicated route IDs; never pretend this is a cv2004/ps5280 camera.
        "hdpro_get_sensor_type":
            "push {r0,r1,r2,r3,r4,lr}\ncbz r0,8f\nldr r1,=s_name\n"
            "ldr ip,=strcmp_arm\nblx ip\ncmp r0,#0\n"
            "pop {r0,r1,r2,r3,r4,lr}\nbne 9f\n"
            "cmp.w r1,#1920\nbne 7f\ncmp.w r2,#1080\nbne 7f\n"
            "cmp r3,#60\nbeq 1f\ncmp r3,#100\nbne 7f\n"
            "movs r0,#0x17\nbx lr\n1: movs r0,#0x16\nbx lr\n"
            "7: movs r0,#0x23\nbx lr\n"
            "8: pop {r0,r1,r2,r3,r4,lr}\n"
            "9: push.w {r4,r5,r6,r7,r8,lr}\nb.w gst_cont\n.ltorg\n",
        "hdpro_family":
            "push {r4,lr}\nbl get_fpv_gctx\nmov r4,r0\nldr r1,=s_name\n"
            "ldr ip,=strcmp_arm\nblx ip\ncmp r0,#0\nbne 1f\n"
            "movw r0,#385\npop {r4,pc}\n"
            "1: mov r0,r4\npop {r4,lr}\npush {r4,lr}\nb.w fsgst_cont\n.ltorg\n",
        "hdpro_vi_geometry":
            "cmp r3,#0x16\nbeq 1f\ncmp r3,#0x17\nbeq 2f\n"
            "ldr r0,=ivv_msg\nb.w ivv_error\n"
            "1: movs r3,#60\nb 3f\n2: movs r3,#100\n"
            "3: movw r1,#1920\nmovw r2,#1080\nstrd r1,r2,[r4,#0x44]\n"
            "str r3,[r4,#0x4c]\nmovs r1,#4\nstr r1,[r4,#0x28]\nb.w ivv_copy\n.ltorg\n",
        "hdpro_main_sensor":
            # r0 is the name buffer; r1 is main's packed video config.
            "push {r4,r5,r6,lr}\nmov r4,r0\nmov r5,r1\nbl bootstrap\n"
            "movs r0,#1\nbl enable_sensor\ncmp r0,#0\nbne 9f\n"
            "bl clock_prepare\ncmp r0,#0\nbne 9f\n"
            "movw r0,#50000\nldr ip,=usleep_arm\nblx ip\ncmp r0,#0\nbne 9f\n"
            "mov r0,r4\nldr r1,=s_name\nldr ip,=strcpy_arm\nblx ip\n"
            "bl get_fpv_gctx\nmovw r1,#1920\nmovw r2,#1080\nmovs r3,#60\n"
            "strd r1,r2,[r0,#0x20]\nstr r3,[r0,#0x28]\n"
            "strh r1,[r5,#10]\nstrh r2,[r5,#12]\nstrb r3,[r5,#14]\n"
            "ldr r0,=s_name\npop {r4,r5,r6,pc}\n"
            # No stock-camera fallback on preparation failure.
            "9: movs r0,#1\nldr ip,=exit_arm\nblx ip\nudf #0\n.ltorg\n",
    }
    for symbol, assembly in source.items():
        address = (Z.NEW_RX_VA + len(builder.rx) + 3) & ~3
        code = Z.assemble(assembly, address, ext, name=symbol)
        assert builder.rx_alloc(code, align=4) == address
        ext[symbol] = address | 1
    builder.expect(0x668fc, "push", "{r4, r5, r6, r7, r8, lr}")
    builder.patch(0x668fc,Z.enc_bw(0x668fc,ext["hdpro_get_sensor_type"]),4,"HD Pro dedicated mode routes; stock fallback preserved")
    builder.expect(0x5aae8,"push","{r4, lr}")
    builder.expect(0x5aaea,"bl")
    builder.patch(0x5aae8,Z.enc_bw(0x5aae8,ext["hdpro_family"]),6,"HD Pro internal family385; stock fallback preserved")
    builder.expect(0x67138,"ldr","r0")
    builder.patch(0x67138,Z.enc_bw(0x67138,ext["hdpro_vi_geometry"]),4,"HD Pro VI geometry60/100")
    builder.expect(0x5a6aa,"bl")
    code=Z.assemble("mov r0,r6\nmov r1,r4\nbl hdpro_main_sensor\nmov r8,r0\nb.w main_join\n",0x5a6aa,ext,name="hdpro_main_hook")
    builder.patch(0x5a6aa,code,0x5a6fc-0x5a6aa,"HD Pro explicit startup; bootstrap, clock, geometry, fail-closed")
    builder.expect(0x66792,"bl")
    builder.patch(0x66792,Z.enc_bl(0x66792,ext['hdpro_isp_init']),4,
                  'Promote sensor transport errors into existing application ISP-init failure path')
    return {"symbols":{n:ext[n] for n in source},"name":name,
            "route_ids":{"60":0x16,"100":0x17},"patches":builder.report["patches"],
            "bootstrap":bootstrap,"capture":capture_report,
            "capture_table_installed":capture,"image_admitted":False}
