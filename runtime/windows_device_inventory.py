"""Read current Windows PnP/IPv4 state through SetupAPI and IP Helper.

Same ContainerId correlation inputs as the PowerShell provider, without WMI or
helper-process startup. No address/adapter/driver changes. Missing correlation
properties never become inferred matches.
"""
from __future__ import annotations
import ctypes as C
from ctypes import wintypes as W
import os
import re
import socket
import uuid
from datetime import datetime,timezone


class NativeInventoryUnavailable(RuntimeError):pass
class NativeInventoryError(RuntimeError):pass


class GUID(C.Structure):
    _fields_=[('Data1',C.c_uint32),('Data2',C.c_uint16),('Data3',C.c_uint16),('Data4',C.c_ubyte*8)]
    @classmethod
    def parse(cls,value):return cls.from_buffer_copy(uuid.UUID(value).bytes_le)
    def text(self):return '{'+str(uuid.UUID(bytes_le=bytes(self))).upper()+'}'


class DEVINFO(C.Structure):
    _fields_=[('cbSize',C.c_uint32),('ClassGuid',GUID),('DevInst',C.c_uint32),('Reserved',C.c_size_t)]
class DEVPROPKEY(C.Structure):
    _fields_=[('fmtid',GUID),('pid',C.c_uint32)]
class SOCKET_ADDRESS(C.Structure):
    _fields_=[('address',C.c_void_p),('length',C.c_int)]
class UNICAST(C.Structure):pass
UNICAST._fields_=[('Length',C.c_uint32),('Flags',C.c_uint32),('Next',C.POINTER(UNICAST)),
    ('Address',SOCKET_ADDRESS),('PrefixOrigin',C.c_int),('SuffixOrigin',C.c_int),('DadState',C.c_int),
    ('ValidLifetime',C.c_uint32),('PreferredLifetime',C.c_uint32),('LeaseLifetime',C.c_uint32),('OnLinkPrefixLength',C.c_ubyte)]
class ADAPTER(C.Structure):pass
ADAPTER._fields_=[('Length',C.c_uint32),('IfIndex',C.c_uint32),('Next',C.POINTER(ADAPTER)),
    ('AdapterName',C.c_char_p),('FirstUnicastAddress',C.POINTER(UNICAST)),('FirstAnycastAddress',C.c_void_p),
    ('FirstMulticastAddress',C.c_void_p),('FirstDnsServerAddress',C.c_void_p),('DnsSuffix',C.c_wchar_p),
    ('Description',C.c_wchar_p),('FriendlyName',C.c_wchar_p),('PhysicalAddress',C.c_ubyte*8),
    ('PhysicalAddressLength',C.c_uint32),('Flags',C.c_uint32),('Mtu',C.c_uint32),('IfType',C.c_uint32),
    ('OperStatus',C.c_int),('Ipv6IfIndex',C.c_uint32),('ZoneIndices',C.c_uint32*16),('FirstPrefix',C.c_void_p),
    ('TransmitLinkSpeed',C.c_uint64),('ReceiveLinkSpeed',C.c_uint64)]


def _api():
    if os.name!='nt':raise NativeInventoryUnavailable('Native Windows inventory requires Windows')
    try:
        setup=C.WinDLL('setupapi',use_last_error=True);cfg=C.WinDLL('cfgmgr32',use_last_error=True);ip=C.WinDLL('iphlpapi',use_last_error=True)
        signatures={
            'SetupDiGetClassDevsW':([C.c_void_p,W.LPCWSTR,C.c_void_p,C.c_uint32],C.c_void_p),
            'SetupDiEnumDeviceInfo':([C.c_void_p,C.c_uint32,C.POINTER(DEVINFO)],W.BOOL),
            'SetupDiGetDeviceInstanceIdW':([C.c_void_p,C.POINTER(DEVINFO),W.LPWSTR,C.c_uint32,C.POINTER(C.c_uint32)],W.BOOL),
            'SetupDiGetDeviceRegistryPropertyW':([C.c_void_p,C.POINTER(DEVINFO),C.c_uint32,C.POINTER(C.c_uint32),C.c_void_p,C.c_uint32,C.POINTER(C.c_uint32)],W.BOOL),
            'SetupDiGetDevicePropertyW':([C.c_void_p,C.POINTER(DEVINFO),C.POINTER(DEVPROPKEY),C.POINTER(C.c_uint32),C.c_void_p,C.c_uint32,C.POINTER(C.c_uint32),C.c_uint32],W.BOOL),
            'SetupDiOpenDevRegKey':([C.c_void_p,C.POINTER(DEVINFO),C.c_uint32,C.c_uint32,C.c_uint32,C.c_uint32],C.c_void_p),
            'SetupDiDestroyDeviceInfoList':([C.c_void_p],W.BOOL),
        }
        for name,(args,result)in signatures.items():getattr(setup,name).argtypes=args;getattr(setup,name).restype=result
        cfg.CM_Get_DevNode_Status.argtypes=[C.POINTER(C.c_uint32),C.POINTER(C.c_uint32),C.c_uint32,C.c_uint32];cfg.CM_Get_DevNode_Status.restype=C.c_uint32
        ip.GetAdaptersAddresses.argtypes=[C.c_uint32,C.c_uint32,C.c_void_p,C.c_void_p,C.POINTER(C.c_uint32)];ip.GetAdaptersAddresses.restype=C.c_uint32
        return setup,cfg,ip
    except (AttributeError,OSError)as e:raise NativeInventoryUnavailable(str(e))from e


def _property(setup,handle,info,code):
    buf=C.create_unicode_buffer(4096);kind=C.c_uint32();size=C.c_uint32()
    if not setup.SetupDiGetDeviceRegistryPropertyW(handle,C.byref(info),code,C.byref(kind),buf,C.sizeof(buf),C.byref(size)):
        return None
    return buf.value


def _container(setup,handle,info):
    key=DEVPROPKEY(GUID.parse('8c7ed206-3f8a-4827-b3ab-ae9e1faefc6c'),2)
    value=GUID();kind=C.c_uint32();size=C.c_uint32()
    if not setup.SetupDiGetDevicePropertyW(handle,C.byref(info),C.byref(key),C.byref(kind),C.byref(value),16,C.byref(size),0):return None
    return value.text()if kind.value==13 and size.value==16 and any(bytes(value))else None


def _adapter_id(value):
    try:return str(uuid.UUID(str(value).strip('{}'))).upper()
    except (ValueError,TypeError,AttributeError):return None


def _pnp(setup,cfg,pattern):
    import winreg
    handle=setup.SetupDiGetClassDevsW(None,None,None,6) # DIGCF_PRESENT | DIGCF_ALLCLASSES
    if handle in (None,C.c_void_p(-1).value):raise NativeInventoryError('SetupAPI device enumeration failed')
    rows=[]
    try:
        for index in range(8192):
            info=DEVINFO();info.cbSize=C.sizeof(info)
            if not setup.SetupDiEnumDeviceInfo(handle,index,C.byref(info)):
                if C.get_last_error()==259:break
                raise NativeInventoryError('SetupAPI enumeration did not complete')
            name=C.create_unicode_buffer(4096);required=C.c_uint32()
            if not setup.SetupDiGetDeviceInstanceIdW(handle,C.byref(info),name,len(name),C.byref(required)):
                raise NativeInventoryError('Device instance ID changed during enumeration')
            pnp=name.value
            # Device-class/description reads are local registry queries, not WMI.
            known=bool(re.search(pattern,pnp,re.I))
            if not known and not pnp.upper().startswith('USB\\'):continue
            klass=_property(setup,handle,info,7)or''
            description=_property(setup,handle,info,0)or''
            friendly=_property(setup,handle,info,12)or description
            if not known and not(klass.lower()=='net'and re.search(r'RNDIS|Remote NDIS|USB Ethernet',description,re.I)):continue
            status=C.c_uint32();problem=C.c_uint32()
            result=cfg.CM_Get_DevNode_Status(C.byref(status),C.byref(problem),info.DevInst,0)
            if result:raise NativeInventoryError('Device node changed during inventory')
            row={'Name':friendly,'Status':'OK'if problem.value==0 else'Error','PNPClass':klass,
                 'DeviceID':pnp,'PNPDeviceID':pnp,'ContainerId':_container(setup,handle,info),'description':description,'known':known}
            if klass.lower()=='net':
                key=setup.SetupDiOpenDevRegKey(handle,C.byref(info),1,0,2,0x20019)
                if key not in(None,C.c_void_p(-1).value):
                    try:row['adapter_id']=_adapter_id(winreg.QueryValueEx(key,'NetCfgInstanceId')[0])
                    except OSError:row['adapter_id']=None
                    finally:winreg.CloseKey(key)
            rows.append(row)
        else:raise NativeInventoryError('Device enumeration exceeded its bound')
    finally:setup.SetupDiDestroyDeviceInfoList(handle)
    return rows


def _addresses(ip):
    size=C.c_uint32(16384)
    for attempt in range(3):
        if size.value>4*1048576:raise NativeInventoryError('IP inventory size exceeded its bound')
        buf=C.create_string_buffer(size.value)
        result=ip.GetAdaptersAddresses(socket.AF_INET,0x1e,None,buf,C.byref(size))
        if result==111:continue
        if result==232:return {}
        if result:raise NativeInventoryError('IP Helper inventory failed: '+str(result))
        pointer=C.cast(buf,C.POINTER(ADAPTER));rows={};seen=set()
        while pointer:
            address=C.addressof(pointer.contents)
            if address in seen or len(seen)>=512:raise NativeInventoryError('Invalid IP adapter list')
            seen.add(address);adapter=pointer.contents
            if adapter.Length<C.sizeof(ADAPTER):raise NativeInventoryError('Unsupported IP adapter structure')
            key=_adapter_id((adapter.AdapterName or b'').decode('ascii','strict'))
            ips=[];unicast=adapter.FirstUnicastAddress;visited=set()
            while unicast:
                at=C.addressof(unicast.contents)
                if at in visited or len(visited)>=256:raise NativeInventoryError('Invalid unicast list')
                visited.add(at);u=unicast.contents
                if u.Length<C.sizeof(UNICAST):raise NativeInventoryError('Unsupported unicast structure')
                if u.Address.address and u.Address.length>=16 and C.c_ushort.from_address(u.Address.address).value==socket.AF_INET:
                    ips.append({'IPAddress':socket.inet_ntoa(C.string_at(u.Address.address+4,4)),
                        'PrefixLength':int(u.OnLinkPrefixLength),'PrefixOrigin':u.PrefixOrigin,
                        'SuffixOrigin':u.SuffixOrigin,'AddressState':u.DadState})
                unicast=u.Next
            if key:
                if key in rows:raise NativeInventoryError('Duplicate network adapter GUID')
                rows[key]={'Name':adapter.FriendlyName or None,'InterfaceDescription':adapter.Description or None,
                    'ifIndex':adapter.IfIndex,'Status':'Up'if adapter.OperStatus==1 else'Not Present'if adapter.OperStatus==6 else'Down',
                    'MacAddress':'-'.join(f'{b:02X}'for b in bytes(adapter.PhysicalAddress)[:min(adapter.PhysicalAddressLength,8)]),
                    'LinkSpeed':int(adapter.TransmitLinkSpeed)or None,'IPv4':ips}
            pointer=adapter.Next
        return rows
    raise NativeInventoryError('IP inventory changed repeatedly')


def merge(pnp,adapters):
    """Join only exact current network GUIDs; never guess by address/name."""
    usb=[{k:v for k,v in row.items()if k not in('description','known','adapter_id')}for row in pnp if row['known']]
    network=[];used=set()
    for row in pnp:
        if row['PNPClass'].lower()!='net':continue
        key=row.get('adapter_id');adapter=adapters.get(key)
        if adapter is None:
            raise NativeInventoryError('A present receiver network device has no current IP Helper counterpart')
        if key in used:raise NativeInventoryError('Two device nodes claim the same network adapter GUID')
        used.add(key)
        if adapter['Status']=='Not Present':continue
        network.append({**adapter,'PnPDeviceID':row['PNPDeviceID'],'ContainerId':row['ContainerId']})
    return {'platform':'Windows','supported':True,'usb':usb,'network':network,
            'captured_at':datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),'provider':'SetupAPI+IPHelper'}


def collect(vid_pattern):
    setup,cfg,ip=_api()
    return merge(_pnp(setup,cfg,vid_pattern),_addresses(ip))


if __name__=='__main__':
    import sys,json
    try:
        if len(sys.argv)!=2:raise NativeInventoryError('An inventory VID pattern is required')
        print(json.dumps(collect(sys.argv[1]),separators=(',',':')))
    except NativeInventoryUnavailable as exc:
        print(str(exc),file=sys.stderr);sys.exit(3)
    except Exception as exc:
        print(type(exc).__name__+': '+str(exc),file=sys.stderr);sys.exit(1)
