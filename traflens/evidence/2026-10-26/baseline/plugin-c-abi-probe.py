import ctypes,sys,resource
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
class Ctx(ctypes.Structure):
    _fields_=[('ip_type',ctypes.c_ubyte),('ip_src',ctypes.c_ubyte*16),('ip_dst',ctypes.c_ubyte*16),('port_src',ctypes.c_ushort),('port_dst',ctypes.c_ushort),('l4_protocol',ctypes.c_ubyte),('proto',ctypes.c_ubyte),('ebpf_type',ctypes.c_ubyte),('time',ctypes.c_ulonglong),('direction',ctypes.c_ubyte),('process_kname',ctypes.c_void_p),('buf_size',ctypes.c_int),('payload_size',ctypes.c_int),('payload',ctypes.c_void_p)]
class Result(ctypes.Structure):
    _fields_=[('proto',ctypes.c_ubyte),('proto_name',ctypes.c_char*16)]
libc=ctypes.CDLL(None);libc.setbuf.argtypes=[ctypes.c_void_p,ctypes.c_void_p];libc.setbuf(ctypes.c_void_p.in_dll(libc,'stdout'),None)
plugin=ctypes.CDLL(sys.argv[1]);plugin.on_check_payload.argtypes=[ctypes.POINTER(Ctx)];plugin.on_check_payload.restype=Result
payload=bytes([58,166,1,32,0,1,0,0,0,0,0,1,5,98,97,105,100,117,3,99,111,109,0,0,1,0,1,0,0,41,4,208,0,0,0,0,0,12,0,10,0,8,115,109,120,32,132,36,153,244])
buf=ctypes.create_string_buffer(payload);name=ctypes.create_string_buffer(b'\0')
ctx=Ctx();ctx.ip_type=4;ctx.port_src=12345;ctx.port_dst=8080;ctx.l4_protocol=6;ctx.time=12345678;ctx.payload_size=len(payload);ctx.payload=ctypes.addressof(buf);ctx.process_kname=1 if sys.argv[2]=='dangling-empty' else ctypes.addressof(name)
print('process_kname:',hex(ctx.process_kname),'offsetof:',Ctx.process_kname.offset,flush=True)
r=plugin.on_check_payload(ctypes.byref(ctx));print('proto:',r.proto,'name:',bytes(r.proto_name),flush=True)
assert r.proto==1
