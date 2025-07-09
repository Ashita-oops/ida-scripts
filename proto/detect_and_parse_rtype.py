import idaapi
import idc
import ida_ida
import ida_idp
import ida_typeinf
import subprocess
import json
import os
import re
import traceback

from collections import namedtuple

if idaapi.IDA_SDK_VERSION < 900:
    raise ValueError("Sorry. Current version not supported: IDA_SDK_VERSION = %d < 900" % idaapi.IDA_SDK_VERSION)
if ida_ida.inf_get_procname() != "metapc" and ida_ida.inf_is_64bit():
    raise ValueError("Sorry. Current method detection only works for x64 binaries: " + ida_ida.inf_get_procname())

class GoConvertFailedError(Exception):
    pass

# =========================================================================
#       Golang AST generator
# =========================================================================

GO_PARSE_EXE = "C:\\Users\\null\\Documents\\go_ast\\main.exe"

def interact_with_process(command, input_data):
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,  # Use text mode for string I/O
        shell=True  # Use shell=True for simplicity; set to False for security with list-based commands
    )
    
    stdout, stderr = None, None

    try:
        stdout, stderr = process.communicate(input=input_data, timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        raise GoConvertFailedError(f"Go AST parser {GO_PARSE_EXE} timed out after 10 seconds")
        
    if process.returncode != 0:
        raise GoConvertFailedError(f"Go AST parser {GO_PARSE_EXE} returned with code {process.returncode}")

    return stdout, stderr
    
def get_go_ast(go_src):
    if not os.path.exists(GO_PARSE_EXE):
        raise GoConvertFailedError(f"Go AST parser \"{GO_PARSE_EXE}\" not found")
    
    stdout, stderr = interact_with_process(
                        GO_PARSE_EXE, json.dumps({
                            "go_source": go_src 
                        }) + "\n")

    result = json.loads(stdout)
    if result["status"] != 0:
        raise GoConvertFailedError(result["error"] + f"\n   on {go_src}")
    return result["result"]

def get_typedef_ast(typedef: str):
    # HACK: Sometimes Go adds `.autotmp_` as the field name variable :(
    # we need to manually detect it and change it to proper variable name :(
    if "struct {" in typedef:
        typedef = typedef.replace(" .autotmp_", " autotmp_")
    #                              ^             ^
    #                     NOTE: is the space here enough to detect as field name?

    result = get_go_ast("package main\n"
                        f"type X {typedef}") # yeah, trick :(
    try:
        return result["Decls"][0]["Specs"][0]["Type"]     # shortcut :)
    except Exception as e:
        raise GoConvertFailedError("get_typedef_ast unhandled error: " + e.str())
    
# =========================================================================
#       Golang parser
# =========================================================================

# Following https://tip.golang.org/src/cmd/compile/abi-internal,
# hope that it's generic enough to add new architecture here...
RegMapByArch = namedtuple("RegMapByArch", ['closure_ctx'])
REG_MAPS: dict[tuple[str, int], RegMapByArch] = {
    ("metapc", 64): \
        RegMapByArch(
            closure_ctx = "RDX"
        )
}

def get_procinfo():
    BITS = None
    if ida_ida.inf_is_32bit_exactly():
        BITS = 32
    elif ida_ida.inf_is_64bit():
        BITS = 64
    procname = ida_ida.inf_get_procname()
    return procname, BITS

def get_closure_ctx_reg():
    procinfo = get_procinfo()
    if procinfo not in REG_MAPS:
        raise GoConvertFailedError(f"closure context register not defined for architecture {procinfo}")
    return REG_MAPS[procinfo].closure_ctx

def idb_type(typename: str):
    if typename == "int":
        typename = "int64" # depends on machine :v

    # NOTE: do a fuzzy finder here if 
    # direct search doesn't yield a result :)
    tif = ida_typeinf.tinfo_t()
    if tif.get_named_type(typename):
        return typename
    
    # HACK: For newly created struct, e.g
    # *struct { ... }, there's no
    # pointer type with name to it.
    #
    # So we return name as '*' + type :)
    if typename.startswith('_ptr_'):
        typename_without_ptr = typename[len('_ptr_'):]
        if tif.get_named_type(typename_without_ptr):
            return '*' + typename_without_ptr

    # raise GoConvertFailedError(f'typename {typename} does not exist')
    print(f'typename {typename} does not exist')

def create_struct_from_strtypes(
    names_and_types: list[tuple[str, str]], 
    struct_typename: str | None = None,
    existing_tif: ida_typeinf.tinfo_t = None,
) -> ida_typeinf.tinfo_t:
    
    if existing_tif:
        tif = existing_tif
    else:
        tif = ida_typeinf.tinfo_t()
    
    udt = ida_typeinf.udt_type_data_t()
    tif.create_udt(udt)
    if struct_typename:
        tif.set_named_type(None, struct_typename)

    for varname, typename in names_and_types:
        udm = ida_typeinf.udm_t()
        udm.name = varname
        udm.offset = tif.get_unpadded_size() * 8
        udm.type = ida_typeinf.tinfo_t(typename)
        udm.size = udm.type.get_size() * 8
        tif.add_udm(udm)

    return tif

def make_new_struct(ast_type, **ctx) -> str: # ctx could be parent function name/ etc...
    if ast_type["NodeType"] != 'StructType':
        return ""
    
    fields = ast_type["Fields"]["List"]
    if not fields: # struct {}
        fields = []
    
    field_names_and_types = []

    for field in fields:
        field_type = resolve_type(field["Type"])

        for i, name in enumerate(field["Names"]):
            # TODO: if it's SelectorExpr 
            # -> we need to search for the struct name in the whole database
            if name["NodeType"] != "Ident": 
                raise GoConvertFailedError(f"make_new_struct: unhandled: {field['Names'][i]['NodeType'] = }")
            
            field_names_and_types.append((name["Name"], field_type))

    #  Special case:
    #      *struct {F uintptr; ...} 
    #  -> F will be interpreted as a function
    
    is_likely_closure = (
        field_names_and_types and 
        field_names_and_types[0][0] == 'F' and 
        field_names_and_types[0][1] == 'uintptr' 
    )

    struct_typename = f"MyStruct_{os.urandom(4).hex()}"
    tif = create_struct_from_strtypes(
            field_names_and_types,
            struct_typename        
          )

    if is_likely_closure:
        ok, udm0 = tif.get_udm(field_names_and_types[0][0])

        # Make a func :)

        udm0_funcdef = "void* (__usercall *)"
        udm0_funcdef += "("

        # I hate IDA documents :(
        # don't know how to use argloc_t :<<
        curr_reg = None
        udm0_funcargs = []
        for varname, typename in field_names_and_types:
            # typedef = "void (__usercall *F)(_ptr_peer_Conn@<rax>, void *@<rdx>)"
            udm0_funcargs.append(f'{typename} {varname}@<>')
        udm0_funcdef += ")"

    print(f'Created struct {struct_typename}')

    return struct_typename

def make_new_closure_struct(ast_type, **ctx) -> str:
    if ast_type["NodeType"] != "FuncType":
        return ""
    
    fields = []
    if ast_type["Params"] and ast_type["Params"]["List"]:
        fields = ast_type["Params"]["List"]

    results = []
    if ast_type["Results"] and ast_type["Results"]["List"]:
        results = ast_type["Results"]["List"]

    # Unknown argument names will be set to
    # anon_0, anon_1, anon_2, ..., etc.
    i_anonvar = 0
    arg_names_and_types = []
    for field in fields:
        field_type = resolve_type(field["Type"])

        if field["Names"] == None:
            arg_names_and_types.append((f'anon_{i_anonvar}', field_type))
            i_anonvar += 1
            continue

        for i, name in enumerate(field["Names"]):
            if name["NodeType"] != "Ident": 
                raise GoConvertFailedError(f"make_new_closure_struct: unhandled: {field['Names'][i]['NodeType'] = }")
            arg_names_and_types.append((name["Name"], field_type))

    # We do the same for return type
    i_anonvar = 0
    ret_names_and_types = []
    for result in results:
        field_type = resolve_type(result["Type"])
        ret_names_and_types.append((f'anon_{i_anonvar}', field_type))
        i_anonvar += 1

    funcinfo = ida_typeinf.func_type_data_t()
    for varname, typename in arg_names_and_types:
        funcarg = ida_typeinf.funcarg_t()
        funcarg.name = varname
        funcarg.type = ida_typeinf.tinfo_t(typename)
        funcinfo.push_back(funcarg)

    udt = ida_typeinf.udt_type_data_t()
    funcinfo.rettype.create_udt(udt)

    for varname, typename in arg_names_and_types:
        udm = ida_typeinf.udm_t()
        udm.name = varname
        udm.offset = funcinfo.rettype.get_unpadded_size() * 8
        udm.type = ida_typeinf.tinfo_t(typename)
        udm.size = udm.type.get_size() * 8
        funcinfo.rettype.add_udm(udm)

    # Resolve arguments into registers
    # in Golang-style
    funcinfo.cc = ida_typeinf.CM_CC_GOLANG
    processor = ida_idp.get_ph()
    if (retval := processor.calc_arglocs(funcinfo)) != 1:
        raise GoConvertFailedError(f'make_new_closure_struct: calc_arglocs failed: {retval = }')
    if (retval := processor.calc_retloc(funcinfo.retloc, funcinfo.rettype, ida_typeinf.CM_CC_GOLANG)) != 1:
        raise GoConvertFailedError(f'make_new_closure_struct: calc_retloc failed: {retval = }')

    # Change back to custom calling to
    # add closure context register :)
    funcinfo.cc = ida_typeinf.CM_CC_SPECIAL

    # Create closure object
    closure_struct_typename = f"MyStruct_{os.urandom(4).hex()}"

    tif = ida_typeinf.tinfo_t()
    udt = ida_typeinf.udt_type_data_t()
    tif.create_udt(udt)
    if closure_struct_typename:
        tif.set_named_type(None, closure_struct_typename)

    for varname, typename in [('F', idb_type("uintptr"))] + arg_names_and_types:
        udm = ida_typeinf.udm_t()
        udm.name = varname
        udm.offset = tif.get_unpadded_size() * 8
        udm.type = ida_typeinf.tinfo_t(typename)
        udm.size = udm.type.get_size() * 8
        tif.add_udm(udm)

    tif_closure = tif

    # Add closure context register to functype
    func_closure_arg = ida_typeinf.funcarg_t()
    func_closure_arg.name = "closure_ctx"
    func_closure_arg.type.create_ptr(tif_closure)
    func_closure_arg.argloc.set_reg1(idaapi.str2reg(get_closure_ctx_reg()))
    funcinfo.push_back(func_closure_arg)

    functype = idaapi.tinfo_t()
    if not functype.create_func(funcinfo):
        raise GoConvertFailedError("make_new_closure_struct: create_func failed")

    # Set F as func pointer :)
    ptrfntype = idaapi.tinfo_t()
    ptrfntype.create_ptr(functype)
    tif_closure.set_udm_type(0, ptrfntype)


def resolve_type(ast_type, **ctx) -> str:
    node_type = ast_type["NodeType"]

    if node_type == "StructType":
        return make_new_struct(ast_type, **ctx)
    
    if node_type == "FuncType":
        return make_new_closure_struct(ast_type, **ctx)

    if node_type == "StarExpr":
        return idb_type('_ptr_' + resolve_type(ast_type["X"], **ctx))
    
    if node_type == "Ident":
        return idb_type(ast_type["Name"])

    if node_type == "SelectorExpr":
        return idb_type(ast_type["X"]["Name"] + "_" + ast_type["Sel"]["Name"])

    if node_type == "ChanType":
        if ast_type["Dir"] == "SEND":
            return idb_type("_chan_left_chan_" + resolve_type(ast_type["Value"], **ctx))
        if ast_type["Dir"] == "RECV":
            return idb_type("chan_chan_left__" + resolve_type(ast_type["Value"], **ctx)) # this is me bullshiting...
        if ast_type["Dir"] == "BOTH":
            return idb_type("chan_" + resolve_type(ast_type["Value"], **ctx))

    raise GoConvertFailedError(f"get_simple_type: unhandled {ast_type['NodeType'] = }")

# =========================================================================
#       IDA C-tree parser
# =========================================================================

class runtime_newobject_finder(idaapi.ctree_visitor_t):
    def __init__(self, ea):
        idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST | idaapi.CV_INSNS)
        self.ea = ea
        self.found = (
            None,   # return item
            None,   # call item
            None,   # 1st argument item 
        )

    def visit_insn(self, item: idaapi.citem_t):
        if item.ea != self.ea:
            return 0
        
        # I wonder if there's an expression that 
        # has nothing on the right...?
        if item.op != idaapi.cit_expr:
            return 0
        if not item.cexpr.y:
            return 0
        
        # Is this enough checks?
        call_item = None
        if item.cexpr.y.op == idaapi.cot_call: # ... = runtime_newobject(...)
            call_item = item.cexpr.y
        elif item.cexpr.y.op == idaapi.cot_cast and item.cexpr.y.x.op == idaapi.cot_call: # ... = (type*) runtime_newobject(...)
            call_item = item.cexpr.y.x
        else:
            return 0

        if call_item.x.dstr() != 'runtime_newobject':
            return 0
        
        # Unwrap unnecessary tokens like
        # casting and referencing...
        # ex.: (type*)&struct_1234 <- we want to reach struct_1234 :)
        call_arg_item = None
        if call_item.a.size() != 0:
            depth = 1
            call_arg_item = call_item.a[0]
            while depth <= 3:
                if not call_arg_item:
                    break
                if call_arg_item.op == idaapi.cot_obj:
                    break
                # Casting and referencing always uses .x to move to
                # an inner expression... hope this is enough...
                call_arg_item = call_arg_item.x
                depth += 1   
        
        self.found = (item.cexpr.x, call_item, call_arg_item) 
        return 1 # stop enumeration
    
def get_ctree_item(ea):
    # widget = ida_kernwin.get_current_widget()
    # vdui = idaapi.get_widget_vdui(widget)
    vdui = idaapi.open_pseudocode(ea, 0)
    finder = runtime_newobject_finder(ea)
    finder.apply_to(vdui.cfunc.body, None)
    return finder.found
    
def extract_type_runtime_new_object(
    ret_item: idaapi.cexpr_t,
    call_item: idaapi.cexpr_t,
    arg_item: idaapi.cexpr_t
):
    if not arg_item:
        print("cannot extract argument item from function!")
        return
    if not arg_item.obj_ea:
        print("cannot extract argument EA from function!")
        return
    
    rodata_segm = idaapi.get_segm_by_name('.rodata')
    if not rodata_segm:
        print("cannot extract .rodata details!")
        return

    # Need to find a way to detect this....
    is_little_endian = True
    endianness = ('little' if is_little_endian else 'big')
    get_size = (8 if ida_ida.inf_is_64bit() else 4)
    
    rtype_ea = arg_item.obj_ea
    rtype_stroff_addr = rtype_ea + 0x28 # offset of func declarion relative to .rodata section
    rtype_stroff = idc.get_bytes(rtype_stroff_addr, get_size)

    if rtype_stroff == None:
        print("Cannot get stroff from RTYPE!")
        return

    rtype_stroff = int.from_bytes(rtype_stroff, endianness)
    rtype_str_addr = rodata_segm.start_ea + rtype_stroff

    # Not sure if it takes 2 bytes...?
    rtype_str_size = idc.get_bytes(rtype_str_addr + 1, 1)
    if rtype_str_size == None:
        print("Cannot get str size from RTYPE!")
        return
    
    rtype_str_size = rtype_str_size[0]
    rtype_str = idc.get_bytes(rtype_str_addr + 2, rtype_str_size)
    return rtype_str

if __name__ == '__main__':
    # ret_item, call_item, arg_item = get_ctree_item(idaapi.get_screen_ea())

    # rtype_str = extract_type_runtime_new_object(ret_item, call_item, arg_item)
    # if not rtype_str:
    #     print("what the f")
    #     exit(-1)

    # ast_type = get_typedef_ast(rtype_str.decode())
    ast_type = get_typedef_ast("func (int, int) (int, int)")
    try:
        print(resolve_type(ast_type))
    except Exception as e:
        print("Dumped JSON:")
        print(json.dumps(ast_type, indent=4))
        print("\nDetailed traceback:")
        # Print formatted traceback with file name and line numbers
        traceback.print_exc()
