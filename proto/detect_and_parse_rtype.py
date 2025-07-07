import idaapi
import idc
import ida_ida
import ida_kernwin
import subprocess
import json
import os

from collections import namedtuple

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
        raise GoConvertFailedError(result["error"])
    return result["result"]

def get_typedef_ast(typedef):
    result = get_go_ast("package main\n"
                        f"type X {typedef}") # yeah, trick :(
    try:
        return result["Decls"][0]["Specs"][0]["Type"]     # shortcut :)
    except Exception as e:
        raise GoConvertFailedError("get_typedef_ast unhandled error: " + e.str())
    
# =========================================================================
#       Golang parser
# =========================================================================

def get_type_info(typename: str):
    # TODO: implement here
    # fuzzy finder is enough?
    pass

def make_new_struct(ast_type, **ctx) -> str: # ctx could be parent function name/ etc...
    if ast_type["NodeType"] != 'StructType':
        return ""
    
    fields = ast_type["Fields"]["List"]
    if not fields: # struct {}
        names_and_types = []
    else:
    
    names_and_types = []

    for field in fields:
        field_type = get_type(field["Type"])

        for i, name in enumerate(field["Names"]):
            # TODO: if it's SelectorExpr 
            # -> we need to search for the struct name in the whole database
            if name["NodeType"] != "Ident": 
                raise GoConvertFailedError(f"create_struct: unhandled: {field['Names'][i]['NodeType'] = }")
            
            names_and_types.append((name["Name"], field_type))

    #  Special case:
    #      *struct {F uintptr; ...} 
    #  -> F will be interpreted as a function
    
    is_likely_closure = (
        names_and_types and 
        names_and_types[0][0] == 'F' and 
        names_and_types[0][1] == 'uintptr' 
    )

    return ""

def get_type(ast_type, **ctx):
    node_type = ast_type["NodeType"]

    if node_type == "StarExpr":
        return '_ptr_' + get_type(ast_type["X"], **ctx)
    
    if node_type == "Ident":
        return ast_type["Name"]

    if node_type == "SelectorExpr":
        return ast_type["X"]["Name"] + "_" + ast_type["Sel"]["Name"]

    if node_type == "ChanType":
        if ast_type["Dir"] == "SEND":
            return "_chan_left_chan_" + get_type(ast_type["Value"], **ctx)
        if ast_type["Dir"] == "RECV":
            return "chan_chan_left__" + get_type(ast_type["Value"], **ctx) # this is me bullshiting...
        if ast_type["Dir"] == "BOTH":
            return "chan_" + get_type(ast_type["Value"], **ctx)
        
    if node_type == "StructType":
        return make_new_struct(ast_type, **ctx)

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
    ret_item, call_item, arg_item = get_ctree_item(idaapi.get_screen_ea())

    rtype_str = extract_type_runtime_new_object(ret_item, call_item, arg_item)
    if not rtype_str:
        print("what the f")
        exit(-1)

    ast_type = get_typedef_ast(rtype_str.decode())
    get_struct_type(ast_type)
