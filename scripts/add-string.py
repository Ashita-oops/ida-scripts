import ida_kernwin
import ida_bytes
import idaapi
import ida_search
import idc
import ida_ida

'''
NOTE: Handle for 64-bit only :v
'''

def create_string(ea, strlen):
    if strlen == None or strlen < 0:
        return

    str_value = ida_bytes.get_strlit_contents(ea, strlen, idaapi.STRTYPE_C)
    if str_value == None:
        return
    if len(str_value) != strlen:
        return

    ida_bytes.del_items(ea)
    if not ida_bytes.create_strlit(ea, strlen, idaapi.STRTYPE_C):
        print('Unable to make a string @ 0x%x with length of %d' % (ea, strlen))

def str2int(txt: str):
    if txt.endswith('h'):
        try:
            return int(txt[:-1], 16)
        except:
            return None
    try:
        return int(txt, 10)
    except:
        return None

def get_ea_by_name(label: str):
    return idc.get_name_ea_simple(label)

def is_rodata_addr(ea):
    if idc.get_segm_start(ea) == idc.BADADDR:
        return False
    return idc.get_segm_name(ea) == '.rodata' or idc.get_segm_name(ea) == '.data'

def is_code_addr(ea):
    if idc.get_segm_start(ea) == idc.BADADDR:
        return False
    return idc.get_segm_name(ea) == '.text'

def is_small_int(val):
    return 0 <= val < 2**32

def handle_ea_in_rodata(ea):
    wordlen = 8
    if ida_ida.inf_is_32bit_exactly():
        wordlen = 4

    probable_addr = ida_bytes.get_bytes(ea, wordlen)
    probable_addr = int.from_bytes(probable_addr, 'little')
    probable_len  = ida_bytes.get_bytes(ea+wordlen, wordlen)
    probable_len  = int.from_bytes(probable_len, 'little')

    if not is_rodata_addr(probable_addr) or not is_small_int(probable_len):
        length = ida_kernwin.ask_long(-1, "Detect @ 0x%x as start of a string.\n Please manually add length for string:" % ea)
        if length != None:
            create_string(ea, length)
        return

    todo_str = ida_bytes.get_strlit_contents(probable_addr, probable_len, idaapi.STRTYPE_C)

    length = ida_kernwin.ask_long(probable_len, "Detect @ 0x%x as pointer to string:\n%s\nPlease confirm length of string:" % (probable_addr, todo_str))
    if length != None:
        create_string(ea, length)

def handle_ea_in_code(ea):
    prev_ea = ida_search.find_code(ea, ida_search.SEARCH_UP)
    next_ea = ida_search.find_code(ea, ida_search.SEARCH_DOWN)

    curr_op = get_ea_by_name(idc.print_operand(ea, 1))
    prev_op = str2int(idc.print_operand(prev_ea, 1))
    next_op = str2int(idc.print_operand(next_ea, 1))
    if curr_op == idc.BADADDR:
        ida_kernwin.warning("Cannot find string at 0x%x" % curr_op)
        return

    length = None
    if prev_op != None and next_op != None:
        length = ida_kernwin.ask_long(prev_op, "Choose between 2 lengths: (%d - %d)" % (prev_op, next_op))
    elif prev_op != None:
        length = prev_op
    elif next_op != None:
        length = next_op
    else:
        length = ida_kernwin.ask_long(-1, "Cannot find length data about string.\nDo you want to manually add length?")
        create_string(curr_op, length)
        return

    todo_str = ida_bytes.get_strlit_contents(curr_op, length, idaapi.STRTYPE_C)
    if todo_str == None:
        ida_kernwin.warning("Cannot find string at 0x%x" % curr_op)
        return
    
    length = ida_kernwin.ask_long(length, "Detect @ 0x%x as pointer to string:\n%s\nPlease confirm length of string:" % (curr_op, todo_str))
    if length != None:
        create_string(ea, length)
    
    create_string(curr_op, length)


def hotkey_pressed():
    ea = idaapi.get_screen_ea()
    if is_rodata_addr(ea):
        handle_ea_in_rodata(ea)
    elif is_code_addr(ea):
        handle_ea_in_code(ea)

try:
    hotkey_ctx
    if ida_kernwin.del_hotkey(hotkey_ctx):
        print("Hotkey unregistered!")
        del hotkey_ctx
    else:
        print("Failed to delete hotkey!")
except:
    hotkey_ctx = ida_kernwin.add_hotkey("Ctrl-D", hotkey_pressed)
    if hotkey_ctx is None:
        print("Failed to register hotkey!")
        del hotkey_ctx
    else:
        print("Hotkey registered!")

