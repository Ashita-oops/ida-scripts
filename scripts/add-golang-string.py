import ida_kernwin
import ida_bytes
import idaapi
import ida_search
import idc

def create_string(ea, strlen):
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

def hotkey_pressed():
    ea = idaapi.get_screen_ea()
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
        ida_kernwin.warning("Cannot find length data about string")
        return

    todo_str = ida_bytes.get_strlit_contents(curr_op, length, idaapi.STRTYPE_C)
    if todo_str == None:
        ida_kernwin.warning("Cannot find string at 0x%x" % curr_op)
        return
    
    user_input = ida_kernwin.ask_yn(0, "Do you want to make this string: %s" % todo_str)
    if user_input == 0:
        return
    
    create_string(curr_op, length)

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

