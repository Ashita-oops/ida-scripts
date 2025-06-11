import sys
import idc
import time
import idaapi
import idautils

from shims import ida_shims
from collections import deque

# This limits the depth of any individual path, as well as the maximum
# number of paths that will be searched; this is needed for practical
# reasons, as IDBs with tens of thousands of functions take a long time
# to exhaust all possible paths without some practical limitation.
#
# This is global so it's easy to change from the IDAPython prompt.
ALLEYCAT_LIMIT = 10000

def add_to_namespace(namespace, source, name, variable):
    '''
    Add a variable to a different namespace, likely __main__.
    '''
    import importlib

    importer_module = sys.modules[namespace]
    if source in list(sys.modules.keys()):
        if not (sys.version_info.major == 3 and sys.version_info.minor >= 4):
            import imp
            imp.reload(sys.modules[source])
        else:
            importlib.reload(sys.modules[source])
    else:
        m = importlib.import_module(source, None)
        sys.modules[source] = m

    setattr(importer_module, name, variable)

class AlleyCatColor:
    GRAPH_EDGE_NODE = 0xff007b
    GRAPH_START_NODE = 0x483882
    GRAPH_END_NODE = 0x1f130e

class AlleyCatException(Exception):
    pass

class AlleyCatPathNode(object):
    '''
    Class which stores 
    '''
    def __init__(self, ea: int, xrefs: list['AlleyCatPathNode'] = None):
        self.ea = ea
        self.xrefs = xrefs if xrefs != None else []
        self.xrefs_eas = set()
        if xrefs:
            for xref in xrefs:
                self.xrefs_eas.add(xref.ea)

    def add_xref(self, xref_node: 'AlleyCatPathNode'):
        if xref_node.ea in self.xrefs_eas:
            return
        self.xrefs_eas.add(xref_node.ea)
        self.xrefs.append(xref_node)


class AlleyCat(object):
    '''
    Class which resolves code paths. This is where most of the work is done.
    '''

    def _name(self, ea):
        name = ida_shims.get_name(ea)
        if name:
            return name

        name = ida_shims.get_func_off_str(ea)
        if name:
            return name      

        return '0x%X' % ea

    def _get_code_block(self, ea):
        return idaapi.get_func(ea)

    def __init__(self, start, end, quiet=False):
        '''
        Class constructor.

        @start - The start address.
        @end   - The end address.

        Returns None.
        '''
        global ALLEYCAT_LIMIT
        self.limit = ALLEYCAT_LIMIT
        self.root = None
        self.npaths = 1
        self.quiet = quiet

        # We work backwards via xrefs, so we start at the end and end at the
        # start
        if not self.quiet:
            print("Generating call paths from %s to %s..." % (self._name(end),
                                                              self._name(start)))
        self._build_paths(start, end)
        self._calc_npaths()
        self._debug_print_path()

    def _set_root(self, node):
        self.root = node

    def _build_paths(self, start, end=idc.BADADDR):
        if start == end:
            self._set_root(AlleyCatPathNode(ea=start))
            return

        bfs_queue = deque()
        bfs_queue.append(AlleyCatPathNode(ea=start))
        bfs_visited_nodes = {}

        # Loop until queue exceeds ALLEYCAT_LIMIT :)
        while bfs_queue and len(bfs_queue) < self.limit: 
            callee_node = bfs_queue.popleft()
            # if callee_node.ea in bfs_visited_nodes:
            #     continue
            # if callee_node.ea == end:
            #     self._set_root(callee_node)                
            bfs_visited_nodes[callee_node.ea] = callee_node

            for xref in idautils.XrefsTo(callee_node.ea):
                caller = self._get_code_block(xref.frm)
                if not caller:
                    continue
                
                caller_ea = ida_shims.start_ea(caller)
                if caller_ea in bfs_visited_nodes:
                    caller_node = bfs_visited_nodes[caller_ea]
                else:
                    caller_node = AlleyCatPathNode(ea=caller_ea)
                    bfs_queue.append(caller_node)
                    if caller_ea == end:
                        self._set_root(caller_node)
                
                caller_node.add_xref(callee_node)

    def _calc_npaths(self):
        '''
        Calculate number of paths to target. 
        '''
        pass

    def _debug_print_path(self):
        '''
        Debug path from a node to the end node :)
        '''
        class PrintContext:
            def __init__(self, is_ref_by: int = None, is_parent_last_child: list = None):
                if is_ref_by != None:
                    self.is_ref_by = is_ref_by
                else:
                    self.is_ref_by = 0xffffffff
                    
                if is_parent_last_child != None:                
                    self.is_parent_last_child = is_parent_last_child
                else:
                    self.is_parent_last_child = []

        q = deque()
        v = set()
        q.append((self.root, PrintContext(is_parent_last_child=[True])))

        disp = '.'
        disp += '\n'

        while q:
            node, ctx = q.pop()
            for i in range(len(ctx.is_parent_last_child)):
                if ctx.is_parent_last_child[i]:
                    if i == len(ctx.is_parent_last_child) - 1:
                        disp += '└── '
                    else:
                        disp += '    '
                else:
                    if i == len(ctx.is_parent_last_child) - 1:
                        disp += '├── '
                    else:
                        disp += '│   '

            disp += "0x%x" % node.ea 
            # disp += " (refby = 0x%x)" % ctx.is_ref_by 
            disp += '\n' 
            if node.ea in v:
                disp = disp[:-1] + ' -> ...\n'
                # disp = disp[:-1] + " -(loop)-\n"
                continue

            v.add(node.ea)

            for i, child_node in enumerate(node.xrefs):
                q.append((child_node, PrintContext(
                                        is_ref_by = node.ea,
                                        is_parent_last_child = ctx.is_parent_last_child + [i==0]
                                      )
                ))

        print(disp)

class AlleyCatFunctionPaths(AlleyCat):
    def __init__(self, start_ea, end_ea, quiet=False):
        # We work backwards via xrefs, so we start at the end and end at the start
        try:
            func = idaapi.get_func(end_ea)
            start = ida_shims.start_ea(func)
        except:
            raise AlleyCatException("Address 0x%X is not part of a function!" %
                                    end_ea)
        try:
            func = idaapi.get_func(start_ea)
            end = ida_shims.start_ea(func)
        except:
            end = idc.BADADDR

        super(AlleyCatFunctionPaths, self).__init__(start, end, quiet)


class AlleyCatCodePaths(AlleyCat):
    def __init__(self, start_ea, end_ea, quiet=False):
        end_func = idaapi.get_func(end_ea)
        start_func = idaapi.get_func(start_ea)

        if not start_func:
            raise AlleyCatException("Address 0x%X is not part of a function!" %
                                    start_ea)
        if not end_func:
            raise AlleyCatException("Address 0x%X is not part of a function!" %
                                    end_ea)

        start_func_ea = ida_shims.start_ea(start_func)
        end_func_ea = ida_shims.start_ea(end_func)
        if start_func_ea != end_func_ea:
            raise AlleyCatException("The start and end addresses are not part "
                                    "of the same function!")

        self.func = start_func
        self.blocks = [block for block in idaapi.FlowChart(self.func)]

        # We work backwards via xrefs, so we start at the end and end at the start
        end_block = self._get_code_block(start_ea)
        start_block = self._get_code_block(end_ea)

        if not end_block:
            raise AlleyCatException("Failed to find the code block associated "
                                    "with address 0x%X" % start_ea)
        if not start_block:
            raise AlleyCatException("Failed to find the code block associated "
                                    "with address 0x%X" % end_ea)

        start_block_ea = ida_shims.start_ea(start_block)
        end_block_ea = ida_shims.start_ea(end_block)

        super(AlleyCatCodePaths, self).__init__(
            start_block_ea, end_block_ea, quiet)

    def _get_code_block(self, ea):
        for block in self.blocks:
            start_ea = ida_shims.start_ea(block)
            end_ea = ida_shims.end_ea(block)
            if start_ea <= ea and end_ea > ea:
                return block
        return None


# Everything below here is just IDA UI/Plugin stuff

class AlleyCatGraphHistory(object):
    '''
    Manages include/exclude graph history.
    '''

    INCLUDE_ACTION = 0
    EXCLUDE_ACTION = 1

    def __init__(self):
        self.history = []
        self.includes = []
        self.excludes = []
        self.history_index = 0
        self.include_index = 0
        self.exclude_index = 0

    def reset(self):
        self.history = []
        self.includes = []
        self.excludes = []
        self.history_index = 0
        self.include_index = 0
        self.exclude_index = 0

    def update_history(self, action):
        if self.excludes and len(self.history)-1 != self.history_index:
            self.history = self.history[0:self.history_index+1]
        self.history.append(action)
        self.history_index = len(self.history)-1

    def add_include(self, obj):
        if self.includes and len(self.includes)-1 != self.include_index:
            self.includes = self.includes[0:self.include_index+1]
        self.includes.append(obj)
        self.include_index = len(self.includes)-1
        self.update_history(self.INCLUDE_ACTION)

    def add_exclude(self, obj):
        if len(self.excludes)-1 != self.exclude_index:
            self.excludes = self.excludes[0:self.exclude_index+1]
        self.excludes.append(obj)
        self.exclude_index  = len(self.excludes)-1
        self.update_history(self.EXCLUDE_ACTION)

    def get_includes(self):
        return set(self.includes[0:self.include_index+1])

    def get_excludes(self):
        return set(self.excludes[0:self.exclude_index+1])

    def undo(self):
        if self.history:
            if self.history[self.history_index] == self.INCLUDE_ACTION:
                if self.include_index >= 0:
                    self.include_index -= 1
            elif self.history[self.history_index] == self.EXCLUDE_ACTION:
                if self.exclude_index >= 0:
                    self.exclude_index -= 1

            self.history_index -= 1
            if self.history_index < 0:
                self.history_index = 0

    def redo(self):
        self.history_index += 1
        if self.history_index >= len(self.history):
            self.history_index = len(self.history)-1

        if self.history[self.history_index] == self.INCLUDE_ACTION:
            if self.include_index < len(self.includes)-1:
                self.include_index += 1
        elif self.history[self.history_index] == self.EXCLUDE_ACTION:
            if self.exclude_index < len(self.excludes)-1:
                self.exclude_index += 1


class AlleyCatGraph(idaapi.GraphViewer):
    '''
    Displays the graph and manages graph actions.
    '''
    def __init__(self, results, title="AlleyCat Graph V2"):
        idaapi.GraphViewer.__init__(self, title)
        self.results = results

        self.nodes_ea2id = {}
        self.nodes_id2ea = {}
        self.edges = {}
        self.end_nodes = []
        self.edge_nodes = []
        self.start_nodes = []

        self.history = AlleyCatGraphHistory()
        self.include_on_click = False
        self.exclude_on_click = False

        self.cmd_undo = None
        self.cmd_redo = None
        self.cmd_reset = None
        self.cmd_exclude = None
        self.cmd_include = None
        self.cmd_unhighlight = None

    def Show(self):
        '''
        Display the graph.

        Returns True on success, False on failure.
        '''
        if not idaapi.GraphViewer.Show(self):
            return False
        else:
            self.cmd_undo = self.AddCommand("Undo", "")
            self.cmd_redo = self.AddCommand("Redo", "")
            self.cmd_reset = self.AddCommand("Reset graph", "")
            self.cmd_exclude = self.AddCommand("Exclude node", "")
            self.cmd_include = self.AddCommand("Include node", "")
            self.cmd_unhighlight = self.AddCommand(
                "Temporarily un-highlight all paths", "")
            return True

    def OnRefresh(self):
        # Clear the graph before refreshing
        self.clear()
        
        self.nodes_ea2id = {}
        self.nodes_id2ea = {}
        self.edges = {}
        self.end_nodes = []
        self.edge_nodes = []
        self.start_nodes = []

        includes = self.history.get_includes()
        excludes = self.history.get_excludes()

        for path in self.results:
            parent_node = None

            # Check to see if this path contains all nodes marked for explicit
            # inclusion
            # NOTE: the repeatedly calls to set() increases time :(
            if (set(path) & includes) != includes:
                continue

            # Check to see if this path contains any nodes marked for explicit
            # exclusion
            # NOTE: the repeatedly calls to set() increases time :(
            if (set(path) & excludes) != set():
                continue

            for ea in path:
                # If this node already exists, use its existing node ID
                if ea in self.nodes_ea2id:
                    this_node = self.nodes_ea2id[ea]
                # Else, add this node to the graph
                else:
                    this_node = self.AddNode(self.get_name_by_ea(ea))
                    self.nodes_ea2id[ea] = this_node
                    self.nodes_id2ea[this_node] = ea

                # If there is a parent node, add an edge between the parent node
                # and this one
                if parent_node is not None:
                    self.AddEdge(parent_node, this_node)
                    if this_node not in self.edges[parent_node]:
                        self.edges[parent_node].append(this_node)

                # Update the parent node for the next loop
                parent_node = this_node
                if parent_node not in self.edges:
                    self.edges[parent_node] = []

                # Highlight this node in the disassembly window
                self.highlight(ea)

            try:
                # Track the first, last, and next to last nodes in each path for
                # proper colorization in self.OnGetText.
                self.start_nodes.append(self.nodes_ea2id[path[0]])
                self.end_nodes.append(self.nodes_ea2id[path[-1]])
                self.edge_nodes.append(self.nodes_ea2id[path[-2]])
            except:
                pass

        return True

    def OnGetText(self, node_id):
        color = idc.DEFCOLOR

        if node_id in self.edge_nodes:
            color = 0xff007b
        elif node_id in self.start_nodes:
            color = 0x483882
        elif node_id in self.end_nodes:
            color = 0x1f130e

        return self[node_id], color

    def OnHint(self, node_id):
        hint = ""

        try:
            for edge_node in self.edges[node_id]:
                hint += "%s\n" % self[edge_node]
        except:
            pass

        return hint

    def OnCommand(self, cmd_id):
        if self.cmd_undo == cmd_id:
            if self.include_on_click or self.exclude_on_click:
                self.include_on_click = False
                self.exclude_on_click = False
            else:
                self.history.undo()
            self.Refresh()

        elif self.cmd_redo == cmd_id:
            self.history.redo()
            self.Refresh()

        elif self.cmd_include == cmd_id:
            self.include_on_click = True

        elif self.cmd_exclude == cmd_id:
            self.exclude_on_click = True

        elif self.cmd_reset == cmd_id:
            self.include_on_click = False
            self.exclude_on_click = False
            self.history.reset()
            self.Refresh()

        elif self.cmd_unhighlight == cmd_id:
            self.unhighlight_all()

    def OnClick(self, node_id):
        if self.include_on_click:
            self.history.add_include(self.nodes_id2ea[node_id])
            self.include_on_click = False

        elif self.exclude_on_click:
            self.history.add_exclude(self.nodes_id2ea[node_id])
            self.exclude_on_click = False
        
        self.Refresh()

    def OnDblClick(self, node_id):
        xref_locations = []
        node_ea = self.get_ea_by_name(self[node_id])

        if node_id in self.edges:
            for edge_node_id in self.edges[node_id]:

                edge_node_name = self[edge_node_id]
                edge_node_ea = self.get_ea_by_name(edge_node_name)

                if edge_node_ea != idc.BADADDR:
                    for xref in idautils.XrefsTo(edge_node_ea):
                        # Is the specified node_id the source of this xref?
                        if self.match_xref_source(xref, node_ea):
                            xref_locations.append((xref.frm, edge_node_ea))

        if xref_locations:
            xref_locations.sort()

            print("")
            print("Path Xrefs from %s:" % self[node_id])
            print("-" * 100)
            for (xref_ea, dst_ea) in xref_locations:
                print("%-50s  =>  %s" % (self.get_name_by_ea(xref_ea),
                                         self.get_name_by_ea(dst_ea)))
            print("-" * 100)
            print("")

            ida_shims.jumpto(xref_locations[0][0])
        else:
            ida_shims.jumpto(node_ea)

    def OnClose(self):
        if ida_shims.ask_yn(1, "Path nodes have been highlighted in the "
                               "disassembly window. Undo highlighting?") == 1:
            self.unhighlight_all()

    def match_xref_source(self, xref, source):
        return ((xref.type != idc.fl_F) and
                (ida_shims.get_func_attr(xref.frm, idc.FUNCATTR_START) == source))

    def get_ea_by_name(self, name):
        '''
        Get the address of a location by name.

        @name - Location name

        Returns the address of the named location, or idc.BADADDR on failure.
        '''
        # This allows support of the function offset style names (e.g., main+0C)
        ea = 0
        if '+' in name:
            (func_name, offset) = name.split('+')
            base_ea = ida_shims.get_name_ea_simple(func_name)
            if base_ea != idc.BADADDR:
                try:
                    ea = base_ea + int(offset, 16)
                except:
                    ea = idc.BADADDR
        else:
            ea = ida_shims.get_name_ea_simple(name)
            if ea == idc.BADADDR:
                try:
                    ea = int(name, 0)
                except:
                    ea = idc.BADADDR

        return ea

    def clear(self):
        # Clears the graph and unhighlights the disassembly
        self.Clear()
        self.unhighlight_all()

    def get_name_by_ea(self, ea):
        '''
        Get the name of the specified address.

        @ea - Address.

        Returns a name for the address, one of idc.Name, idc.GetFuncOffset or
        0xXXXXXXXX.
        '''
        name = ida_shims.get_name(ea)
        if name:
            return name

        name = ida_shims.get_func_off_str(ea)
        if name:
            return name
        
        return "0x%X" % ea

    def colorize_node(self, ea, color):
        # Colorizes an entire code block
        func = idaapi.get_func(ea)
        if not func:
            return
        
        for block in idaapi.FlowChart(func):
            block_start_ea = ida_shims.start_ea(block)
            block_end_ea = ida_shims.end_ea(block)

            if block_start_ea <= ea and block_end_ea > ea:
                ea = block_start_ea
                while ea < block_end_ea:
                    idaapi.set_item_color(ea, color)
                    ea = ida_shims.next_head(ea)
                break

    def highlight(self, ea):
        # Highlights an entire code block
        self.colorize_node(ea, 0x41076d)

    def unhighlight(self, ea):
        # Unhighlights an entire code block
        self.colorize_node(ea, idc.DEFCOLOR)

    def unhighlight_all(self):
        # Unhighlights all code blocks
        for path in self.results:
            for ea in path:
                self.unhighlight(ea)


class AlleyCatPaths(object):
    def _current_function(self):
        function = idaapi.get_func(ida_shims.get_screen_ea())
        return ida_shims.start_ea(function)

    def _find_and_plot_paths(self, sources, targets, klass=AlleyCatFunctionPaths):
        results = []

        for target in targets:
            for source in sources:
                s = time.time()
                r = klass(source, target)
                e = time.time()
                print("Found %d paths in %f seconds." % (r.npaths, (e-s)))

                if not r:
                    name = ida_shims.get_name(target)
                    if not name:
                        name = "0x%X" % target
                    print("No paths found to", name)
                    continue
                
                results.append(r.root)

        # TODO: After adding correct stuffs, move back
        results = []
        if not results:
            return

        # Be sure to close any previous graph before creating a new one.
        # Failure to do so may crash IDA.
        try:
            self.graph.Close()
        except:
            pass

        self.graph = AlleyCatGraph(results, 'Path Graph')
        self.graph.Show()

    def _get_user_selected_functions(self, many=False):
        functions = []
        ea = ida_shims.get_screen_ea()
        try:
            current_function = ida_shims.get_func_attr(ea, idc.FUNCATTR_START)
        except:
            current_function = None

        while True:
            function = ida_shims.choose_func(
                "Select a function and click 'OK' until all functions have "
                "been selected. When finished, click 'Cancel' to display the "
                "graph.")

            if ida_shims.get_screen_ea() != ea:
                ida_shims.jumpto(ea)

            if not function or \
                    function == idc.BADADDR or function == current_function:
                break
            elif function not in functions:
                functions.append(function)

            if not many:
                break

        return functions

    def FindPathsToCodeBlock(self):
        target = ida_shims.get_screen_ea()
        source = self._current_function()

        if source:
            self._find_and_plot_paths(
                [source], [target], klass=AlleyCatCodePaths)

    def FindPathsToMany(self):
        source = self._current_function()

        if source:
            targets = self._get_user_selected_functions(many=True)
            if targets:
                self._find_and_plot_paths([source], targets)

    def FindPathsFromMany(self):
        target = self._current_function()

        if target:
            sources = self._get_user_selected_functions(many=True)
            if sources:
                self._find_and_plot_paths(sources, [target])


# Helper functions to execute commands selected from dropdown menus.
# args parameter is required for IDA version < 7.0
def find_paths_from_many(arg=None):
    AlleyCatPaths().FindPathsFromMany()


def find_paths_to_many(arg=None):
    AlleyCatPaths().FindPathsToMany()


def find_paths_to_code_block(args=None):
    AlleyCatPaths().FindPathsToCodeBlock()


try:
    class ToCurrentFromAction(idaapi.action_handler_t):
        def __init__(self):
            idaapi.action_handler_t.__init__(self)

        def activate(self, ctx):
            find_paths_from_many()
            return 1

        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS


    class FromCurrentToAction(idaapi.action_handler_t):
        def __init__(self):
            idaapi.action_handler_t.__init__(self)

        def activate(self, ctx):
            find_paths_to_many()
            return 1

        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS

    class InCurrentFunctionToCurrentCodeBlockAction(idaapi.action_handler_t):
        def __init__(self):
            idaapi.action_handler_t.__init__(self)

        def activate(self, ctx):
            find_paths_to_code_block()
            return 1

        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS
        
except AttributeError:
    pass


class idapathfinder_t(idaapi.plugin_t):
    flags = 0
    comment = ''
    help = ''
    wanted_name = 'AlleyCat'
    wanted_hotkey = ''
    menu_name = 'View/Graphs/'
    menu_context = []

    to_from_action_name = 'tocurrfrom:action'
    from_to_action_name = 'fromcurrto:action'
    curr_func_curr_block_action_name = 'currfunccurrblock:action'

    to_from_menu_name = 'Find paths to the current function from...'
    from_to_menu_name = 'Find paths from the current function to...'
    curr_func_curr_block_menu_name = 'Find paths in the current function to ' \
                                     'the current code block'

    def init(self):
        if idaapi.IDA_SDK_VERSION >= 700:
            # Add ALLEYCAT_LIMIT variable to the global namespace so it can be
            # accessed from the IDA python terminal.
            global ALLEYCAT_LIMIT
            add_to_namespace(
                '__main__', 'alleycat', 'ALLEYCAT_LIMIT', ALLEYCAT_LIMIT)

            # Add functions to global namespace.
            add_to_namespace(
                '__main__', 'alleycat', 'AlleyCatFunctionPaths',
                AlleyCatFunctionPaths)
            add_to_namespace(
                '__main__', 'alleycat', 'AlleyCatCodePaths', AlleyCatCodePaths)
            add_to_namespace(
                '__main__', 'alleycat', 'AlleyCatGraph', AlleyCatGraph)

            to_curr_from_desc = idaapi.action_desc_t(
                self.to_from_action_name, self.to_from_menu_name,
                ToCurrentFromAction(), self.wanted_hotkey,
                'Find paths to the current function from...', 199)

            from_curr_to_desc = idaapi.action_desc_t(
                self.from_to_action_name, self.from_to_menu_name,
                FromCurrentToAction(), self.wanted_hotkey,
                'Find paths from the current function to...', 199)

            curr_func_to_block_desc = idaapi.action_desc_t(
                self.curr_func_curr_block_action_name,
                self.curr_func_curr_block_menu_name,
                InCurrentFunctionToCurrentCodeBlockAction(),
                self.wanted_hotkey,
                'Find paths in the current function to the current code block',
                199)

            idaapi.register_action(to_curr_from_desc)
            idaapi.register_action(from_curr_to_desc)
            idaapi.register_action(curr_func_to_block_desc)

            idaapi.attach_action_to_menu(
                self.menu_name, self.to_from_action_name, idaapi.SETMENU_APP)
            idaapi.attach_action_to_menu(
                self.menu_name, self.from_to_action_name, idaapi.SETMENU_APP)
            idaapi.attach_action_to_menu(
                self.menu_name, self.curr_func_curr_block_action_name,
                idaapi.SETMENU_APP)

        else:
            self.menu_context.append(
                idaapi.add_menu_item(
                    self.menu_name, self.to_from_menu_name, "", 0,
                    find_paths_from_many, (None,)))

            self.menu_context.append(
                idaapi.add_menu_item(
                    self.menu_name, self.from_to_menu_name, "", 0,
                    find_paths_to_many, (None,)))

            self.menu_context.append(
                idaapi.add_menu_item(
                    self.menu_name, self.curr_func_curr_block_menu_name, "", 0,
                    find_paths_to_code_block, (None,)))

        return idaapi.PLUGIN_KEEP

    def term(self):
        if idaapi.IDA_SDK_VERSION >= 700:
            idaapi.detach_action_from_menu(
                self.menu_name, self.to_from_action_name)
            idaapi.detach_action_from_menu(
                self.menu_name, self.from_to_action_name)
            idaapi.detach_action_from_menu(
                self.menu_name, self.curr_func_curr_block_action_name)
        else:
            for context in self.menu_context:
                idaapi.del_menu_item(context)
        return None

    def run(self, arg):
        pass


def PLUGIN_ENTRY():
    return idapathfinder_t()

