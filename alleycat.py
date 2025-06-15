import sys
import idc
import time
import idaapi
import idautils
import ida_kernwin
import bisect
import ida_graph

from shims import ida_shims
from collections import deque

if idaapi.IDA_SDK_VERSION < 750:
    raise ValueError("Shoo shoo: IDA_SDK_VERSION = %d < 750" % idaapi.IDA_SDK_VERSION)

# ---------------------------------------------------------------------
#
# This part contains common functions used by the plugin.
#
# ---------------------------------------------------------------------

class AlleyCatCommands:
    '''
    Modes of AlleyCat.
    '''
    FIND_PATH_FROM_MANY = 1
    FIND_PATH_TO_MANY = 2
    FIND_PATH_TO_CODE_BLOCK = 3
    FIND_FUNCTION_XREFS = 4
    
    @classmethod
    def is_xref_mode(cls, cmd_id):
        return cmd_id == cls.FIND_FUNCTION_XREFS
    
    @classmethod
    def is_startend_mode(cls, cmd_id):
        return (cmd_id == cls.FIND_PATH_FROM_MANY or 
                cmd_id == cls.FIND_PATH_TO_MANY or 
                cmd_id == cls.FIND_PATH_TO_CODE_BLOCK)
        
class AlleyCatUtils(object):
    @staticmethod
    def get_ea_by_name(name):
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

    @staticmethod
    def get_name_by_ea(ea):
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
    

    @staticmethod
    def xrefs_from(ea):
        '''
        Find all functions the function containing <ea> calling to.

        @ea - Address.

        Returns a list of addresses.
        '''

        func = idaapi.get_func(ea)
        if not func:
            return []

        start_ea = ida_shims.start_ea(func)
        end_ea = ida_shims.end_ea(func)
        if start_ea == idc.BADADDR or end_ea == idc.BADADDR:
            return []

        xrefs = []
        
        ea = start_ea
        while ea < end_ea:
            for xref in idautils.XrefsFrom(ea):
                # Note: A self-reference function will fail this
                # check. This works best for a normal program. 
                if end_ea <= xref.to or start_ea >= xref.to:
                    xrefs.append(xref)
            
            ea = ida_shims.next_head(ea)
            if ea == idc.BADADDR:
                break

        return xrefs

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
    
# ---------------------------------------------------------------------
#
# This code implements BFS (breath first search) to find paths in this
# graph. While it's quite fast, there's no guarantee that it will keep
# finding children nodes out in Antartica or not, so a memory limit
# is placed in case the memory runs out.
#
# This variable is global so it's easy to change from the IDAPython
# prompt.
#
# ---------------------------------------------------------------------

ALLEYCAT_MEMLIMIT = 10000

class AlleyCatException(Exception):
    pass

class AlleyCatPathNode(object):
    '''
    Class which stores info of a path node in a graph.
    '''
    
    IS_ROOT = 1
    IS_EDGE = 2
    IS_TARGET = 4

    def __init__(self, ea:int, is_root=False, is_target=False):
        self.ea = ea
        self.xrefs_to = []
        self.xrefs_from = []
        self.xrefs_to_eas = set()
        self.xrefs_from_eas = set()
        self.timestamp = time.time() 

        self.status = 0
        if is_root:
            self.status |= self.IS_ROOT
        if is_target:
            self.status |= self.IS_TARGET
        if not is_root and not is_target:
            self.status = self.IS_EDGE

    def add_xref_to(self, xref_to:'AlleyCatPathNode'):
        if xref_to.ea not in self.xrefs_to_eas:
            self.xrefs_to_eas.add(xref_to.ea)
            self.xrefs_to.append(xref_to)

    def add_xref_from(self, xref_from:'AlleyCatPathNode'):
        if xref_from.ea not in self.xrefs_from_eas:
            self.xrefs_from_eas.add(xref_from.ea)
            self.xrefs_from.append(xref_from)

    def is_root(self):
        return self.status & self.IS_ROOT != 0
    def is_target(self):
        return self.status & self.IS_TARGET != 0
    def is_edge(self):
        return self.status & self.IS_EDGE != 0
    def is_outer(self):
        return len(self.xrefs_from) == 0 and len(self.xrefs_to) == 0 
        
class AlleyCatBase(object):
    '''
    Class which includes common functions
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
    
    
    def get_npaths(self):
        return -1

class AlleyCatSE(AlleyCatBase):
    '''
    Class which resolves code paths from starting point to end. This is where most of the work is done.
    '''

    def __init__(self, start, end, quiet=False):
        '''
        Class constructor.

        @start  - The start address.
        @end    - The end address.

        Returns None.
        '''
        global ALLEYCAT_MEMLIMIT
        self.memlimit = ALLEYCAT_MEMLIMIT
        self.root = None
        self.quiet = quiet
        self.nodes = {}
        self.start = start
        self.end = end

        if not self.quiet:
            print("Generating call paths from %s to %s..." % (self._name(start),
                                                              self._name(end)))
        self._build_paths()
        # self._debug_print_path()

    def _set_root(self, node) -> None:
        self.root = node

    def _build_paths(self) -> None:
        if self.start == self.end:
            self._set_root(AlleyCatPathNode(ea=self.end, is_root=True, is_target=True))
            return

        # We work backwards via xrefs_to, so we start at the end and end at the start
        end_node = AlleyCatPathNode(ea=self.end, is_target=True)
        self.nodes[self.end] = end_node
        
        bfs_queue = deque()
        bfs_queue.append(end_node)
        bfs_visited_nodes = set()

        while bfs_queue and len(bfs_queue) < self.memlimit: 
            callee_node = bfs_queue.popleft()
            if callee_node.ea in bfs_visited_nodes:
                continue
            bfs_visited_nodes.add(callee_node.ea)

            for xref_to in idautils.XrefsTo(callee_node.ea):
                caller = self._get_code_block(xref_to.frm)
                if not caller:
                    continue
                
                caller_ea = ida_shims.start_ea(caller)
                
                if caller_ea in self.nodes:
                    caller_node = self.nodes[caller_ea]
                elif caller_ea == self.start:
                    self.nodes[caller_ea] = caller_node = AlleyCatPathNode(ea=caller_ea, is_root=True)
                    self._set_root(caller_node)
                else:
                    self.nodes[caller_ea] = caller_node = AlleyCatPathNode(ea=caller_ea)
                
                caller_node.add_xref_from(callee_node)

                if caller_ea not in bfs_visited_nodes:
                    bfs_queue.append(caller_node)

    def _debug_print_path(self) -> None:
        '''
        Display path from start node to the end node,
        using tree representation.
        '''
        class PrintContext:
            def __init__(self, is_ref_by:int=0xffffffff, is_parent_last_child:list[bool]=None):
                self.is_ref_by = is_ref_by
                    
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
                continue

            v.add(node.ea)

            for i, child_node in enumerate(node.xrefs_to):
                q.append((child_node, PrintContext(
                                        is_ref_by = node.ea,
                                        is_parent_last_child = ctx.is_parent_last_child + [i==0]
                                      )
                ))

        print(disp)

class AlleyCatFunctionPaths(AlleyCatSE):
    def __init__(self, start_ea, end_ea, quiet=False):
        try:
            end = ida_shims.start_ea(idaapi.get_func(end_ea))
        except:
            raise AlleyCatException("Address 0x%X is not part of a function!" %
                                    end_ea)
        try:
            start = ida_shims.start_ea(idaapi.get_func(start_ea))
        except:
            start = idc.BADADDR

        super(AlleyCatFunctionPaths, self).__init__(start, end, quiet)


class AlleyCatCodePaths(AlleyCatSE):
    def __init__(self, start_ea, end_ea, quiet=False):
        start_func = idaapi.get_func(start_ea)
        end_func   = idaapi.get_func(end_ea)

        if not start_func:
            raise AlleyCatException("Address 0x%X is not part of a function!" %
                                    start_ea)
        if not end_func:
            raise AlleyCatException("Address 0x%X is not part of a function!" %
                                    end_ea)

        start_func_ea = ida_shims.start_ea(start_func)
        end_func_ea   = ida_shims.start_ea(end_func)
        if start_func_ea != end_func_ea:
            raise AlleyCatException("The start and end addresses are not part "
                                    "of the same function!")

        self.func   = start_func
        self.blocks = [block for block in idaapi.FlowChart(self.func)]

        start_block = self._get_code_block(start_ea)
        end_block   = self._get_code_block(end_ea)

        if not end_block:
            raise AlleyCatException("Failed to find the code block associated "
                                    "with address 0x%X" % start_ea)
        if not start_block:
            raise AlleyCatException("Failed to find the code block associated "
                                    "with address 0x%X" % end_ea)

        start_block_ea = ida_shims.start_ea(start_block)
        end_block_ea   = ida_shims.start_ea(end_block)

        super(AlleyCatCodePaths, self).__init__(
            start_block_ea, end_block_ea, quiet)

    def _get_code_block(self, ea):
        for block in self.blocks:
            start_ea = ida_shims.start_ea(block)
            end_ea = ida_shims.end_ea(block)
            if start_ea <= ea and end_ea > ea:
                return block
        return None
    

class AlleyCatXR(AlleyCatBase):
    '''
    Class which computes path from and to of a graph, with a choice :)
    Mostly copied from AlleyCat :'3
    '''

    def __init__(self, start, xref_to_depth, xref_from_depth, quiet=False):
        '''
        Class constructor.

        @start              - The start address.
        @xref_to_depth      - Maximum depth to search backward.
        @xref_from_depth    - Maximum depth to search forward.

        Returns None.
        '''
        global ALLEYCAT_MEMLIMIT
        self.memlimit = ALLEYCAT_MEMLIMIT
        self.root = None
        self.quiet = quiet
        self.nodes = {}
        self.start = start
        self.xref_to_depth   = (xref_to_depth   if xref_to_depth != None else 0)
        self.xref_from_depth = (xref_from_depth if xref_from_depth != None else 0)

        if not self.quiet:
            print("Generating call paths from %s with "     \
                  "xref_to_depth=%d, xref_from_depth=%d..." \
                                      % (self._name(start),
                                         self.xref_to_depth,
                                         self.xref_from_depth))
        self._build_paths()

    def _set_root(self, node):
        self.root = node

    def _build_paths(self):
        start_node = AlleyCatPathNode(ea=self.start, is_target=True)
        self.nodes[self.start] = start_node
        self._set_root(start_node) 
        self._build_directional_path(fwd=False)
        self._build_directional_path(fwd=True)

    def _build_directional_path(self, fwd):
        if not self.root:
            return
        
        bfs_queue = deque()
        bfs_queue.append((self.root, 0))
        bfs_visited_nodes = set()

        while bfs_queue and len(bfs_queue) < self.memlimit: 
            node, depth = bfs_queue.popleft()
            
            if fwd and depth >= self.xref_from_depth:
                break
            elif not fwd and depth >= self.xref_to_depth:
                break   

            if node.ea in bfs_visited_nodes:
                continue
            bfs_visited_nodes.add(node.ea)

            # if fwd, search forward nodes,
            # if bck, search backward nodes,
            if fwd:
                xrefs = AlleyCatUtils.xrefs_from(node.ea)
            else:
                xrefs = idautils.XrefsTo(node.ea)

            for xref in xrefs:
                if fwd:
                    child = self._get_code_block(xref.to)
                else:
                    child = self._get_code_block(xref.frm)
                if not child:
                    continue
                
                child_ea = ida_shims.start_ea(child)
                
                if child_ea in self.nodes:
                    child_node = self.nodes[child_ea]
                else:
                    self.nodes[child_ea] = child_node = AlleyCatPathNode(ea=child_ea)
                
                if fwd:
                    node.add_xref_from(child_node)
                else:
                    node.add_xref_to(child_node)

                if child_ea not in bfs_visited_nodes:
                    bfs_queue.append((child_node, depth+1))

class AlleyCatFunctionXrefs(AlleyCatXR):
    def __init__(self, start_ea, xref_to_depth, xref_from_depth, quiet=False):
        try:
            start = ida_shims.start_ea(idaapi.get_func(start_ea))
            super(AlleyCatFunctionXrefs, self).__init__(start, xref_to_depth, xref_from_depth, quiet)
        except Exception as e:
            raise AlleyCatException("Address 0x%X is not part of a function!" 
                                    % start_ea)

# ---------------------------------------------------------------------
#
# Everything below here is just IDA UI/Plugin stuff
# 
# ---------------------------------------------------------------------
class AlleyCatColor:
    # Internal mapping of IDA colors.
    # Don't know why it's like this :'3
    BIN_ASM_GRAPH_COLOR_MAP = {
        0x8113e243: 0x00cb4300,
        0x8113e244: 0x00009100,
        0x8113e245: 0x000000bc,
    }
    
    GRAPH_EDGE_NODE = 0xff007b
    GRAPH_START_NODE = 0x483882
    GRAPH_END_NODE = 0x483882
    GRAPH_OUTER_NODE = 0x191919
    HIGHLIGHT_MAIN_GRAPH = 0x41076d
    

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
        if not self.history:
            return
        
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
        if not self.history:
            return
        
        self.history_index += 1
        if self.history_index >= len(self.history):
            self.history_index = len(self.history)-1

        if self.history[self.history_index] == self.INCLUDE_ACTION:
            if self.include_index < len(self.includes)-1:
                self.include_index += 1
        elif self.history[self.history_index] == self.EXCLUDE_ACTION:
            if self.exclude_index < len(self.excludes)-1:
                self.exclude_index += 1

class AlleyCatGraphicNode(object):
    def __init__(self, node:'AlleyCatPathNode'):
        self.ea = node.ea
        
        self.text = AlleyCatUtils.get_name_by_ea(node.ea)
        
        self.color = idc.DEFCOLOR
        if node.is_root():
            self.color = AlleyCatColor.GRAPH_START_NODE
        elif node.is_target():
            self.color = AlleyCatColor.GRAPH_END_NODE
        elif node.is_outer():
            self.color = AlleyCatColor.GRAPH_OUTER_NODE
        elif node.is_edge():
            self.color = AlleyCatColor.GRAPH_EDGE_NODE

        self.edges = set()
        self.edges_colors = {}

    def add_connection(self, child_node_id, color=idc.DEFCOLOR):
        self.edges.add(child_node_id)
        self.edges_colors[child_node_id] = color

class AlleyCatGraph(idaapi.GraphViewer):
    '''
    Displays the graph and manages graph actions.
    '''
    def __init__(self, results, title="AlleyCat Graph V2"):
        idaapi.GraphViewer.__init__(self, title)
        
        # Get surrounding infos so we can cache data
        # about the viewer later if needed.
        self.update_associated_viewer()
        self.is_same_func = None
            
        # Important variables deciding how
        # to update graph contents smoothly.
        self.soft_refresh = False
        self.force_refresh = True
        self.results = results
        self.last_results_timestamps = [root_node.timestamp for root_node in results]
        
        # Node caches.
        self.cache_func_eas = (None, None)
        self.cache_block_eas = []
        self.cache_block_ea2viewerid = {}

        # Info caches.
        self.ea2id: dict[int,int] = {}
        self.id2gnodes: dict[int,'AlleyCatGraphicNode'] = {}

        # We can click the same node again
        # to switch to another child in the disassembly
        # graph.
        self.last_focused_node_id = None
        self.last_focused_node_xref_index = -1
        self.last_focused_node_xref_locations = []

        # Implementing node inclusion/exclusion
        # on the graph. Note: It's currently
        # useless.
        self.history = AlleyCatGraphHistory()
        self.last_history_index = self.history.history_index
        self.include_on_click = False
        self.exclude_on_click = False
        
        # If set to False, we need to double click
        # to jump into node, else we only need
        # one click
        self.focus_on_click = True

        # If set to True, all corresponding
        # disassembly lines are highlighted.
        self.is_highlighting_path = True

        # List of command id for the menu items.
        # self.cmd_undo = None
        # self.cmd_redo = None
        # self.cmd_exclude = None
        # self.cmd_include = None
        self.cmd_refresh = None
        self.cmd_toggle_highlight = None
        self.cmd_toggle_focus_on_click = None
        
        
    def add_command(self, title, shortcut):
        cmd_id = self.AddCommand(title, shortcut)
        return cmd_id

    def Show(self):
        '''
        Display the graph.

        Returns True on success, False on failure.
        '''
        if not idaapi.GraphViewer.Show(self):
            return False
        
        # self.cmd_undo = self.AddCommand("Undo", "")
        # self.cmd_redo = self.AddCommand("Redo", "")
        # self.cmd_exclude = self.AddCommand("Exclude node", "")
        # self.cmd_include = self.AddCommand("Include node", "")
        self.cmd_refresh = self.add_command("Refresh graph", "R")
        self.cmd_toggle_highlight = self.add_command(
            "Toggle highlight/un-highlight all paths", "H")
        self.cmd_toggle_focus_on_click = self.add_command(
            "Toggle focus to address on click", "")
        
        # Colorize edges is always a mind game...        
        if self.is_same_func:
            self._colorize_all_edges()

        return True
        
    def clear(self):
        self.ea2id = {}
        self.id2gnodes = {}
        
        # Clears the graph and unhighlights the disassembly
        self.Clear()
        self.toggle_highlight_all(highlight=False)
        
    def _cache_block_eas(self, func):
        if not func:
            return
        
        func_start_ea = ida_shims.start_ea(func) 
        func_end_ea = ida_shims.end_ea(func) 
        
        self.cache_block_eas = []
        self.cache_func_eas = (func_start_ea, func_end_ea)
        self.cache_block_ea2viewerid = {}
            
        for block in idaapi.FlowChart(func):
            block_start_ea = ida_shims.start_ea(block)
            block_end_ea = ida_shims.end_ea(block)
            self.cache_block_ea2viewerid[block_start_ea] = block.id 
            self.cache_block_eas.append((block_start_ea, block_end_ea))
            self.cache_block_eas.sort()
            
    def _get_block_eas(self, ea):
        func_start_ea, func_end_ea = self.cache_func_eas
        
        if func_start_ea == None or not (func_start_ea <= ea < func_end_ea):
            func = idaapi.get_func(ea)
            if not func:
                return None, None
        
            func_start_ea = ida_shims.start_ea(func)
            if func_start_ea == idc.BADADDR:
                return None, None
            
            # Don't cache on first block. This will dampen
            # the performance during computing function 
            # relationships.
            if func_start_ea == ea:
                for block in idaapi.FlowChart(func):
                    block_start_ea = ida_shims.start_ea(block)
                    block_end_ea = ida_shims.end_ea(block)
                    return block_start_ea, block_end_ea
            
            # Only start caching when we're trying to
            # look at second block. Useful as
            # we only highlight first block when
            # inspecting function relationships.
            self._cache_block_eas(func)
        
        if not self.cache_block_eas:
            return None, None
        
        # Search complexity on average: O(logN)
        pi = bisect.bisect_left(self.cache_block_eas, ea, 
                                key=lambda block_eas:block_eas[0])
        
        block_start_ea, block_end_ea = self.cache_block_eas[pi]
        if not block_start_ea <= ea < block_end_ea:
            return None, None
        
        return block_start_ea, block_end_ea
        
    def add_node(self, node:'AlleyCatPathNode') -> int:
        gnode = AlleyCatGraphicNode(node)
        
        node_id = super().AddNode(gnode.text)
        self.ea2id[node.ea] = node_id
        self.id2gnodes[node_id] = gnode
        
        return node_id
    
    def add_edge(self, src_node_id, dest_node_id):
        super().AddEdge(src_node_id, dest_node_id)
        
        if not self.is_same_func:
            self.id2gnodes[src_node_id].add_connection(dest_node_id)
            return
        
        graph_viewer = ida_graph.get_viewer_graph(self.associated_viewer)
        if not graph_viewer:
            return
        
        # Get edge color in the associated viewer.    
        src_node_ea = self.id2gnodes[src_node_id].ea
        dst_node_ea = self.id2gnodes[dest_node_id].ea
        
        src_block_ea, _ = self._get_block_eas(src_node_ea)
        dst_block_ea, _ = self._get_block_eas(dst_node_ea)
        if (src_block_ea not in self.cache_block_ea2viewerid or
            dst_block_ea not in self.cache_block_ea2viewerid):
            return                
        
        src_block_viewerid = self.cache_block_ea2viewerid[src_block_ea]
        dst_block_viewerid = self.cache_block_ea2viewerid[dst_block_ea]
        
        edge = ida_graph.edge_t(src_block_viewerid, dst_block_viewerid)
        edge_info = graph_viewer.get_edge(edge)
        if not edge_info:
            self.id2gnodes[src_node_id].add_connection(dest_node_id)
            return
        
        color = AlleyCatColor.BIN_ASM_GRAPH_COLOR_MAP.get(edge_info.color, idc.DEFCOLOR)
        self.id2gnodes[src_node_id].add_connection(dest_node_id, color)
        
    def update_results(self, results):
        self.results = results
        self.force_refresh = True
        
    def update_associated_viewer(self):
        self.associated_viewer = idaapi.get_current_viewer()

    def _do_directional_refresh(self, root_node, fwd=True):
        bfs_queue = deque()
        bfs_queue.append(root_node)
        bfs_visited = set()

        while bfs_queue:
            curr_node = bfs_queue.popleft()
            if curr_node.ea in bfs_visited:
                continue

            bfs_visited.add(curr_node.ea)

            # Highlight this node in the disassembly window
            self.highlight(curr_node.ea)

            curr_gnode_id = self.ea2id[curr_node.ea]

            if fwd:
                child_nodes = curr_node.xrefs_from
            else:
                child_nodes = curr_node.xrefs_to

            for child_node in child_nodes:
                if child_node.ea not in self.ea2id:
                    child_gnode_id = self.add_node(child_node)
                else:
                    child_gnode_id = self.ea2id[child_node.ea]

                if fwd:
                    self.add_edge(curr_gnode_id, child_gnode_id)
                else:
                    self.add_edge(child_gnode_id, curr_gnode_id)

                if child_node.ea not in bfs_visited:
                    bfs_queue.append(child_node)
                    
    def _setup_if_same_func(self):
        # NOTE: What the hell, too lazy...
        if len(self.results) != 1:
            return False
        
        # NOTE: Lazy part 2...
        root_node = self.results[0]
        if root_node.xrefs_to:
            return False
        
        func = idaapi.get_func(root_node.ea)
        if not func: 
            return False
        
        func_start_ea = ida_shims.start_ea(func)
        func_end_ea = ida_shims.end_ea(func)
        if func_start_ea == idc.BADADDR or func_end_ea == idc.BADADDR:
            return False
                        
        bfs_queue = deque()
        bfs_queue.append(root_node)
        bfs_visited = set()
        
        while bfs_queue:
            curr_node = bfs_queue.popleft()
            if curr_node.ea in bfs_visited:
                continue
            if not func_start_ea <= curr_node.ea < func_end_ea:
                return False
            
            bfs_visited.add(curr_node.ea)

            for child_node in curr_node.xrefs_from:
                if child_node.ea not in bfs_visited:
                    bfs_queue.append(child_node)
        
        self._cache_block_eas(func)
        return True
                    
    def _do_hard_refresh(self):
        # Clear the graph before refreshing
        self.clear()
        
        # Setting this only is already enough
        # to trigger clear focus :)
        self.last_focused_node_id = None
        
        # You always need to highlight first
        self.is_highlighting_path = True
        
        # TODO: implement excludes & includes
        # includes = self.history.get_includes()
        # excludes = self.history.get_excludes()
        
        self.is_same_func = self._setup_if_same_func()

        for root_node in self.results:
            if root_node.ea not in self.ea2id:
                self.add_node(root_node)
            if root_node.xrefs_to:
                self._do_directional_refresh(root_node, fwd=False)
            if root_node.xrefs_from:
                self._do_directional_refresh(root_node, fwd=True)
                
        return True
    
    def _do_soft_refresh(self):
        '''
        This function only track changes
        in function label. 
        
        Useful when a small rename doesn't
        trigger the whole graph to be redrawn.
        '''
        
        for node_id in self.id2gnodes:
            node_ea = self.id2gnodes[node_id].ea
            
            updated_node_label = AlleyCatUtils.get_name_by_ea(node_ea) 
            if updated_node_label != self.id2gnodes[node_id].text:
                self.id2gnodes[node_id].text = updated_node_label
        
        return True
    
    def Refresh(self):
        result = super().Refresh()
        
        # Always need to recolor the edges :(
        # The edge color goes away after EVERY
        # Refresh()es...
        if self.is_same_func:
            self._colorize_all_edges()
            
        return result

    def OnRefresh(self):
        curr_results_timestamps = list(root_node.timestamp for root_node in self.results)
                
        if (
            self.force_refresh or
            self.last_results_timestamps != curr_results_timestamps or
            self.last_history_index != self.history.history_index
        ):
            self.force_refresh = False
            self.last_results_timestamps = curr_results_timestamps
            self.last_history_index = self.history.history_index
            return self._do_hard_refresh()

        if self.soft_refresh:
            self.soft_refresh = False
            return self._do_soft_refresh()
            
        return True
    
    def OnGetText(self, node_id):
        if node_id not in self.id2gnodes:
            return "(corrupted)", idc.DEFCOLOR

        gnode = self.id2gnodes[node_id]
        return gnode.text, gnode.color

    def OnHint(self, node_id):
        if node_id not in self.id2gnodes:
            return ""

        hint = ""
        for edge_node_id in self.id2gnodes[node_id].edges:
            hint += "%s\n" % self[edge_node_id]
        return hint
    
    def OnEdgeHint(self, src, dst):
        # Display bug: Sometimes on idle, OnEdgeHint is
        # triggered with (src == 0, dst == 0). To counter
        # this, I added a check to see if dst is a child
        # of src.
        if (dst not in self.id2gnodes or
            src not in self.id2gnodes or 
            dst not in self.id2gnodes[src].edges):
            return ""

        displen = max(len(self[src]), len(self[dst]))
        return "%s\n%s\n%s" % (self[src].center(displen), 
                               '↓'.center(displen), 
                               self[dst].center(displen))
        
    def OnCommand(self, cmd_id):        
        # if self.cmd_undo == cmd_id:
        #     if self.include_on_click or self.exclude_on_click:
        #         self.include_on_click = False
        #         self.exclude_on_click = False
        #     else:
        #         self.history.undo()
        #     self.Refresh()

        # elif self.cmd_redo == cmd_id:
        #     self.history.redo()
        #     self.Refresh()

        # elif self.cmd_include == cmd_id:
        #     self.include_on_click = True

        # elif self.cmd_exclude == cmd_id:
        #     self.exclude_on_click = True

        if self.cmd_toggle_focus_on_click == cmd_id:
            self.focus_on_click = not self.focus_on_click

        elif self.cmd_refresh == cmd_id:
            self.include_on_click = False
            self.exclude_on_click = False
            self.history.reset()
            self.soft_refresh = True
            self.Refresh()

        elif self.cmd_toggle_highlight == cmd_id:
            self.is_highlighting_path = not self.is_highlighting_path
            self.toggle_highlight_all(highlight=self.is_highlighting_path)
            
        return 0
    
    def _focus_on_node(self, node_id):
        if node_id in self.id2gnodes:
            node_ea = self.id2gnodes[node_id].ea
        else:
            node_ea = AlleyCatUtils.get_ea_by_name(self[node_id])

        if self.last_focused_node_id != node_id:
            self.last_focused_node_id = node_id
            self.last_focused_node_xref_index = 0
            self.last_focused_node_xref_locations = []

            if node_id in self.id2gnodes:
                for edge_node_id in self.id2gnodes[node_id].edges:
                    if edge_node_id in self.id2gnodes:
                        edge_node_ea = self.id2gnodes[edge_node_id].ea
                    else:
                        edge_node_ea = AlleyCatUtils.get_ea_by_name(self[edge_node_id])

                    if edge_node_ea == idc.BADADDR:
                        continue

                    for xref in idautils.XrefsTo(edge_node_ea):
                        if self._match_xref_source(xref, node_ea):
                            self.last_focused_node_xref_locations.append((xref.frm, edge_node_ea))

            if self.last_focused_node_xref_locations:
                self.last_focused_node_xref_locations.sort()

                print("")
                print("Path Xrefs from %s:" % self[node_id])
                print("-" * 100)
                for (xref_ea, dst_ea) in self.last_focused_node_xref_locations:
                    print("%-50s  =>  %s" % (AlleyCatUtils.get_name_by_ea(xref_ea),
                                             AlleyCatUtils.get_name_by_ea(dst_ea)))
                print("-" * 100)
                print("")

                self.last_focused_node_xref_locations.append((node_ea, node_ea))

        if self.last_focused_node_xref_locations:
            ida_shims.jumpto(self.last_focused_node_xref_locations[self.last_focused_node_xref_index][0])
            self.last_focused_node_xref_index += 1
            self.last_focused_node_xref_index %= len(self.last_focused_node_xref_locations)
        else:
            ida_shims.jumpto(node_ea)


    def OnClick(self, node_id):
        if self.include_on_click:
            self.history.add_include(self.id2gnodes[node_id].ea)
            self.include_on_click = False
            self.Refresh()
        elif self.exclude_on_click:
            self.history.add_exclude(self.id2gnodes[node_id].ea)
            self.exclude_on_click = False
            self.Refresh()
        elif self.focus_on_click:
            self._focus_on_node(node_id)

    def OnDblClick(self, node_id):
        self._focus_on_node(node_id)

    def OnClose(self):
        self.toggle_highlight_all(highlight=False)

    def _match_xref_source(self, xref, source):
        return ((xref.type != idc.fl_F) and
                (ida_shims.get_func_attr(xref.frm, idc.FUNCATTR_START) == source))
        
    def _colorize_edge(self, src_node_id, dst_node_id, color):
        widget = self.GetWidget()
        viewer = None
        if widget:
            viewer = ida_graph.get_viewer_graph(widget)
        if not viewer:
            return
        
        edge = ida_graph.edge_t()
        edge.src = src_node_id
        edge.dst = dst_node_id
        
        edge_info = viewer.get_edge(edge)
        if not edge_info:
            return
        edge_info.color = color
        
    def _colorize_all_edges(self):
        for node_id in self.id2gnodes:
            edges_colors = self.id2gnodes[node_id].edges_colors
            for child_node_id in edges_colors:
                color = edges_colors[child_node_id] 
                self._colorize_edge(node_id, child_node_id, color)
        
    def _colorize_ea_range(self, start_ea, end_ea, color):
        if not start_ea or start_ea >= end_ea:
            ida_kernwin.warning(0, "Colorize ea range failure!\n"
                                "   - start_ea = 0x%x\n"
                                "   - end_ea = 0x%x\n" % (start_ea, end_ea))
            return 
        
        ea = start_ea
        while ea < end_ea:
            idaapi.set_item_color(ea, color)
            ea = ida_shims.next_head(ea)

    def colorize_node(self, ea, color):
        block_start_ea, block_end_ea = self._get_block_eas(ea)
        self._colorize_ea_range(block_start_ea, block_end_ea, color)

    def highlight(self, ea):
        # Highlights an entire code block
        self.colorize_node(ea, AlleyCatColor.HIGHLIGHT_MAIN_GRAPH)

    def unhighlight(self, ea):
        # Unhighlights an entire code block
        self.colorize_node(ea, idc.DEFCOLOR)

    def toggle_highlight_all(self, highlight=True):
        # Unhighlights all code blocks
        for root_node in self.results:
            bfs_queue = deque()
            bfs_queue.append(root_node)
            bfs_visited = set()

            while bfs_queue:
                curr_node = bfs_queue.popleft()
                if curr_node.ea in bfs_visited:
                    continue

                bfs_visited.add(curr_node.ea)

                # Unhighlight/highlight this node in 
                # the disassembly window
                if highlight:
                    self.highlight(curr_node.ea)
                else:
                    self.unhighlight(curr_node.ea)

                for child_node in curr_node.xrefs_to:
                    if child_node.ea not in bfs_visited:
                        bfs_queue.append(child_node)

            # Clears forward. Some nodes are cleared
            # twice, but that's alright :-)
            bfs_queue = deque()
            bfs_queue.append(root_node)
            bfs_visited = set()

            while bfs_queue:
                curr_node = bfs_queue.popleft()
                if curr_node.ea in bfs_visited:
                    continue

                bfs_visited.add(curr_node.ea)

                if highlight:
                    self.highlight(curr_node.ea)
                else:
                    self.unhighlight(curr_node.ea)

                for child_node in curr_node.xrefs_from:
                    if child_node.ea not in bfs_visited:
                        bfs_queue.append(child_node)


class AlleyCatPaths(object):
    # Graph object is shared between
    # many instances. I don't know if
    # in the future, this object is called
    # asyncronously, but let's hope not :-)
    graph = None

    def _current_function(self):
        function = idaapi.get_func(ida_shims.get_screen_ea())
        return ida_shims.start_ea(function)
    
    def _get_xref_results(self, sources, xref_to_depth, xref_from_depth, klass):
        results = []
        
        for source in sources:
            s = time.time()
            r = klass(source, xref_to_depth, xref_from_depth)
            e = time.time()
            print("Found %d paths in %f seconds." % (r.get_npaths(), (e-s)))
            results.append(r.root)

        return results
    
    def _get_startend_results(self, sources, targets, klass):
        assert targets != None, \
            ValueError("AlleyCat: STARTEND: targets is empty")
        
        results = []
        for target in targets:
            for source in sources:
                s = time.time()
                r = klass(source, target)
                e = time.time()
                print("Found %d paths in %f seconds." % (r.get_npaths(), (e-s)))

                if r.root == None:
                    name = ida_shims.get_name(target)
                    if not name:
                        name = "0x%X" % target
                    print("No paths found to", name)
                    continue
            
                results.append(r.root)

        return results

    def _find_and_plot_paths(self, sources, targets=None, 
                             xref_to_depth=None, 
                             xref_from_depth=None, 
                             klass=AlleyCatFunctionPaths,
                             cmd_id=None):
        
        results = []
        if AlleyCatCommands.is_xref_mode(cmd_id):
            results = self._get_xref_results(
                                sources, xref_to_depth, xref_from_depth, klass
                            )
        if AlleyCatCommands.is_startend_mode(cmd_id):
            results = self._get_startend_results(
                                sources, targets, klass
                            )
        if not results:
            return
        
        # Close any previous graph so that it unhighlights
        # previous paths :)
        graph = self.__class__.graph
        if graph != None:
            s = time.time()
            graph.clear()
            graph.update_results(results)
            graph.update_associated_viewer()
            graph.Refresh()
            graph.Show()
            e = time.time()
            print("Graph refresh took %f seconds." % (e-s))
        else:
            s = time.time()
            self.__class__.graph = AlleyCatGraph(results, 'Path Graph')
            self.__class__.graph.Show()
            e = time.time()
            print("Graph initation took %f seconds." % (e-s))
        
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
    
    def _get_config_xref_depths(self):
        xref_to_depth = None
        xref_from_depth = None

        class XREFSelectForm(ida_kernwin.Form):
            def __init__(self):
                self.invert = False
                F = ida_kernwin.Form
                F.__init__(
                    self,
                    r"""XREF to/from depth
<##XREF to depth       :{xref_to_depth}>
<##XREF from depth     :{xref_from_depth}>""", 
                    {
                        'xref_to_depth':   F.NumericInput(tp=F.FT_INT64),
                        'xref_from_depth': F.NumericInput(tp=F.FT_INT64),
                    }
                )

        f = XREFSelectForm()

        # Compile (in order to populate the controls)
        f.Compile()

        f.xref_to_depth.value = -1
        f.xref_from_depth.value = -1

        # Execute the form
        ok = f.Execute()
        if ok == 1:
            if f.xref_to_depth.value >= 0:
                xref_to_depth = f.xref_to_depth.value 
            if f.xref_from_depth.value >= 0:
                xref_from_depth = f.xref_from_depth.value

        # Dispose the form
        f.Free()

        return ok, xref_to_depth, xref_from_depth

    def FindPathsToCodeBlock(self):
        target = ida_shims.get_screen_ea()
        source = self._current_function()
        if source:
            self._find_and_plot_paths([source], 
                                      targets=[target], 
                                      klass=AlleyCatCodePaths, 
                                      cmd_id=AlleyCatCommands.FIND_PATH_TO_CODE_BLOCK)

    def FindPathsToMany(self):
        source = self._current_function()
        if source:
            targets = self._get_user_selected_functions(many=True)
            if targets:
                self._find_and_plot_paths([source], 
                                          targets=targets, 
                                          cmd_id=AlleyCatCommands.FIND_PATH_TO_MANY)

    def FindPathsFromMany(self):
        target = self._current_function()
        if target:
            sources = self._get_user_selected_functions(many=True)
            if sources:
                self._find_and_plot_paths(sources, 
                                          targets=[target],
                                          cmd_id=AlleyCatCommands.FIND_PATH_FROM_MANY)

    def FindFunctionXrefs(self):
        source = self._current_function()
        
        ok, xref_to_depth, xref_from_depth = self._get_config_xref_depths()
        if not ok:
            return
        
        if source:
            self._find_and_plot_paths([source], 
                                      xref_to_depth=xref_to_depth,
                                      xref_from_depth=xref_from_depth,
                                      klass=AlleyCatFunctionXrefs,
                                      cmd_id=AlleyCatCommands.FIND_FUNCTION_XREFS)

# --------------------------------------------------------------------
#
# Helper functions to execute commands selected from dropdown menus.
#
# --------------------------------------------------------------------

class ActionRegisterer():
    class DynamicAction(idaapi.action_handler_t):
        def __init__(self, handler):
            idaapi.action_handler_t.__init__(self)
            self.handler = handler

        def activate(self, ctx):
            self.handler()
            return 1

        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS

    class ActionConfig:
        pngbytes2id = {}
        
        def __init__(self, name, menu_name, handler,           \
                           icon:int|bytes,                     \
                           path_to_in_menu:str|None=None,      \
                           in_popup_widget_type:int|None=None, \
                           hotkey="", help=""):
            
            self.name = name
            self.menu_name = menu_name
            self.handler = handler
            self.hotkey = hotkey
            self.help = help
            self.path_to_in_menu = path_to_in_menu
            self.in_popup_widget_type = in_popup_widget_type
            
            # Either we've got icon ID or
            # raw PNG bytes :)
            if isinstance(icon, int):
                self.icon_id = icon
            elif not isinstance(icon, bytes):
                raise ValueError("icon is neither int or PNG bytes :(")
            elif icon in self.pngbytes2id:
                self.icon_id = self.pngbytes2id[icon]
            else:
                icon_id = ida_kernwin.load_custom_icon(data=icon, format="png")
                self.pngbytes2id[icon] = self.icon_id = icon_id
            
        def register(self) -> bool:
            ok = idaapi.register_action(idaapi.action_desc_t(
                self.name,
                self.menu_name,
                self.handler,
                self.hotkey,
                self.help,
                self.icon_id,
            ))
            
            if not ok:
                return False
            
            if self.path_to_in_menu != None:
                idaapi.attach_action_to_menu(
                    self.path_to_in_menu, self.name, idaapi.SETMENU_APP)
                
            return True
        
        def detach(self):
            if self.path_to_in_menu == None:
                return
            
            idaapi.detach_action_from_menu(
                self.path_to_in_menu, self.name)
        
    class RegisterPopupMenuHooks(idaapi.UI_Hooks):
        def __init__(self, actions:list['ActionRegisterer.ActionConfig'], *args, **kwargs):
            self.actions = actions
            super().__init__(*args, **kwargs)
        
        def finish_populating_widget_popup(self, widget, popup_handle, ctx=None):
            widget_type = ida_kernwin.get_widget_type(widget)
            for action in self.actions:
                if widget_type == action.in_popup_widget_type:
                    idaapi.attach_action_to_popup(widget, popup_handle, action.name, "")
    
    # Defines actions to be registered :)
    actions = [
        ActionConfig(
            name='funcxref_v2:action',
            menu_name='XREF to/from (interactive)',
            handler=DynamicAction(lambda: AlleyCatPaths().FindFunctionXrefs()),
            icon=199,
            path_to_in_menu="View/Graphs/",
            in_popup_widget_type=ida_kernwin.BWN_DISASM,
        ),
        ActionConfig(
            name="tocurrfrom:action",
            menu_name='Find paths to the current function from...',
            handler=DynamicAction(lambda: AlleyCatPaths().FindPathsFromMany()),
            icon=199,
            path_to_in_menu="View/Graphs/",
            in_popup_widget_type=ida_kernwin.BWN_DISASM,
        ),
        ActionConfig(
            name='fromcurrto:action',
            menu_name='Find paths from the current function to...',
            handler=DynamicAction(lambda: AlleyCatPaths().FindPathsToMany()),
            icon=199,
            path_to_in_menu="View/Graphs/",
            in_popup_widget_type=ida_kernwin.BWN_DISASM,
        ),
        ActionConfig(
            name='currfunccurrblock:action',
            menu_name='Find paths in the current function to ' \
                                     'the current code block',
            handler=DynamicAction(lambda: AlleyCatPaths().FindPathsToCodeBlock()),
            icon=199,
            in_popup_widget_type=ida_kernwin.BWN_DISASM,
        ),
    ]

    hooks = None
    
    @classmethod
    def init(cls):
        for action in cls.actions:
            action.register()
        cls.hooks = ActionRegisterer.RegisterPopupMenuHooks(ActionRegisterer.actions)
        cls.hooks.hook()
            
    @classmethod
    def detach(cls):
        for action in cls.actions:
            action.detach()


class idapathfinder_t(idaapi.plugin_t):
    flags = 0
    comment = ''
    help = ''
    wanted_name = 'AlleyCat'

    def init(self):
        # Add ALLEYCAT_MEMLIMIT variable to the global namespace so it can be
        # accessed from the IDA python terminal.
        global ALLEYCAT_MEMLIMIT
        add_to_namespace(
            '__main__', 'alleycat', 'ALLEYCAT_MEMLIMIT', 
            ALLEYCAT_MEMLIMIT)

        # Add functions to global namespace.
        add_to_namespace(
            '__main__', 'alleycat', 'AlleyCatUtils',
            AlleyCatUtils)
        add_to_namespace(
            '__main__', 'alleycat', 'AlleyCatFunctionXrefs',
            AlleyCatFunctionXrefs)
        add_to_namespace(
            '__main__', 'alleycat', 'AlleyCatFunctionPaths',
            AlleyCatFunctionPaths)
        add_to_namespace(
            '__main__', 'alleycat', 'AlleyCatCodePaths', 
            AlleyCatCodePaths)
        add_to_namespace(
            '__main__', 'alleycat', 'AlleyCatGraph', 
            AlleyCatGraph)
        add_to_namespace(
            '__main__', 'alleycat', 'AlleyCatPaths', 
            AlleyCatPaths)
                
        return idaapi.PLUGIN_KEEP

    def term(self):
        ActionRegisterer.detach()
        return None

    def run(self, arg):
        pass

def PLUGIN_ENTRY():
    return idapathfinder_t()

ActionRegisterer.init()
