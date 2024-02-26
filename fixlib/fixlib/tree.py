from __future__ import annotations
import json
import uuid
from collections import defaultdict
from copy import deepcopy
from typing import Iterable, Optional, List

from fixlib.logger import log

"""
NOTE:
This module is copied and ported to proper Python 3.0 from https://github.com/caesar0301/treelib
Since this library has outdated vulnerable dependencies, we decided to copy it here directly.
"""


class NodeError(Exception):
    pass


class NodeIDAbsentError(NodeError):
    pass


class Node:
    """
    Nodes are elementary objects that are stored in the `_nodes` dictionary of a Tree.
    Use `data` attribute to store node-specific data.
    """

    #: Mode constants for routine `update_fpointer()`.
    ADD, DELETE, INSERT, REPLACE = range(4)

    def __init__(self, tag=None, identifier=None, expanded=True, data=None):
        #: if given as a parameter, must be unique
        self.identifier = identifier or str(uuid.uuid1())
        #: None or something else
        #: if None, self._identifier will be set to the identifier's value.
        self._tag = tag or self.identifier
        #: boolean
        self.expanded = expanded
        #: identifier of the parent's node :
        self._predecessor = {}
        #: identifier(s) of the soons' node(s) :
        self._successors = defaultdict(list)
        #: User payload associated with this node.
        self.data = data
        # for retro-compatibility on bpointer/fpointer
        self._initial_tree_id = None

    def __lt__(self, other):
        return self.tag < other.tag

    def set_initial_tree_id(self, tree_id):
        if self._initial_tree_id is None:
            self._initial_tree_id = tree_id

    @property
    def bpointer(self):
        """Use predecessor method, this property is deprecated and only kept for retro-compatilibity. Parents of
        a node are dependant on a given tree. This implementation keeps the previous behavior by keeping returning
        bpointer of first declared tree.
        """
        if self._initial_tree_id not in self._predecessor.keys():
            return None
        return self._predecessor[self._initial_tree_id]

    def predecessor(self, tree_id):
        return self._predecessor[tree_id]

    def set_predecessor(self, nid, tree_id):
        """Set the value of `_predecessor`."""
        self._predecessor[tree_id] = nid

    def successors(self, tree_id):
        return self._successors[tree_id]

    def set_successors(self, value, tree_id=None):
        setter_lookup = {
            "NoneType": lambda x: list(),
            "list": lambda x: x,
            "dict": lambda x: list(x.keys()),
            "set": lambda x: list(x),
        }

        t = value.__class__.__name__
        if t in setter_lookup:
            f_setter = setter_lookup[t]
            self._successors[tree_id] = f_setter(value)
        else:
            raise NotImplementedError("Unsupported value type %s" % t)

    def update_successors(self, nid, mode=ADD, replace=None, tree_id=None):
        """
        Update the children list with different modes: addition (Node.ADD or
        Node.INSERT) and deletion (Node.DELETE).
        """
        if nid is None:
            return

        def _manipulator_append():
            self.successors(tree_id).append(nid)

        def _manipulator_delete():
            if nid in self.successors(tree_id):
                self.successors(tree_id).remove(nid)
            else:
                log.warn("Nid %s wasn't present in fpointer" % nid)

        def _manipulator_insert():
            log.warn("WARNING: INSERT is deprecated to ADD mode")
            self.update_successors(nid, tree_id=tree_id)

        def _manipulator_replace():
            if replace is None:
                raise NodeError('Argument "replace" should be provided when mode is {}'.format(mode))
            ind = self.successors(tree_id).index(nid)
            self.successors(tree_id)[ind] = replace

        manipulator_lookup = {
            self.ADD: "_manipulator_append",
            self.DELETE: "_manipulator_delete",
            self.INSERT: "_manipulator_insert",
            self.REPLACE: "_manipulator_replace",
        }

        if mode not in manipulator_lookup:
            raise NotImplementedError("Unsupported node updating mode %s" % str(mode))

        f_name = manipulator_lookup.get(mode)
        f = locals()[f_name]
        return f()

    def clone_pointers(self, former_tree_id, new_tree_id):
        former_bpointer = self.predecessor(former_tree_id)
        self.set_predecessor(former_bpointer, new_tree_id)
        former_fpointer = self.successors(former_tree_id)
        # fpointer is a list and would be copied by reference without deepcopy
        self.set_successors(deepcopy(former_fpointer), tree_id=new_tree_id)

    def reset_pointers(self, tree_id):
        self.set_predecessor(None, tree_id)
        self.set_successors([], tree_id=tree_id)

    def is_leaf(self, tree_id=None):
        """Return true if current node has no children."""
        if tree_id is None:
            # for retro-compatilibity
            if self._initial_tree_id not in self._successors.keys():
                return True
            else:
                tree_id = self._initial_tree_id

        if len(self.successors(tree_id)) == 0:
            return True
        else:
            return False

    def is_root(self, tree_id=None):
        """Return true if self has no parent, i.e. as root."""
        if tree_id is None:
            # for retro-compatilibity
            if self._initial_tree_id not in self._predecessor.keys():
                return True
            else:
                tree_id = self._initial_tree_id

        return self.predecessor(tree_id) is None

    @property
    def tag(self):
        """
        The readable node name for human. This attribute can be accessed and
        modified with ``.`` and ``=`` operator respectively.
        """
        return self._tag

    @tag.setter
    def tag(self, value):
        """Set the value of `_tag`."""
        self._tag = value if value is not None else None

    def __repr__(self):
        name = self.__class__.__name__
        kwargs = [
            "tag={0}".format(self.tag),
            "identifier={0}".format(self.identifier),
            "data={0}".format(self.data),
        ]
        return "%s(%s)" % (name, ", ".join(kwargs))


class Tree(object):
    """Tree objects are made of Node(s) stored in _nodes dictionary."""

    #: ROOT, DEPTH, WIDTH, ZIGZAG constants :
    (ROOT, DEPTH, WIDTH, ZIGZAG) = list(range(4))
    node_class = Node

    def __contains__(self, identifier):
        return identifier in self.nodes.keys()

    def __init__(self, tree=None, deep=False, node_class=None, identifier=None) -> None:
        """Initiate a new tree or copy another tree with a shallow or
        deep copy.
        """
        self._identifier = None
        self._set_identifier(identifier)

        if node_class:
            assert issubclass(node_class, Node)
            self.node_class = node_class

        #: dictionary, identifier: Node object
        self._nodes = {}

        #: Get or set the identifier of the root. This attribute can be accessed and modified
        #: with ``.`` and ``=`` operator respectively.
        self.root: Optional[str] = None

        if tree is not None:
            self.root = tree.root
            for nid, node in tree.nodes.items():
                new_node = deepcopy(node) if deep else node
                self._nodes[nid] = new_node
                if tree.identifier != self._identifier:
                    new_node.clone_pointers(tree.identifier, self._identifier)

    def _clone(self, identifier=None, with_tree=False, deep=False):
        return self.__class__(identifier=identifier, tree=self if with_tree else None, deep=deep)

    @property
    def identifier(self):
        return self._identifier

    def _set_identifier(self, nid):
        """Initialize self._set_identifier"""
        if nid is None:
            self._identifier = str(uuid.uuid1())
        else:
            self._identifier = nid

    def __getitem__(self, key):
        """Return _nodes[key]"""
        try:
            return self._nodes[key]
        except KeyError:
            raise NodeIDAbsentError("Node '%s' is not in the tree" % key)

    def __len__(self):
        """Return len(_nodes)"""
        return len(self._nodes)

    def __str__(self) -> str:
        return f"Tree(root={self.root}, nodes={len(self._nodes)})"

    def __get_iter(self, nid, level, filter_, key, reverse, dt, is_last):
        dt_vertical_line, dt_line_box, dt_line_corner = dt

        nid = self.root if nid is None else nid
        node = self[nid]

        if level == self.ROOT:
            yield "", node
        else:
            leading = "".join(map(lambda x: dt_vertical_line + " " * 3 if not x else " " * 4, is_last[0:-1]))
            lasting = dt_line_corner if is_last[-1] else dt_line_box
            yield leading + lasting, node

        if filter_(node) and node.expanded:
            children = [self[i] for i in node.successors(self._identifier) if filter_(self[i])]
            idxlast = len(children) - 1
            if key:
                children.sort(key=key, reverse=reverse)
            elif reverse:
                children = reversed(children)
            level += 1
            for idx, child in enumerate(children):
                is_last.append(idx == idxlast)
                for item in self.__get_iter(child.identifier, level, filter_, key, reverse, dt, is_last):
                    yield item
                is_last.pop()

    def __update_pred_pointer(self, nid, parent_id):
        """set self[nid].bpointer"""
        self[nid].set_predecessor(parent_id, self._identifier)

    def __update_succ_pointer(self, nid, child_id, mode):
        if nid is None:
            return
        else:
            self[nid].update_successors(child_id, mode, tree_id=self._identifier)

    def add_node(self, node, parent=None):
        """
        Add a new node object to the tree and make the parent as the root by default.

        The 'node' parameter refers to an instance of Class::Node.
        """
        if not isinstance(node, self.node_class):
            raise OSError("First parameter must be object of {}".format(self.node_class))

        if node.identifier in self._nodes:
            raise NodeError("Can't create node " "with ID '%s'" % node.identifier)

        pid = parent.identifier if isinstance(parent, self.node_class) else parent

        if pid is None:
            if self.root is not None:
                raise NodeError("A tree takes one root merely.")
            else:
                self.root = node.identifier
        elif not self.contains(pid):
            raise NodeIDAbsentError("Parent node '%s' " "is not in the tree" % pid)

        self._nodes.update({node.identifier: node})
        self.__update_succ_pointer(pid, node.identifier, self.node_class.ADD)
        self.__update_pred_pointer(node.identifier, pid)
        node.set_initial_tree_id(self._identifier)

    def all_nodes(self) -> List[Node]:
        """Return all nodes in a list"""
        return list(self._nodes.values())

    def all_nodes_itr(self) -> Iterable[Node]:
        """
        Returns all nodes in an iterator.
        Added by William Rusnack
        """
        return self._nodes.values()

    def ancestor(self, nid, level=None):
        """
        For a given id, get ancestor node object at a given level.
        If no level is provided, the parent node is returned.
        """
        if not self.contains(nid):
            raise NodeIDAbsentError("Node '%s' is not in the tree" % nid)

        descendant = self[nid]
        ascendant = self[nid].bpointer
        ascendant_level = self.level(ascendant)

        if level is None:
            return ascendant
        elif nid == self.root:
            return self[nid]
        elif level >= self.level(descendant.identifier):
            raise AttributeError(
                "Descendant level (level %s) must be greater \
                                      than its ancestor's level (level %s)"
                % (str(self.level(descendant.identifier)), level)
            )

        while ascendant is not None:
            if ascendant_level == level:
                return self[ascendant]
            else:
                descendant = ascendant
                ascendant = self[descendant].bpointer
                ascendant_level = self.level(ascendant)
        return None

    def children(self, nid) -> List[Node]:
        """
        Return the children (Node) list of nid.
        Empty list is returned if nid does not exist
        """
        return [self[i] for i in self.is_branch(nid)]

    def contains(self, nid):
        """Check if the tree contains node of given id"""
        return True if nid in self._nodes else False

    def create_node(self, tag=None, identifier=None, parent=None, data=None) -> Node:
        """
        Create a child node for given @parent node. If ``identifier`` is absent,
        a UUID will be generated automatically.
        """
        node = self.node_class(tag=tag, identifier=identifier, data=data)
        self.add_node(node, parent)
        return node

    def depth(self, node=None):
        """
        Get the maximum level of this tree or the level of the given node.

        @param node Node instance or identifier
        @return int
        @throw NodeIDAbsentError
        """
        ret = 0
        if node is None:
            # Get maximum level of this tree
            leaves = self.leaves()
            for leave in leaves:
                level = self.level(leave.identifier)
                ret = level if level >= ret else ret
        else:
            # Get level of the given node
            if not isinstance(node, self.node_class):
                nid = node
            else:
                nid = node.identifier
            if not self.contains(nid):
                raise NodeIDAbsentError("Node '%s' is not in the tree" % nid)
            ret = self.level(nid)
        return ret

    def expand_tree(self, nid=None, mode=DEPTH, filter_fn=None, key=None, reverse=False, sorting=True):
        """
        Python generator to traverse the tree (or a subtree) with optional
        node filtering and sorting.

        Loosely based on an algorithm from 'Essential LISP' by John R. Anderson,
        Albert T. Corbett, and Brian J. Reiser, page 239-241.

        :param nid: Node identifier from which tree traversal will start.
            If None tree root will be used
        :param mode: Traversal mode, may be either DEPTH, WIDTH or ZIGZAG
        :param filter_fn: the @filter function is performed on Node object during
            traversing. In this manner, the traversing will NOT visit the node
            whose condition does not pass the filter and its children.
        :param key: the @key and @reverse are present to sort nodes at each
            level. If @key is None sorting is performed on node tag.
        :param reverse: if True reverse sorting
        :param sorting: if True perform node sorting, if False return
            nodes in original insertion order. In latter case @key and
            @reverse parameters are ignored.
        :return: Node IDs that satisfy the conditions
        :rtype: generator object
        """
        nid = self.root if nid is None else nid
        if not self.contains(nid):
            raise NodeIDAbsentError("Node '%s' is not in the tree" % nid)

        filter_fn = (lambda x: True) if (filter_fn is None) else filter_fn
        if filter_fn(self[nid]):
            yield nid
            queue = [self[i] for i in self[nid].successors(self._identifier) if filter_fn(self[i])]
            if mode in [self.DEPTH, self.WIDTH]:
                if sorting:
                    queue.sort(key=key, reverse=reverse)
                while queue:
                    yield queue[0].identifier
                    expansion = [self[i] for i in queue[0].successors(self._identifier) if filter_fn(self[i])]
                    if sorting:
                        expansion.sort(key=key, reverse=reverse)
                    if mode is self.DEPTH:
                        queue = expansion + queue[1:]  # depth-first
                    elif mode is self.WIDTH:
                        queue = queue[1:] + expansion  # width-first

            elif mode is self.ZIGZAG:
                # Suggested by Ilya Kuprik (ilya-spy@ynadex.ru).
                stack_fw = []
                queue.reverse()
                stack = stack_bw = queue
                direction = False
                while stack:
                    expansion = [self[i] for i in stack[0].successors(self._identifier) if filter_fn(self[i])]
                    yield stack.pop(0).identifier
                    if direction:
                        expansion.reverse()
                        stack_bw = expansion + stack_bw
                    else:
                        stack_fw = expansion + stack_fw
                    if not stack:
                        direction = not direction
                        stack = stack_fw if direction else stack_bw

            else:
                raise ValueError("Traversal mode '{}' is not supported".format(mode))

    def filter_nodes(self, func):
        """
        Filters all nodes by function.

        :param func: is passed one node as an argument and that node is included if function returns true,
        :return: a filter iterator of the node in python 3 or a list of the nodes in python 2.

        Added by William Rusnack.
        """
        return filter(func, self.all_nodes_itr())

    def get_node(self, nid) -> Node:
        """
        Get the object of the node with ID of ``nid``.

        An alternative way is using '[]' operation on the tree. But small difference exists between them:
        ``get_node()`` will return None if ``nid`` is absent, whereas '[]' will raise ``KeyError``.
        """
        if nid is None or not self.contains(nid):
            return None
        return self._nodes[nid]

    def is_branch(self, nid):
        """
        Return the children (ID) list of nid.
        Empty list is returned if nid does not exist
        """
        if nid is None:
            raise OSError("First parameter can't be None")
        if not self.contains(nid):
            raise NodeIDAbsentError("Node '%s' is not in the tree" % nid)

        try:
            fpointer = self[nid].successors(self._identifier)
        except KeyError:
            fpointer = []
        return fpointer

    def leaves(self, nid=None) -> List[Node]:
        """Get leaves of the whole tree or a subtree."""
        leaves = []
        if nid is None:
            for node in self._nodes.values():
                if node.is_leaf(self._identifier):
                    leaves.append(node)
        else:
            for node in self.expand_tree(nid):
                if self[node].is_leaf(self._identifier):
                    leaves.append(self[node])
        return leaves

    def level(self, nid, filter_fn=None):
        """
        Get the node level in this tree.
        The level is an integer starting with '0' at the root.
        In other words, the root lives at level '0';

        Update: @filter params is added to calculate level passing
        exclusive nodes.
        """
        return len([n for n in self.rsearch(nid, filter_fn)]) - 1

    def link_past_node(self, nid):
        """
        Delete a node by linking past it.

        For example, if we have `a -> b -> c` and delete node b, we are left
        with `a -> c`.
        """
        if not self.contains(nid):
            raise NodeIDAbsentError("Node '%s' is not in the tree" % nid)
        if self.root == nid:
            raise NodeError("Cannot link past the root node, " "delete it with remove_node()")
        # Get the parent of the node we are linking past
        parent = self[self[nid].predecessor(self._identifier)]
        # Set the children of the node to the parent
        for child in self[nid].successors(self._identifier):
            self[child].set_predecessor(parent.identifier, self._identifier)
        # Link the children to the parent
        for id_ in self[nid].successors(self._identifier) or []:
            parent.update_successors(id_, tree_id=self._identifier)
        # Delete the node
        parent.update_successors(nid, mode=parent.DELETE, tree_id=self._identifier)
        del self._nodes[nid]

    def move_node(self, source, destination):
        """
        Move node @source from its parent to another parent @destination.
        """
        if not self.contains(source) or not self.contains(destination):
            raise NodeIDAbsentError
        elif self.is_ancestor(source, destination):
            raise ValueError("Cannot move node '%s' to its descendant '%s'" % (source, destination))

        parent = self[source].predecessor(self._identifier)
        self.__update_succ_pointer(parent, source, self.node_class.DELETE)
        self.__update_succ_pointer(destination, source, self.node_class.ADD)
        self.__update_pred_pointer(source, destination)

    def is_ancestor(self, ancestor, grandchild):
        """
        Check if the @ancestor the preceding nodes of @grandchild.

        :param ancestor: the node identifier
        :param grandchild: the node identifier
        :return: True or False
        """
        parent = self[grandchild].predecessor(self._identifier)
        child = grandchild
        while parent is not None:
            if parent == ancestor:
                return True
            else:
                child = self[child].predecessor(self._identifier)
                parent = self[child].predecessor(self._identifier)
        return False

    @property
    def nodes(self):
        """Return a dict form of nodes in a tree: {id: node_instance}."""
        return self._nodes

    def parent(self, nid):
        """Get parent :class:`Node` object of given id."""
        if not self.contains(nid):
            raise NodeIDAbsentError("Node '%s' is not in the tree" % nid)

        pid = self[nid].predecessor(self._identifier)
        if pid is None or not self.contains(pid):
            return None

        return self[pid]

    def merge(self, nid, new_tree, deep=False):
        """Patch @new_tree on current tree by pasting new_tree root children on current tree @nid node.

        Consider the following tree:
        # tree.show()
        root
        ├── A
        └── B
        # new_tree.show()
        root2
        ├── C
        └── D
            └── D1
        Merging new_tree on B node:
        # tree.merge('B', new_tree)
        # tree.show()
        root
        ├── A
        └── B
            ├── C
            └── D
                └── D1

        Note: if current tree is empty and nid is None, the new_tree root will be used as root on current tree. In all
        other cases new_tree root is not pasted.
        """
        if new_tree.root is None:
            return

        if nid is None:
            if self.root is None:
                new_tree_root = new_tree[new_tree.root]
                self.add_node(new_tree_root)
                nid = new_tree.root
            else:
                raise ValueError('Must define "nid" under which new tree is merged.')
        for child in new_tree.children(new_tree.root):
            self.paste(nid=nid, new_tree=new_tree.subtree(child.identifier), deep=deep)

    def paste(self, nid, new_tree, deep=False):
        """
        Paste a @new_tree to the original one by linking the root
        of new tree to given node (nid).

        Update: add @deep copy of pasted tree.
        """
        assert isinstance(new_tree, Tree)

        if new_tree.root is None:
            return

        if nid is None:
            raise ValueError('Must define "nid" under which new tree is pasted.')

        if not self.contains(nid):
            raise NodeIDAbsentError("Node '%s' is not in the tree" % nid)

        set_joint = set(new_tree._nodes) & set(self._nodes)  # joint keys
        if set_joint:
            raise ValueError("Duplicated nodes %s exists." % list(map(str, set_joint)))

        for cid, node in new_tree.nodes.items():
            if deep:
                node = deepcopy(new_tree[node])
            self._nodes.update({cid: node})
            node.clone_pointers(new_tree.identifier, self._identifier)

        self.__update_pred_pointer(new_tree.root, nid)
        self.__update_succ_pointer(nid, new_tree.root, self.node_class.ADD)

    def paths_to_leaves(self):
        """
        Use this function to get the identifiers allowing to go from the root
        nodes to each leaf.

        :return: a list of list of identifiers, root being not omitted.

        For example:

        .. code-block:: python

            Harry
            |___ Bill
            |___ Jane
            |    |___ Diane
            |         |___ George
            |              |___ Jill
            |         |___ Mary
            |    |___ Mark

        Expected result:

        .. code-block:: python

            [['harry', 'jane', 'diane', 'mary'],
             ['harry', 'jane', 'mark'],
             ['harry', 'jane', 'diane', 'george', 'jill'],
             ['harry', 'bill']]

        """
        res = []

        for leaf in self.leaves():
            res.append([nid for nid in self.rsearch(leaf.identifier)][::-1])

        return res

    def remove_node(self, identifier) -> int:
        """Remove a node indicated by 'identifier' with all its successors.
        Return the number of removed nodes.
        """
        if not self.contains(identifier):
            raise NodeIDAbsentError("Node '%s' " "is not in the tree" % identifier)

        parent = self[identifier].predecessor(self._identifier)

        # Remove node and its children
        removed = list(self.expand_tree(identifier))

        for id_ in removed:
            if id_ == self.root:
                self.root = None
            self.__update_pred_pointer(id_, None)
            for cid in self[id_].successors(self._identifier) or []:
                self.__update_succ_pointer(id_, cid, self.node_class.DELETE)

        # Update parent info
        self.__update_succ_pointer(parent, identifier, self.node_class.DELETE)
        self.__update_pred_pointer(identifier, None)

        for id_ in removed:
            self.nodes.pop(id_)
        return len(removed)

    def remove_subtree(self, nid, identifier=None):
        """
        Get a subtree with ``nid`` being the root. If nid is None, an
        empty tree is returned.

        For the original tree, this method is similar to
        `remove_node(self,nid)`, because given node and its children
        are removed from the original tree in both methods.
        For the returned value and performance, these two methods are
        different:

            * `remove_node` returns the number of deleted nodes;
            * `remove_subtree` returns a subtree of deleted nodes;

        You are always suggested to use `remove_node` if your only to
        delete nodes from a tree, as the other one need memory
        allocation to store the new tree.

        :return: a :class:`Tree` object.
        """
        st = self._clone(identifier)
        if nid is None:
            return st

        if not self.contains(nid):
            raise NodeIDAbsentError("Node '%s' is not in the tree" % nid)
        st.root = nid

        # in original tree, the removed nid will be unreferenced from its parents children
        parent = self[nid].predecessor(self._identifier)

        removed = list(self.expand_tree(nid))
        for id_ in removed:
            if id_ == self.root:
                self.root = None
            st._nodes.update({id_: self._nodes.pop(id_)})
            st[id_].clone_pointers(self._identifier, st.identifier)
            st[id_].reset_pointers(self._identifier)
            if id_ == nid:
                st[id_].set_predecessor(None, st.identifier)
        self.__update_succ_pointer(parent, nid, self.node_class.DELETE)
        return st

    def rsearch(self, nid, filter_fn=None):
        """
        Traverse the tree branch along the branch from nid to its
        ancestors (until root).
        """
        if nid is None:
            return

        if not self.contains(nid):
            raise NodeIDAbsentError("Node '%s' is not in the tree" % nid)

        filter_fn = (lambda x: True) if (filter_fn is None) else filter_fn

        current = nid
        while current is not None:
            if filter_fn(self[current]):
                yield current
            # subtree() hasn't update the bpointer
            current = self[current].predecessor(self._identifier) if self.root != current else None

    def siblings(self, nid):
        """
        Return the siblings of given @nid.

        If @nid is root or there are no siblings, an empty list is returned.
        """
        siblings = []

        if nid != self.root:
            pid = self[nid].predecessor(self._identifier)
            siblings = [self[i] for i in self[pid].successors(self._identifier) if i != nid]

        return siblings

    def size(self, level=None):
        """
        Get the number of nodes of the whole tree if @level is not
        given. Otherwise, the total number of nodes at specific level
        is returned.

        @param level The level number in the tree. It must be between
        [0, tree.depth].

        Otherwise, InvalidLevelNumber exception will be raised.
        """
        if level is None:
            return len(self._nodes)
        else:
            try:
                level = int(level)
                return len([node for node in self.all_nodes_itr() if self.level(node.identifier) == level])
            except Exception:
                raise TypeError("level should be an integer instead of '%s'" % type(level))

    def subtree(self, nid: Optional[str], identifier: Optional[str] = None) -> Tree:
        """
        Return a shallow COPY of subtree with nid being the new root.
        If nid is None, return an empty tree.
        If you are looking for a deepcopy, please create a new tree
        with this shallow copy, e.g.,

        .. code-block:: python

            new_tree = Tree(t.subtree(t.root), deep=True)

        This line creates a deep copy of the entire tree.
        """
        st = self._clone(identifier)
        if nid is None:
            return st

        if not self.contains(nid):
            raise NodeIDAbsentError("Node '%s' is not in the tree" % nid)

        st.root = nid
        for node_n in self.expand_tree(nid):
            st._nodes.update({self[node_n].identifier: self[node_n]})
            # define nodes parent/children in this tree
            # all pointers are the same as copied tree, except the root
            st[node_n].clone_pointers(self._identifier, st.identifier)
            if node_n == nid:
                # reset root parent for the new tree
                st[node_n].set_predecessor(None, st.identifier)
        return st

    def update_node(self, nid, **attrs):
        """
        Update node's attributes.

        :param nid: the identifier of modified node
        :param attrs: attribute pairs recognized by Node object
        :return: None
        """
        cn = self[nid]
        for attr, val in attrs.items():
            if attr == "identifier":
                # Updating node id meets following contraints:
                # * Update node identifier property
                # * Update parent's followers
                # * Update children's parents
                # * Update tree registration of var _nodes
                # * Update tree root if necessary
                cn = self._nodes.pop(nid)
                setattr(cn, "identifier", val)
                self._nodes[val] = cn

                if cn.predecessor(self._identifier) is not None:
                    self[cn.predecessor(self._identifier)].update_successors(
                        nid, mode=self.node_class.REPLACE, replace=val, tree_id=self._identifier
                    )

                for fp in cn.successors(self._identifier):
                    self[fp].set_predecessor(val, self._identifier)

                if self.root == nid:
                    self.root = val
            else:
                setattr(cn, attr, val)

    def to_dict(self, nid=None, key=None, sort=True, reverse=False, with_data=False):
        """Transform the whole tree into a dict."""

        nid = self.root if (nid is None) else nid
        ntag = self[nid].tag
        tree_dict = {ntag: {"children": []}}
        if with_data:
            tree_dict[ntag]["data"] = self[nid].data

        if self[nid].expanded:
            queue = [self[i] for i in self[nid].successors(self._identifier)]
            key = (lambda x: x) if (key is None) else key
            if sort:
                queue.sort(key=key, reverse=reverse)

            for elem in queue:
                tree_dict[ntag]["children"].append(
                    self.to_dict(elem.identifier, with_data=with_data, sort=sort, reverse=reverse)
                )
            if len(tree_dict[ntag]["children"]) == 0:
                tree_dict = self[nid].tag if not with_data else {ntag: {"data": self[nid].data}}
            return tree_dict

    def to_json(self, with_data=False, sort=True, reverse=False):
        """To format the tree in JSON format."""
        return json.dumps(self.to_dict(with_data=with_data, sort=sort, reverse=reverse))
