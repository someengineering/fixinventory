import sys
import os
import unittest

from fixlib.tree import Tree, Node, NodeIDAbsentError

"""
NOTE:
This module is copied and ported to proper Python 3.0 from https://github.com/caesar0301/treelib
Since this library has outdated vulnerable dependencies, we decided to copy it here directly.
"""


class TreeCase(unittest.TestCase):
    def setUp(self):
        tree = Tree(identifier="tree 1")
        tree.create_node("Harry", "harry")
        tree.create_node("Jane", "jane", parent="harry")
        tree.create_node("Bill", "bill", parent="harry")
        tree.create_node("Diane", "diane", parent="jane")
        tree.create_node("George", "george", parent="bill")
        # Harry
        #   |-- Jane
        #       |-- Diane
        #   |-- Bill
        #       |-- George
        self.tree = tree
        self.copytree = Tree(self.tree, deep=True)

    @staticmethod
    def get_t1():
        """
        root
        ├── A
        │   └── A1
        └── B
        """
        t = Tree(identifier="t1")
        t.create_node(tag="root", identifier="r")
        t.create_node(tag="A", identifier="a", parent="r")
        t.create_node(tag="B", identifier="b", parent="r")
        t.create_node(tag="A1", identifier="a1", parent="a")
        return t

    @staticmethod
    def get_t2():
        """
        root2
        ├── C
        └── D
            └── D1
        """
        t = Tree(identifier="t2")
        t.create_node(tag="root2", identifier="r2")
        t.create_node(tag="C", identifier="c", parent="r2")
        t.create_node(tag="D", identifier="d", parent="r2")
        t.create_node(tag="D1", identifier="d1", parent="d")
        return t

    def test_tree(self):
        self.assertEqual(isinstance(self.tree, Tree), True)
        self.assertEqual(isinstance(self.copytree, Tree), True)

    def test_is_root(self):
        # retro-compatibility
        self.assertTrue(self.tree._nodes["harry"].is_root())
        self.assertFalse(self.tree._nodes["jane"].is_root())

    def test_tree_wise_is_root(self):
        subtree = self.tree.subtree("jane", identifier="subtree 2")
        # harry is root of tree 1 but not present in subtree 2
        self.assertTrue(self.tree._nodes["harry"].is_root("tree 1"))
        self.assertNotIn("harry", subtree._nodes)
        # jane is not root of tree 1 but is root of subtree 2
        self.assertFalse(self.tree._nodes["jane"].is_root("tree 1"))
        self.assertTrue(subtree._nodes["jane"].is_root("subtree 2"))

    def test_paths_to_leaves(self):
        paths = self.tree.paths_to_leaves()
        self.assertEqual(len(paths), 2)
        self.assertTrue(["harry", "jane", "diane"] in paths)
        self.assertTrue(["harry", "bill", "george"] in paths)

    def test_nodes(self):
        self.assertEqual(len(self.tree.nodes), 5)
        self.assertEqual(len(self.tree.all_nodes()), 5)
        self.assertEqual(self.tree.size(), 5)
        self.assertEqual(self.tree.get_node("jane").tag, "Jane")
        self.assertEqual(self.tree.contains("jane"), True)
        self.assertEqual("jane" in self.tree, True)
        self.assertEqual(self.tree.contains("alien"), False)
        self.tree.create_node("Alien", "alien", parent="jane")
        self.assertEqual(self.tree.contains("alien"), True)
        self.tree.remove_node("alien")

    def test_getitem(self):
        """Nodes can be accessed via getitem."""
        for node_id in self.tree.nodes:
            try:
                self.tree[node_id]
            except NodeIDAbsentError:
                self.fail("Node access should be possible via getitem.")
        try:
            self.tree["root"]
        except NodeIDAbsentError:
            pass
        else:
            self.fail("There should be no default fallback value for getitem.")

    def test_parent(self):
        for nid in self.tree.nodes:
            if nid == self.tree.root:
                self.assertEqual(self.tree.parent(nid), None)
            else:
                self.assertEqual(self.tree.parent(nid) in self.tree.all_nodes(), True)

    def test_ancestor(self):
        for nid in self.tree.nodes:
            if nid == self.tree.root:
                self.assertEqual(self.tree.ancestor(nid), None)
            else:
                for level in range(self.tree.level(nid) - 1, 0, -1):
                    self.assertEqual(self.tree.ancestor(nid, level=level) in self.tree.all_nodes(), True)

    def test_children(self):
        for nid in self.tree.nodes:
            children = self.tree.is_branch(nid)
            for child in children:
                self.assertEqual(self.tree[child] in self.tree.all_nodes(), True)
            children = self.tree.children(nid)
            for child in children:
                self.assertEqual(child in self.tree.all_nodes(), True)
        try:
            self.tree.is_branch("alien")
        except NodeIDAbsentError:
            pass
        else:
            self.fail("The absent node should be declaimed.")

    def test_remove_node(self):
        self.tree.create_node("Jill", "jill", parent="george")
        self.tree.create_node("Mark", "mark", parent="jill")
        self.assertEqual(self.tree.remove_node("jill"), 2)
        self.assertEqual(self.tree.get_node("jill") is None, True)
        self.assertEqual(self.tree.get_node("mark") is None, True)

    def test_tree_wise_depth(self):
        # Try getting the level of this tree
        self.assertEqual(self.tree.depth(), 2)
        self.tree.create_node("Jill", "jill", parent="george")
        self.assertEqual(self.tree.depth(), 3)
        self.tree.create_node("Mark", "mark", parent="jill")
        self.assertEqual(self.tree.depth(), 4)

        # Try getting the level of the node
        """
        Harry
        |___ Bill
        |    |___ George
        |         |___ Jill
        |              |___ Mark
        |___ Jane
        |    |___ Diane
        """
        self.assertEqual(self.tree.depth(self.tree.get_node("mark")), 4)
        self.assertEqual(self.tree.depth(self.tree.get_node("jill")), 3)
        self.assertEqual(self.tree.depth(self.tree.get_node("george")), 2)
        self.assertEqual(self.tree.depth("jane"), 1)
        self.assertEqual(self.tree.depth("bill"), 1)
        self.assertEqual(self.tree.depth("harry"), 0)

        # Try getting Exception
        node = Node("Test One", "identifier 1")
        self.assertRaises(NodeIDAbsentError, self.tree.depth, node)

        # Reset the test case
        self.tree.remove_node("jill")

    def test_leaves(self):
        # retro-compatibility
        leaves = self.tree.leaves()
        for nid in self.tree.expand_tree():
            self.assertEqual((self.tree[nid].is_leaf()) == (self.tree[nid] in leaves), True)
        leaves = self.tree.leaves(nid="jane")
        for nid in self.tree.expand_tree(nid="jane"):
            self.assertEqual(self.tree[nid].is_leaf() == (self.tree[nid] in leaves), True)

    def test_tree_wise_leaves(self):
        leaves = self.tree.leaves()
        for nid in self.tree.expand_tree():
            self.assertEqual((self.tree[nid].is_leaf("tree 1")) == (self.tree[nid] in leaves), True)
        leaves = self.tree.leaves(nid="jane")
        for nid in self.tree.expand_tree(nid="jane"):
            self.assertEqual(self.tree[nid].is_leaf("tree 1") == (self.tree[nid] in leaves), True)

    def test_link_past_node(self):
        self.tree.create_node("Jill", "jill", parent="harry")
        self.tree.create_node("Mark", "mark", parent="jill")
        self.assertEqual("mark" not in self.tree.is_branch("harry"), True)
        self.tree.link_past_node("jill")
        self.assertEqual("mark" in self.tree.is_branch("harry"), True)

    def test_expand_tree(self):
        # default config
        # Harry
        #   |-- Jane
        #       |-- Diane
        #   |-- Bill
        #       |-- George
        # Traverse in depth first mode preserving insertion order
        nodes = [nid for nid in self.tree.expand_tree(sorting=False)]
        self.assertEqual(nodes, ["harry", "jane", "diane", "bill", "george"])
        self.assertEqual(len(nodes), 5)

        # By default, traverse depth first and sort child nodes by node tag
        nodes = [nid for nid in self.tree.expand_tree()]
        self.assertEqual(nodes, ["harry", "bill", "george", "jane", "diane"])
        self.assertEqual(len(nodes), 5)

        # expanding from specific node
        nodes = [nid for nid in self.tree.expand_tree(nid="bill")]
        self.assertEqual(nodes, ["bill", "george"])
        self.assertEqual(len(nodes), 2)

        # changing into width mode preserving insertion order
        nodes = [nid for nid in self.tree.expand_tree(mode=Tree.WIDTH, sorting=False)]
        self.assertEqual(nodes, ["harry", "jane", "bill", "diane", "george"])
        self.assertEqual(len(nodes), 5)

        # Breadth first mode, child nodes sorting by tag
        nodes = [nid for nid in self.tree.expand_tree(mode=Tree.WIDTH)]
        self.assertEqual(nodes, ["harry", "bill", "jane", "george", "diane"])
        self.assertEqual(len(nodes), 5)

        # expanding by filters
        # Stops at root
        nodes = [nid for nid in self.tree.expand_tree(filter_fn=lambda x: x.tag == "Bill")]
        self.assertEqual(len(nodes), 0)
        nodes = [nid for nid in self.tree.expand_tree(filter_fn=lambda x: x.tag != "Bill")]
        self.assertEqual(nodes, ["harry", "jane", "diane"])
        self.assertEqual(len(nodes), 3)

    def test_move_node(self):
        diane_parent = self.tree.parent("diane")
        self.tree.move_node("diane", "bill")
        self.assertEqual("diane" in self.tree.is_branch("bill"), True)
        self.tree.move_node("diane", diane_parent.identifier)

    def test_paste_tree(self):
        new_tree = Tree()
        new_tree.create_node("Jill", "jill")
        new_tree.create_node("Mark", "mark", parent="jill")
        self.tree.paste("jane", new_tree)
        self.assertEqual("jill" in self.tree.is_branch("jane"), True)
        self.tree.remove_node("jill")
        self.assertNotIn("jill", self.tree.nodes.keys())
        self.assertNotIn("mark", self.tree.nodes.keys())

    def test_merge(self):
        # merge on empty initial tree
        t1 = Tree(identifier="t1")
        t2 = self.get_t2()
        t1.merge(nid=None, new_tree=t2)

        self.assertEqual(t1.identifier, "t1")
        self.assertEqual(t1.root, "r2")
        self.assertEqual(set(t1._nodes.keys()), {"r2", "c", "d", "d1"})

        # merge empty new_tree (on root)
        t1 = self.get_t1()
        t2 = Tree(identifier="t2")
        t1.merge(nid="r", new_tree=t2)

        self.assertEqual(t1.identifier, "t1")
        self.assertEqual(t1.root, "r")
        self.assertEqual(set(t1._nodes.keys()), {"r", "a", "a1", "b"})

        # merge at root
        t1 = self.get_t1()
        t2 = self.get_t2()
        t1.merge(nid="r", new_tree=t2)

        self.assertEqual(t1.identifier, "t1")
        self.assertEqual(t1.root, "r")
        self.assertNotIn("r2", t1._nodes.keys())
        self.assertEqual(set(t1._nodes.keys()), {"r", "a", "a1", "b", "c", "d", "d1"})

        # merge on node
        t1 = self.get_t1()
        t2 = self.get_t2()
        t1.merge(nid="b", new_tree=t2)
        self.assertEqual(t1.identifier, "t1")
        self.assertEqual(t1.root, "r")
        self.assertNotIn("r2", t1._nodes.keys())
        self.assertEqual(set(t1._nodes.keys()), {"r", "a", "a1", "b", "c", "d", "d1"})

    def test_paste(self):
        # paste under root
        t1 = self.get_t1()
        t2 = self.get_t2()
        t1.paste(nid="r", new_tree=t2)
        self.assertEqual(t1.identifier, "t1")
        self.assertEqual(t1.root, "r")
        self.assertEqual(t1.parent("r2").identifier, "r")
        self.assertEqual(set(t1._nodes.keys()), {"r", "r2", "a", "a1", "b", "c", "d", "d1"})

        # paste under non-existing node
        t1 = self.get_t1()
        t2 = self.get_t2()
        with self.assertRaises(NodeIDAbsentError) as e:
            t1.paste(nid="not_existing", new_tree=t2)
        self.assertEqual(e.exception.args[0], "Node 'not_existing' is not in the tree")

        # paste under None nid
        t1 = self.get_t1()
        t2 = self.get_t2()
        with self.assertRaises(ValueError) as e:
            t1.paste(nid=None, new_tree=t2)
        self.assertEqual(e.exception.args[0], 'Must define "nid" under which new tree is pasted.')

        # paste under node
        t1 = self.get_t1()
        t2 = self.get_t2()
        t1.paste(nid="b", new_tree=t2)
        self.assertEqual(t1.identifier, "t1")
        self.assertEqual(t1.root, "r")
        self.assertEqual(t1.parent("b").identifier, "r")
        self.assertEqual(set(t1._nodes.keys()), {"r", "a", "a1", "b", "c", "d", "d1", "r2"})
        # paste empty new_tree (under root)
        t1 = self.get_t1()
        t2 = Tree(identifier="t2")
        t1.paste(nid="r", new_tree=t2)

        self.assertEqual(t1.identifier, "t1")
        self.assertEqual(t1.root, "r")
        self.assertEqual(set(t1._nodes.keys()), {"r", "a", "a1", "b"})

    def test_rsearch(self):
        for nid in ["harry", "jane", "diane"]:
            self.assertEqual(nid in self.tree.rsearch("diane"), True)

    def test_subtree(self):
        subtree_copy = Tree(self.tree.subtree("jane"), deep=True)
        self.assertEqual(subtree_copy.parent("jane") is None, True)
        subtree_copy["jane"].tag = "Sweeti"
        self.assertEqual(self.tree["jane"].tag == "Jane", True)
        self.assertEqual(subtree_copy.level("diane"), 1)
        self.assertEqual(subtree_copy.level("jane"), 0)
        self.assertEqual(self.tree.level("jane"), 1)

    def test_remove_subtree(self):
        subtree_shallow = self.tree.remove_subtree("jane")
        self.assertEqual("jane" not in self.tree.is_branch("harry"), True)
        self.tree.paste("harry", subtree_shallow)

    def test_remove_subtree_whole_tree(self):
        self.tree.remove_subtree("harry")
        self.assertIsNone(self.tree.root)
        self.assertEqual(len(self.tree.nodes.keys()), 0)

    def test_to_json(self):
        self.tree.to_json()
        self.tree.to_json(True)

    def test_siblings(self):
        self.assertEqual(len(self.tree.siblings("harry")) == 0, True)
        self.assertEqual(self.tree.siblings("jane")[0].identifier == "bill", True)

    def test_tree_data(self):
        class Flower(object):
            def __init__(self, color):
                self.color = color

        self.tree.create_node("Jill", "jill", parent="jane", data=Flower("white"))
        self.assertEqual(self.tree["jill"].data.color, "white")
        self.tree.remove_node("jill")

    def test_show_data_property(self):
        new_tree = Tree()

        sys.stdout = open(os.devnull, "w")  # stops from printing to console

        try:

            class Flower(object):
                def __init__(self, color):
                    self.color = color

            new_tree.create_node("Jill", "jill", data=Flower("white"))
        finally:
            sys.stdout.close()
            sys.stdout = sys.__stdout__  # stops from printing to console

    def test_level(self):
        self.assertEqual(self.tree.level("harry"), 0)
        depth = self.tree.depth()
        self.assertEqual(self.tree.level("diane"), depth)
        self.assertEqual(self.tree.level("diane", lambda x: x.identifier != "jane"), depth - 1)

    def test_size(self):
        self.assertEqual(self.tree.size(level=2), 2)
        self.assertEqual(self.tree.size(level=1), 2)
        self.assertEqual(self.tree.size(level=0), 1)

    def tearDown(self):
        self.tree = None
        self.copytree = None

    def test_all_nodes_itr(self):
        """
        tests: Tree.all_nodes_iter
        Added by: William Rusnack
        """
        new_tree = Tree()
        self.assertEqual(len(new_tree.all_nodes_itr()), 0)
        nodes = list()
        nodes.append(new_tree.create_node("root_node"))
        nodes.append(new_tree.create_node("second", parent=new_tree.root))
        for nd in new_tree.all_nodes_itr():
            self.assertTrue(nd in nodes)

    def test_filter_nodes(self):
        """
        tests: Tree.filter_nodes
        Added by: William Rusnack
        """
        new_tree = Tree(identifier="tree 1")

        self.assertEqual(tuple(new_tree.filter_nodes(lambda n: True)), ())

        nodes = list()
        nodes.append(new_tree.create_node("root_node"))
        nodes.append(new_tree.create_node("second", parent=new_tree.root))

        self.assertEqual(tuple(new_tree.filter_nodes(lambda n: False)), ())
        self.assertEqual(tuple(new_tree.filter_nodes(lambda n: n.is_root("tree 1"))), (nodes[0],))
        self.assertEqual(tuple(new_tree.filter_nodes(lambda n: not n.is_root("tree 1"))), (nodes[1],))
        self.assertTrue(set(new_tree.filter_nodes(lambda n: True)), set(nodes))

    def test_loop(self):
        tree = Tree()
        tree.create_node("a", "a")
        tree.create_node("b", "b", parent="a")
        tree.create_node("c", "c", parent="b")
        tree.create_node("d", "d", parent="c")
        try:
            tree.move_node("b", "d")
        except ValueError:
            pass

    def test_modify_node_identifier_directly_failed(self):
        tree = Tree()
        tree.create_node("Harry", "harry")
        tree.create_node("Jane", "jane", parent="harry")
        n = tree.get_node("jane")
        self.assertTrue(n.identifier == "jane")

        # Failed to modify
        n.identifier = "xyz"
        self.assertTrue(tree.get_node("xyz") is None)
        self.assertTrue(tree.get_node("jane").identifier == "xyz")

    def test_modify_node_identifier_recursively(self):
        tree = Tree()
        tree.create_node("Harry", "harry")
        tree.create_node("Jane", "jane", parent="harry")
        n = tree.get_node("jane")
        self.assertTrue(n.identifier == "jane")

        # Success to modify
        tree.update_node(n.identifier, identifier="xyz")
        self.assertTrue(tree.get_node("jane") is None)
        self.assertTrue(tree.get_node("xyz").identifier == "xyz")

    def test_modify_node_identifier_root(self):
        tree = Tree(identifier="tree 3")
        tree.create_node("Harry", "harry")
        tree.create_node("Jane", "jane", parent="harry")
        tree.update_node(tree["harry"].identifier, identifier="xyz", tag="XYZ")
        self.assertTrue(tree.root == "xyz")
        self.assertTrue(tree["xyz"].tag == "XYZ")
        self.assertEqual(tree.parent("jane").identifier, "xyz")

    def test_subclassing(self):
        class SubNode(Node):
            pass

        class SubTree(Tree):
            node_class = SubNode

        tree = SubTree()
        node = tree.create_node()
        self.assertTrue(isinstance(node, SubNode))

        tree = Tree(node_class=SubNode)
        node = tree.create_node()
        self.assertTrue(isinstance(node, SubNode))

    def test_shallow_copy_hermetic_pointers(self):
        # tree 1
        # Harry
        #   └── Jane
        #       └── Diane
        #   └── Bill
        #       └── George
        tree2 = self.tree.subtree(nid="jane", identifier="tree 2")
        # tree 2
        # Jane
        #   └── Diane

        # check that in shallow copy, instances are the same
        self.assertIs(self.tree["jane"], tree2["jane"])
        self.assertEqual(self.tree["jane"]._predecessor, {"tree 1": "harry", "tree 2": None})
        self.assertEqual(dict(self.tree["jane"]._successors), {"tree 1": ["diane"], "tree 2": ["diane"]})

        # when creating new node on subtree, check that it has no impact on initial tree
        tree2.create_node("Jill", "jill", parent="diane")
        self.assertIn("jill", tree2)
        self.assertIn("jill", tree2.is_branch("diane"))
        self.assertNotIn("jill", self.tree)
        self.assertNotIn("jill", self.tree.is_branch("diane"))

    def test_paste_duplicate_nodes(self):
        t1 = Tree()
        t1.create_node(identifier="A")
        t2 = Tree()
        t2.create_node(identifier="A")
        t2.create_node(identifier="B", parent="A")

        with self.assertRaises(ValueError) as e:
            t1.paste("A", t2)
        self.assertEqual(e.exception.args, ("Duplicated nodes ['A'] exists.",))

    def test_shallow_paste(self):
        t1 = Tree()
        n1 = t1.create_node(identifier="A")

        t2 = Tree()
        n2 = t2.create_node(identifier="B")

        t3 = Tree()
        n3 = t3.create_node(identifier="C")

        t1.paste(n1.identifier, t2)
        self.assertEqual(t1.to_dict(), {"A": {"children": ["B"]}})
        t1.paste(n1.identifier, t3)
        self.assertEqual(t1.to_dict(), {"A": {"children": ["B", "C"]}})

        self.assertEqual(t1.level(n1.identifier), 0)
        self.assertEqual(t1.level(n2.identifier), 1)
        self.assertEqual(t1.level(n3.identifier), 1)

    def test_root_removal(self):
        t = Tree()
        t.create_node(identifier="root-A")
        self.assertEqual(len(t.nodes.keys()), 1)
        self.assertEqual(t.root, "root-A")
        t.remove_node(identifier="root-A")
        self.assertEqual(len(t.nodes.keys()), 0)
        self.assertEqual(t.root, None)
        t.create_node(identifier="root-B")
        self.assertEqual(len(t.nodes.keys()), 1)
        self.assertEqual(t.root, "root-B")
