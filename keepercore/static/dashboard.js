/* globals Chart:false, feather:false */

class Graph {
    constructor(array) {
        this.vertexes = {}
        this.childs = {}
        this.parents = {}
        array.forEach(elem => this.add(elem))
    }

    addVertex(vertex) {
        this.vertexes[vertex.id] = vertex.data
    }

    addEdge(edge) {
        // safe guard, if there is no related vertex
        if (!this.vertexes[edge.from]) this.vertexes[edge.from] = {}
        if (!this.vertexes[edge.to]) this.vertexes[edge.to] = {}
        // add edge
        if (!this.childs[edge.from]) this.childs[edge.from] = []
        if (!this.parents[edge.to]) this.parents[edge.to] = []
        this.childs[edge.from].push(edge.to)
        this.parents[edge.to].push(edge.from)
    }

    /**
     * Add either vertex or edge document.
     */
    add(document) {
        if ("id" in document && "data" in document) this.addVertex(document)
        else if ("from" in document && "to" in document) this.addEdge(document)
    }

    /**
     * A compound is this:
     * - a node with more than 5 elements
     * - a node that has one compound as children
     */
    isCompound(elemId) {
        if (!elemId in this.parents) return false
        if (elemId in this.childs) {
            const childs = this.childs[elemId]
            if (childs.length > 5) return true
            // for (const childId of childs) {
            //     if (this.isCompound(childId)) return true
            // }
        }
        return false
    }

    /**
     * Create cytoscape formatted jason
     * @returns {
     *   {
     *      nodes: [
     *          { data: { id: "some_id", parent: "parent_id", some_other: *} },
     *          { data: { id: "some_id", some_other: *} },
     *          { data: { id: "some_id"} }
     *      ],
     *      edges: [
     *          { data: { source: "some_id", target: "some_id"}}
     *      ]
     *   }
     * }
     */
    cytoscape() {
        const compounds = new Set(Object.keys(this.childs).filter(key => this.isCompound(key)))
        const self = this

        function toNode(id, node) {
            // is there a parent that is a compound?
            const p = id in self.parents ? self.parents[id].find(p => compounds.has(p)) : undefined
            const parent = p !== undefined ? {'parent': p} : {}
            return {'group':'nodes', 'data': {...node, ...parent, 'id': id}}
        }

        function toEdge(from, to) {
            return {group:'edges', 'data': {'source': from, 'target': to}}
        }

        return {
            nodes: Object.keys(this.vertexes).map(id => toNode(id, this.vertexes[id])),
            edges: Object.keys(this.childs)
                .filter(from => !compounds.has(from))
                .flatMap(from => this.childs[from].map(to => toEdge(from, to)))
        }
    }
}

(
    function () {

        const search = document.getElementById("search")

        search.addEventListener('keypress', function (e) {
            if (e.key === 'Enter') {
                query("/graph/ns/reported/query/graph", search.value, function (json) {
                    js = new Graph(json).cytoscape()
                    //console.log(js)
                    graph(js);
                })
            }
        });

        const query = function (url, queryString, callback) {
            const xhr = new XMLHttpRequest();
            xhr.open('POST', url, true);
            xhr.setRequestHeader("Content-Type", "text/plain");
            xhr.setRequestHeader("Accept", "application/json");
            xhr.responseType = 'json';
            xhr.onload = function () {
                const status = xhr.status;
                if (status === 200) {
                    callback(xhr.response);
                } else {
                    callback(xhr.response);
                }
            };
            xhr.send(queryString);
        };


        const graph = function (elements) {
            cytoscape({

                container: document.getElementById('cy'), // container to render in
                elements: elements,

                style: [ // the stylesheet for the graph
                    {
                        selector: 'node',
                        style: {
                            //'background-color': '#666',
                            'label': 'data(label)',
                            'width': 50,
                            'height': 50
                        }
                    },

                    {
                        selector: 'edge',
                        style: {
                            'width': 3,
                            'line-color': '#ccc',
                            'target-arrow-color': '#ccc',
                            'target-arrow-shape': 'triangle',
                            'curve-style': 'bezier'
                        }
                    }
                ],

                layout: {
                    //name: 'concentric',
                    // see options: https://github.com/iVis-at-Bilkent/cytoscape.js-fcose
                    name: 'fcose',
                    animationDuration: 1000,
                    sampleSize: 100,
                    nestingFactor: 5,
                    nodeDimensionsIncludeLabels: true,
                    uniformNodeDimensions: false,
                    tile: true
                }
            })
        };
    }
)()
