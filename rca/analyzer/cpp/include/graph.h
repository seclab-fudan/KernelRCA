#pragma once 
#include "spdlog.h"
#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <vector>

template<class IdentifyType, class ValueType> 
struct Node {
    IdentifyType id; 
    ValueType value;
    std::set<Node*> from;
    std::set<Node*> to; 
    Node(const IdentifyType& id, const ValueType& value) : id(id), value(value) { }
    ~Node() { from.clear(); to.clear(); }

    class iterator : public std::iterator<std::forward_iterator_tag, IdentifyType> {
    private:
        typename std::set<Node*>::iterator _it;
    public:
        explicit iterator(typename std::set<Node*>::const_iterator it): _it(it) {}
        iterator& operator++() { ++_it; return *this; }
        iterator operator++(int) { iterator retval = *this; ++(*this); return retval; }
        bool operator==(iterator other) const { return _it == other._it; }
        bool operator!=(iterator other) const { return !(*this == other); }
        IdentifyType operator*() const { return _it->id; }
    };

    iterator from_begin() { return iterator(from.begin()); }
    iterator from_end() { return iterator(from.end()); }

    iterator to_begin() { return iterator(to.begin()); }
    iterator to_end() { return iterator(to.end()); }
};

template<class IdentifyType, class ValueType>
class DirectedGraph {
private:
    uint64_t node_cnt; 
    std::map<IdentifyType, Node<IdentifyType, ValueType>*> __id2node; 
public:
    std::set<IdentifyType> allNodes; 
    Node<IdentifyType, ValueType>* insertNode(const IdentifyType& id, const ValueType& value) {
        auto node = new Node(id, value);
        allNodes.insert(id); 
        __id2node[id] = node;
        return node; 
    }

    ~DirectedGraph() {
        for (auto& node: allNodes)
            delete node; 
        allNodes.clear();
        __id2node.clear();
    }

    void insertEdge(Node<IdentifyType, ValueType>* from, Node<IdentifyType, ValueType>* to) {
        from->to.insert(to);
        to->from.insert(from);
    }

    void insertEdge(const IdentifyType& from, const IdentifyType& to) {
        Node<IdentifyType, ValueType>* from_node = __id2node[from], *to_node = __id2node[to];
        insertEdge(from_node, to_node);
    }

    bool hasNode(const IdentifyType& id) {
        return __id2node.count(id);
    }

    Node<IdentifyType, ValueType>* getNode(const IdentifyType& id) {
        return __id2node.at(id);
    }

    size_t size() {
        return __id2node.size();
    }

    bool hasEdge(const IdentifyType& from, const IdentifyType& to) {
        Node<IdentifyType, ValueType>* from_node = __id2node[from], *to_node = __id2node[to];
        return from_node->to.count(to_node);
    }

    Node<IdentifyType, ValueType>* operator [] (const IdentifyType& id) {
        this->getNode(id);
    }

} ;
