#ifndef HTREE_HPP
#define HTREE_HPP
#include <cstring>
#include <string>
#include <string.h> // strelen

#ifndef HASH_HPP
#include "sha.h"
#endif

#ifndef NODE_HPP
#define NODE_HPP
#include <cassert> //assert

class Node
{
private:
    uint32_t volume; // data id or merkle volume;
    hash hash_t; // store hash function;
	Node* parent;
    Node* left;
    Node* right;

public:
    Node(uint32_t vol, hash hs);
    Node* get_parent();
    uint32_t get_volume();
    void set_parent(Node* p);
    void set_volume(uint32_t vol);
    int set_child(Node* child, int index);
    Node* get_child(int index);
    hash get_hash();
    int check_dir();
    Node* get_sibling();
    int set_hash(hash p_hash);
    int reset_hash(hash p_hash);
    ~Node();
};
#endif

class MT{
private:
    Node *_root;
    void set_root_hash(hash hash_val);
    int directly_insert(uint32_t id, hash hash_t);
    int update_parent_hash(Node*left, Node *right, Node *parent);
    void _printBT(const char* prefix, Node*node, bool isLeft);

public:
    MT();
    ~MT();
    int update_from_leaf(Node *leaf);
    Node* get_node(uint32_t id);
    hash get_root_hash();
    int insert(uint32_t id, hash hash_t);
    int update(uint32_t id, hash hash_t);
    void printBT();
    int check_leaf(uint32_t id, hash hash_t); // check if leaf exist and hash exist;
};


#endif