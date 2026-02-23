#include "MerkleTree.h"


Node::Node(uint32_t vol, hash *hs){
    volume = vol;
    hash_t = hs;
    parent = NULL;
    // memset(children, 0, sizeof(children));
    left = NULL;
    right = NULL;
}


Node* Node::get_parent(){
    return parent;
}


uint32_t Node::get_volume(){
    return volume;
}


void Node::set_parent(Node* p){
    parent = p;
}


void Node::set_volume(uint32_t vol){
    volume = vol;
}

int Node::set_child(Node* child, int index){
    if (index == 0){
        this -> left = child;
    }else if(index == 1){
        this -> right = child;
    }else{
        return 1;
    }
    return 0;
}


Node* Node::get_child(int index){
    assert(index <= 1);
    if (index == 0){
        return left;
    }else{
        return right;
    }
}


hash* Node::get_hash(){ // if hash is null
    return hash_t;
}


int Node::check_dir(){
    // return 0 if current is left; else right;
    return parent->get_child(0) == this ? 0 : 1;
}


Node* Node::get_sibling(){ // return another child;
    Node* parent = get_parent();
    return parent->get_child(0) == this ? parent->get_child(1) : parent->get_child(0);
}


int Node::set_hash(hash *p_hash){
    hash_t = p_hash;
    return 0;
}


int Node::reset_hash(hash *p_hash){
    delete hash_t;
    hash_t = p_hash;
    return 0;
}


Node::~Node(){
    delete left;
    delete right;
    delete hash_t;  
};


void MT::set_root_hash(hash *hash_val){
    _root->set_hash(hash_val);
}


int MT::directly_insert(uint32_t id, hash *hash_t){
    uint32_t current_val = _root->get_volume();
    int child_idx;
    Node *current_node = _root;
    Node *parent_node = current_node;
    
    for (int i = current_val-1; i >= 0; i--){ // find the leaf; // from top to bottom            
        child_idx = id>>i & 1;
        assert(child_idx<=1);
        
        parent_node = current_node;
        current_node = parent_node -> get_child(child_idx); // choose path using id[i];
        // current_val -= 1;
        
        if (not current_node){ // create node if empty;
            current_node = new Node((i==0)?id: i, (i==0)?hash_t:NULL);
            current_node->set_parent(parent_node); 
            parent_node ->set_child(current_node , child_idx);
        }
            
    }
    // return 0;
    return update_from_leaf(current_node);
}


int MT::update_parent_hash(Node *left, Node *right, Node *parent){
    hash *hash_val, *hash1, *hash2;
    int len1, len2;
    hash_val = parent->get_hash();
    if (not hash_val){
        hash_val = (hash*) malloc(SHA_LEN); // allocate hash if not exist before;
    }

    uint8_t *new_msg = (uint8_t *) malloc(2*SHA_LEN);
    memset(new_msg, 0, 2*SHA_LEN);

    if (not left || not left->get_hash()){
        hash1 = NULL;
        len1 = 0;
        // return compute_hash(*(right->get_hash()), SHA_LEN, hash_val);
    }else{
        hash1 = left -> get_hash();
        len1 = SHA_LEN;
    }
    if (right == NULL || not right->get_hash()){
        hash2 = NULL;
        len2 = 0;
        // return compute_hash(*(left->get_hash()), SHA_LEN, hash_val);
    }else{
        hash2 = right -> get_hash();
        len2 = SHA_LEN;
    }

    memcpy(new_msg, hash1, len1);
    memcpy(new_msg+len1, hash2, len2);

    if (compute_hash(new_msg, len1+len2, hash_val) != 0){
        free(new_msg);
        return 1;
    }

    parent->set_hash(hash_val);
    free(new_msg);
    return 0;
}

void MT::_printBT(const char* prefix, Node *node, bool isLeft)
{
    uint32_t volume;
    hash *h=NULL;
    Node *left=NULL;
    Node *right=NULL;

    if( node != NULL ){
        // print the value of the node
        volume = node -> get_volume();
        left = node -> get_child(0);
        right = node -> get_child(1);
        h = node -> get_hash();
        if (not h){
        }else{
            show_hash(h);
        }
        char *new_prefix = (char *)malloc(strlen(prefix) + 5);
        memset(new_prefix, 0, strlen(prefix)+5);

        memcpy(new_prefix, prefix, strlen(prefix));
        memcpy(new_prefix+strlen(prefix), isLeft ? "â”?  " : "    ", 4);
        
        // enter the next tree level - left and right branch            
        _printBT(new_prefix, left, true);
        _printBT(new_prefix, right, false);
        free(new_prefix);

    }
}


MT::MT(){
    _root = new Node(1, NULL);
}


MT::~MT(){
    if (_root != NULL){
        delete _root;
    }
}


int MT::update_from_leaf(Node *leaf){  
    Node *current_node=leaf;
    Node *sibling=NULL;
    Node *parent=NULL;
    int current_idx;

    while(current_node != _root){
        current_idx = current_node -> check_dir();
        sibling = current_node->get_sibling();
        parent = current_node->get_parent();

        if (current_idx == 0){ // if current is left:
            update_parent_hash(current_node, sibling, parent);
        }else{ // if right;
            update_parent_hash(sibling, current_node, parent);
        }
        current_node = parent;
    }
    return 0;
}

// check if the node exists; if exist, return a address;
Node* MT::get_node(uint32_t id){
    uint32_t current_val = _root->get_volume();
    if (id >> current_val != 0){ // if id < 2^root_val; out of scope; 
        return NULL;
    }
    int child_idx;
    Node *current_node = _root;
    
    for (int i=(int) current_val -1; i>=0; i--){
        child_idx = id >> i & 1; // find the i-th number of child idx;
        assert(child_idx <= 1);
        current_node = current_node->get_child(child_idx);
        if (not current_node){
            return NULL;
        }
    }
    return current_node;
} 


hash* MT::get_root_hash(){
    return _root->get_hash();
}


int MT::insert(uint32_t id, hash *hash_t){
    uint32_t current_volume = _root->get_volume();
    if ( (id >> current_volume) == 0){ // if id < 2^root: directly insert;
        return directly_insert(id, hash_t);
    }

    else{ // new root node and recursive
        Node *new_root = new Node(current_volume+1 , NULL);
        new_root->set_child(_root, 0);
        _root -> set_parent(new_root);
        _root = new_root;
        update_parent_hash(_root->get_child(0), NULL, _root); // update parent after insert;
        return insert(id, hash_t);
    }

}

// update leaf with new hash; return 0 if update success;
int MT::update(uint32_t id, hash *hash_t){ 
    Node *node = get_node(id);
    if (not node){
        return 1; // not exist;
    }
    node->reset_hash(hash_t); // delete previous hash and set new hash;
    if (update_from_leaf(node) !=0){
        return 1;
    }
    return 0;
}


void MT::printBT()
{
    _printBT("", _root, false);    
}

// check if node id exist with hash_t; and the path;
int MT::check_leaf(uint32_t id, hash *hash_t){
    Node *leaf = get_node(id);
    if (not leaf){
        return 1;
    }
    return equal_hash(hash_t, leaf->get_hash());
}


