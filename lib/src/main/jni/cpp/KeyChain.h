#ifndef KEY_CHAIN
#define KEY_CHAIN

class KeyChain {
public:
    char *name;
    char *value;
    KeyChain *next;

    KeyChain();

    ~KeyChain();

    virtual void assign(const char *key, const char *val);
};

#endif