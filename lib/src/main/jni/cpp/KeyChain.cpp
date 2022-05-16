#include "KeyChain.h"
#include <cstdlib>
#include <cstring>

KeyChain::KeyChain() {
    this->name = nullptr;
    this->value = nullptr;
    this->next = nullptr;
}

KeyChain::~KeyChain() {
    if (this->name != nullptr) {
        free(this->name);
        this->name = nullptr;
    }
    if (this->value != nullptr) {
        free(this->value);
        this->value = nullptr;
    }
    if (this->next != nullptr) {
        delete this->next;
        this->next = nullptr;
    }
}

void KeyChain::assign(const char *key, const char *val) {
    if (key == nullptr || val == nullptr) return;
    size_t k_len = strlen(key);
    this->name = (char *) malloc(k_len + 1);
    memcpy(this->name, key, k_len);
    *(this->name + k_len) = '\0';
    //
    size_t v_len = strlen(val);
    this->value = (char *) malloc(v_len + 1);
    memcpy(this->value, val, v_len);
    *(this->value + v_len) = '\0';
}