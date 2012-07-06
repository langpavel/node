// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

#ifndef SSL_SESS_STORAGE_H_
#define SSL_SESS_STORAGE_H_

#include "node.h"

#include <openssl/ssl.h>
#include <stdint.h> // uint32_t

namespace node {
namespace crypto {

using namespace v8;

// Forward declaration
class SecureContext;

class SessionStorage {
 public:
  // Content of hashmap's space's cell
  // NOTE: that constructors copies `key`, while `value` is used as it is.
  class KeyValue {
   public:
    KeyValue(unsigned char* key, int len, unsigned char* value, int value_len);

    ~KeyValue() {
      delete[] key_;
      delete[] value_;
    }

    inline bool Equals(unsigned char* key, int len);

   protected:
    unsigned char* key_;
    int len_;
    unsigned char* value_;
    int value_len_;
    uint64_t created_;

    friend class SessionStorage;
  };

  enum StorageType {
    kLocal,
    kShared
  };

  SessionStorage(int32_t size, uint64_t timeout);
  ~SessionStorage() {
    delete[] map_;
  }

  void Init(int32_t size, uint64_t timeout, StorageType type);
  uint32_t GetIndex(unsigned char* key, int len);
  void RemoveExpired();

  static SessionStorage* CreateShared(int32_t size, uint64_t timeout);
  static SessionStorage* Setup(SecureContext* sc, Handle<Object> options);
  static void Setup(SecureContext* sc, SessionStorage* storage);
  static SessionStorage* Create(SecureContext* sc,
                                Handle<Object> options,
                                StorageType type);
  static void Destroy(SessionStorage* storage);

  static inline uint32_t Hash(unsigned char* key, int len);
  static int New(SSL* ssl, SSL_SESSION* sess);
  static void Remove(SSL_CTX* ctx, SSL_SESSION* sess);
  static SSL_SESSION* Get(SSL* ssl, unsigned char* id, int len, int* copy);

  static inline SessionStorage* Cast(char* storage) {
    return reinterpret_cast<SessionStorage*>(storage);
  }

  inline bool is_local() { return type_ == kLocal; }
  inline bool is_shared() { return type_ == kShared; }

 public:
  StorageType type_;

  KeyValue** map_;
  uint32_t size_;
  uint32_t mask_;
  uint64_t timeout_;

  // Max serialized session size
  static const int kMaxSessionSize = 1024 * 8;

  // Index in SSL_CTX where SessionStorage instance will be stored
  static int ssl_idx;
  uv_mutex_t mutex_;
};

} // namespace crypto
} // namespace node

#endif // SSL_SESS_STORAGE_H_
