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

#include "node.h"
#include "ssl_sess_storage.h"
#include "node_crypto.h"

#include <string.h> // memset
#include <sys/mman.h> // mmap

#define UNWRAP_STORAGE(ctx)\
    SessionStorage* storage = reinterpret_cast<SessionStorage*>(\
        SSL_CTX_get_ex_data(ctx, ssl_idx));

namespace node {
namespace crypto {

using namespace v8;


int SessionStorage::ssl_idx = -1;


SessionStorage* SessionStorage::Setup(SecureContext* sc,
                                      Handle<Object> options) {

  // Register storage's index
  if (ssl_idx == -1) {
    ssl_idx = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    assert(ssl_idx != -1);
  }

  // Create new storage and put it inside SSL_CTX
  SessionStorage* storage = Create(sc, options, kLocal);

  Setup(sc, storage);

  return storage;
}


void SessionStorage::Setup(SecureContext* sc, SessionStorage* storage) {
  if (sc->storage_ != NULL) SessionStorage::Destroy(sc->storage_);
  sc->storage_ = storage;

  SSL_CTX_set_session_cache_mode(sc->ctx_,
                                 SSL_SESS_CACHE_SERVER |
                                 SSL_SESS_CACHE_NO_INTERNAL |
                                 SSL_SESS_CACHE_NO_AUTO_CLEAR);
  SSL_CTX_sess_set_new_cb(sc->ctx_, SessionStorage::New);
  SSL_CTX_sess_set_get_cb(sc->ctx_, SessionStorage::Get);
  SSL_CTX_sess_set_remove_cb(sc->ctx_, SessionStorage::Remove);
  SSL_CTX_set_ex_data(sc->ctx_, ssl_idx, storage);
  SSL_CTX_set_timeout(sc->ctx_, storage->timeout_ / 1e9);
}


SessionStorage* SessionStorage::Create(SecureContext* sc,
                                       Handle<Object> options,
                                       StorageType type) {
  HandleScope scope;

  int size = 10 * 1024;
  int64_t timeout = 5 * 60 * 1e9; // 5 minutes

  Local<Value> size_prop = options->Get(String::NewSymbol("size"));
  if (size_prop->IsNumber()) size = size_prop->Int32Value();

  Local<Value> timeout_prop = options->Get(String::NewSymbol("timeout"));
  if (timeout_prop->IsNumber()) timeout = timeout_prop->IntegerValue() * 1e6;

  if (type == kLocal) {
    return new SessionStorage(size, timeout);
  } else {
    return CreateShared(size, timeout);
  }
}


SessionStorage* SessionStorage::CreateShared(int32_t size, uint64_t timeout) {
  void* raw = mmap(NULL,
                   sizeof(SessionStorage) + sizeof(KeyValue*[size]),
                   PROT_READ | PROT_WRITE,
                   MAP_ANON | MAP_SHARED,
                   -1,
                   0);
  if (raw == reinterpret_cast<void*>(-1)) abort();
  memset(raw, 0, sizeof(SessionStorage) + sizeof(KeyValue*[size]));

  SessionStorage* storage = reinterpret_cast<SessionStorage*>(raw);
  storage->map_ = reinterpret_cast<KeyValue**>(
      reinterpret_cast<char*>(raw) + sizeof(SessionStorage));

  storage->Init(size, timeout, kShared);
  uv_mutex_init_shared(&storage->mutex_);

  assert(storage->is_shared());
  fprintf(stdout, "master: %p size: %d\n", storage, storage->size_);

  return storage;
}


void SessionStorage::Destroy(SessionStorage* storage) {
  if (storage->is_local()) {
    delete storage;
  } else {
    if (munmap(storage, sizeof(SessionStorage) +
                        sizeof(KeyValue*[storage->size_]))) {
      abort();
    }
  }
}


SessionStorage::SessionStorage(int32_t size, uint64_t timeout)
    : map_(new KeyValue*[size]) {
  Init(size, timeout, kLocal);

  // Nullify map
  memset(map_, 0, sizeof(map_[0]) * size_);
  uv_mutex_init(&mutex_);
}


void SessionStorage::Init(int32_t size, uint64_t timeout, StorageType type) {
  type_ = type;
  size_ = size;
  mask_ = size - 1;
  timeout_ = timeout;
}


SessionStorage::KeyValue::KeyValue(unsigned char* key,
                                   int len,
                                   unsigned char* value,
                                   int value_len)
    : len_(len),
      value_(value),
      value_len_(value_len),
      created_(uv_hrtime()) {
  key_ = new unsigned char[len];
  memcpy(key_, key, len);
}


inline bool SessionStorage::KeyValue::Equals(unsigned char* key, int len) {
  if (len != len_) return false;
  return memcmp(key, key_, len) == 0;
}


// Jenkins hash function
inline uint32_t SessionStorage::Hash(unsigned char* key, int len) {
  uint32_t hash = 0;

  for (int i = 0; i < len; i++) {
    hash += key[i];
    hash += (hash << 10);
    hash ^= (hash >> 6);
  }

  hash += (hash << 3);
  hash ^= (hash >> 11);
  hash += (hash >> 6);

  return hash;
}


uint32_t SessionStorage::GetIndex(unsigned char* key, int len) {
  uint32_t start = Hash(key, len) & mask_;
  uint32_t index;
  int tries = 0;

  uint64_t expire_edge = uv_hrtime() - timeout_;

  // Find closest cell with the same key value
  for (index = start; tries < 10; tries++, index = (index + 1) & mask_) {
    if (map_[index] == NULL) return index;

    // Remove expired items
    if (map_[index]->created_ < expire_edge) {
      delete map_[index];
      map_[index] = NULL;
    }
    if (map_[index]->Equals(key, len)) return index;
  }

  // Cleanup all neighboors
  // TODO: Use some sort of MRU algorithm here
  for (index = start; tries < 10; tries++, index = (index + 1) & mask_) {
    delete map_[index];
    map_[index] = NULL;
  }

  return start;
}


void SessionStorage::RemoveExpired() {
  uv_mutex_lock(&mutex_);
  uint64_t expire_edge = uv_hrtime() - timeout_;
  for (uint32_t i = 0; i < size_; i++) {
    if (map_[i] == NULL) continue;
    if (map_[i]->created_ < expire_edge) {
      delete map_[i];
      map_[i] = NULL;
    }
  }
  uv_mutex_unlock(&mutex_);
}


int SessionStorage::New(SSL* ssl, SSL_SESSION* sess) {
  UNWRAP_STORAGE(ssl->ctx)

  // Check if session is small enough to be stored
  int size = i2d_SSL_SESSION(sess, NULL);
  if (size > kMaxSessionSize) return 0;

  // Serialize session
  unsigned char* serialized = new unsigned char[size];
  unsigned char* pserialized = serialized;
  memset(serialized, 0, size);
  i2d_SSL_SESSION(sess, &pserialized);

  uv_mutex_lock(&storage->mutex_);
  // Put it into hashmap
  uint32_t index = storage->GetIndex(sess->session_id, sess->session_id_length);
  storage->map_[index] = new KeyValue(sess->session_id,
                                      sess->session_id_length,
                                      serialized,
                                      size);
  uv_mutex_unlock(&storage->mutex_);

  return 0;
}


void SessionStorage::Remove(SSL_CTX* ctx, SSL_SESSION* sess) {
  UNWRAP_STORAGE(ctx)

  uv_mutex_lock(&storage->mutex_);
  uint32_t index = storage->GetIndex(sess->session_id, sess->session_id_length);

  delete storage->map_[index];
  storage->map_[index] = NULL;
  uv_mutex_unlock(&storage->mutex_);
}


SSL_SESSION* SessionStorage::Get(SSL* ssl,
                                 unsigned char* id,
                                 int len,
                                 int* copy) {
  UNWRAP_STORAGE(ssl->ctx)

  // Do not use ref-counting for this session
  *copy = NULL;

  uv_mutex_lock(&storage->mutex_);
  uint32_t index = storage->GetIndex(id, len);

  SSL_SESSION* sess = NULL;
  KeyValue* kv = storage->map_[index];
  if (kv != NULL) {
    const unsigned char* buf = kv->value_;
    sess = d2i_SSL_SESSION(NULL, &buf, kv->value_len_);
  }
  uv_mutex_unlock(&storage->mutex_);

  return sess;
}


} // namespace crypto
} // namespace node
