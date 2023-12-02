#include <openssl/bn.h>
#include <openssl/rand.h>
#include <string.h>

#include <chrono>
#include <iostream>
#include <mutex>
#include <shared_mutex>

#include "cosigner/cmp_ecdsa_offline_signing_service.h"
#include "cosigner/cmp_key_persistency.h"
#include "cosigner/cmp_offline_refresh_service.h"
#include "cosigner/cmp_signature_preprocessed_data.h"
#include "cosigner/cosigner_exception.h"
#include "cosigner/mpc_globals.h"
#include "crypto/GFp_curve_algebra/GFp_curve_algebra.h"
#include "crypto/elliptic_curve_algebra/elliptic_curve256_algebra.h"
#include "main_common.h"

using namespace fireblocks::common::cosigner;

using Clock = std::conditional<std::chrono::high_resolution_clock::is_steady,
                               std::chrono::high_resolution_clock,
                               std::chrono::steady_clock>::type;

static elliptic_curve256_algebra_ctx_t *
create_algebra(cosigner_sign_algorithm type) {
  switch (type) {
  case ECDSA_SECP256K1:
    return elliptic_curve256_new_secp256k1_algebra();
  case ECDSA_SECP256R1:
    return elliptic_curve256_new_secp256r1_algebra();
  case ECDSA_STARK:
    return elliptic_curve256_new_stark_algebra();
  }
  return NULL;
}

std::string setup_persistency::dump_key(const std::string &key_id) const {
  auto it = _keys.find(key_id);
  if (it == _keys.end())
    throw cosigner_exception(cosigner_exception::BAD_KEY);
  return HexStr(it->second.private_key,
                &it->second.private_key[sizeof(elliptic_curve256_scalar_t)]);
}

bool setup_persistency::key_exist(const std::string &key_id) const {
  return _keys.find(key_id) != _keys.end();
}

void setup_persistency::load_key(
    const std::string &key_id, cosigner_sign_algorithm &algorithm,
    elliptic_curve256_scalar_t &private_key) const {
  auto it = _keys.find(key_id);
  if (it == _keys.end())
    throw cosigner_exception(cosigner_exception::BAD_KEY);
  memcpy(private_key, it->second.private_key,
         sizeof(elliptic_curve256_scalar_t));
  algorithm = it->second.algorithm;
}

const std::string
setup_persistency::get_tenantid_from_keyid(const std::string &key_id) const {
  return TENANT_ID;
}

void setup_persistency::load_key_metadata(const std::string &key_id,
                                          cmp_key_metadata &metadata,
                                          bool full_load) const {
  auto it = _keys.find(key_id);
  if (it == _keys.end())
    throw cosigner_exception(cosigner_exception::BAD_KEY);
  metadata = it->second.metadata;
}

void setup_persistency::load_auxiliary_keys(const std::string &key_id,
                                            auxiliary_keys &aux) const {
  auto it = _keys.find(key_id);
  if (it == _keys.end())
    throw cosigner_exception(cosigner_exception::BAD_KEY);
  aux = it->second.aux_keys;
}

void setup_persistency::store_key(const std::string &key_id,
                                  cosigner_sign_algorithm algorithm,
                                  const elliptic_curve256_scalar_t &private_key,
                                  uint64_t ttl) {
  auto &info = _keys[key_id];
  memcpy(info.private_key, private_key, sizeof(elliptic_curve256_scalar_t));
  info.algorithm = algorithm;
}

void setup_persistency::store_key_metadata(const std::string &key_id,
                                           const cmp_key_metadata &metadata) {
  auto &info = _keys[key_id];
  info.metadata = metadata;
}

void setup_persistency::store_auxiliary_keys(const std::string &key_id,
                                             const auxiliary_keys &aux) {
  auto &info = _keys[key_id];
  info.aux_keys = aux;
}

void setup_persistency::store_keyid_tenant_id(const std::string &key_id,
                                              const std::string &tenant_id) {}

void setup_persistency::store_setup_data(const std::string &key_id,
                                         const setup_data &metadata) {
  _setup_data[key_id] = metadata;
}

void setup_persistency::load_setup_data(const std::string &key_id,
                                        setup_data &metadata) {
  metadata = _setup_data[key_id];
}

void setup_persistency::store_setup_commitments(
    const std::string &key_id,
    const std::map<uint64_t, commitment> &commitments) {
  _commitments[key_id] = commitments;
}

void setup_persistency::load_setup_commitments(
    const std::string &key_id, std::map<uint64_t, commitment> &commitments) {
  commitments = _commitments[key_id];
}

void setup_persistency::delete_temporary_key_data(const std::string &key_id,
                                                  bool delete_key) {
  _setup_data.erase(key_id);
  _commitments.erase(key_id);
  if (delete_key)
    _keys.erase(key_id);
}

class sign_platform : public platform_service {
public:
  sign_platform(uint64_t id) : _id(id), _positive_r(false) {}
  void set_positive_r(bool positive_r) { _positive_r = positive_r; }

private:
  void gen_random(size_t len, uint8_t *random_data) const {
    RAND_bytes(random_data, len);
  }

  const std::string get_current_tenantid() const { return TENANT_ID; }
  uint64_t get_id_from_keyid(const std::string &key_id) const { return _id; }
  void derive_initial_share(const share_derivation_args &derive_from,
                            cosigner_sign_algorithm algorithm,
                            elliptic_curve256_scalar_t *key) const {
    assert(0);
  }
  byte_vector_t encrypt_for_player(uint64_t id,
                                   const byte_vector_t &data) const {
    return data;
  }
  byte_vector_t decrypt_message(const byte_vector_t &encrypted_data) const {
    return encrypted_data;
  }
  bool backup_key(const std::string &key_id, cosigner_sign_algorithm algorithm,
                  const elliptic_curve256_scalar_t &private_key,
                  const cmp_key_metadata &metadata, const auxiliary_keys &aux) {
    return true;
  }
  void start_signing(const std::string &key_id, const std::string &txid,
                     const signing_data &data, const std::string &metadata_json,
                     const std::set<std::string> &players) {}
  void fill_signing_info_from_metadata(const std::string &metadata,
                                       std::vector<uint32_t> &flags) const {
    for (auto i = flags.begin(); i != flags.end(); ++i)
      *i = _positive_r ? POSITIVE_R : 0;
  }
  bool is_client_id(uint64_t player_id) const override { return false; }

  const uint64_t _id;
  bool _positive_r;
};

static inline bool is_positive(const elliptic_curve256_scalar_t &n) {
  return (n[0] & 0x80) == 0;
}

static uint8_t ZERO[sizeof(cmp_signature_preprocessed_data)] = {0};
class key_refresh_persistency;

class preprocessing_persistency
    : public cmp_ecdsa_offline_signing_service::preprocessing_persistency {
  void store_preprocessing_metadata(const std::string &request_id,
                                    const preprocessing_metadata &data,
                                    bool override) override {
    std::unique_lock lock(_mutex);
    if (!override && _metadata.find(request_id) != _metadata.end())
      throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
    _metadata[request_id] = data;
  }

  void
  load_preprocessing_metadata(const std::string &request_id,
                              preprocessing_metadata &data) const override {
    std::shared_lock lock(_mutex);
    auto it = _metadata.find(request_id);
    if (it == _metadata.end())
      throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
    data = it->second;
  }

  void store_preprocessing_data(const std::string &request_id, uint64_t index,
                                const ecdsa_signing_data &data) override {
    std::unique_lock lock(_mutex);
    _signing_data[request_id][index] = data;
  }

  void load_preprocessing_data(const std::string &request_id, uint64_t index,
                               ecdsa_signing_data &data) const override {
    std::shared_lock lock(_mutex);
    auto it = _signing_data.find(request_id);
    if (it == _signing_data.end())
      throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
    auto index_it = it->second.find(index);
    if (index_it == it->second.end())
      throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
    data = index_it->second;
  }

  void delete_preprocessing_data(const std::string &request_id) override {
    std::unique_lock lock(_mutex);
    _metadata.erase(request_id);
    _signing_data.erase(request_id);
  }

  void create_preprocessed_data(const std::string &key_id,
                                uint64_t size) override {
    std::unique_lock lock(_mutex);
    auto it = _preprocessed_data.find(key_id);
    if (it != _preprocessed_data.end()) {
      if (it->second.size() != size)
        throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
    } else
      _preprocessed_data.emplace(
          key_id,
          std::move(std::vector<cmp_signature_preprocessed_data>(size)));
  }

  void store_preprocessed_data(
      const std::string &key_id, uint64_t index,
      const cmp_signature_preprocessed_data &data) override {
    std::unique_lock lock(_mutex);
    auto it = _preprocessed_data.find(key_id);
    if (it == _preprocessed_data.end())
      throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
    if (index >= it->second.size())
      throw cosigner_exception(cosigner_exception::INVALID_PRESIGNING_INDEX);
    it->second[index] = data;
  }

  void load_preprocessed_data(const std::string &key_id, uint64_t index,
                              cmp_signature_preprocessed_data &data) override {
    std::unique_lock lock(_mutex);
    auto it = _preprocessed_data.find(key_id);
    if (it == _preprocessed_data.end())
      throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
    if (index >= it->second.size() ||
        memcmp(it->second[index].k.data, ZERO,
               sizeof(cmp_signature_preprocessed_data)) == 0)
      throw cosigner_exception(cosigner_exception::INVALID_PRESIGNING_INDEX);
    data = it->second[index];
    memset(it->second[index].k.data, 0,
           sizeof(cmp_signature_preprocessed_data));
  }

  void delete_preprocessed_data(const std::string &key_id) override {
    std::unique_lock lock(_mutex);
    _preprocessed_data.erase(key_id);
  }

  mutable std::shared_mutex _mutex;
  std::map<std::string, preprocessing_metadata> _metadata;
  std::map<std::string, std::map<uint64_t, ecdsa_signing_data>> _signing_data;
  std::map<std::string, std::vector<cmp_signature_preprocessed_data>>
      _preprocessed_data;
  friend class key_refresh_persistency;
};

class key_refresh_persistency
    : public cmp_offline_refresh_service::offline_refresh_key_persistency {
public:
  key_refresh_persistency(
      preprocessing_persistency &preproc_persistency,
      cmp_setup_service::setup_key_persistency &setup_persistency)
      : _preprocessing_persistency(preproc_persistency),
        _setup_persistency(setup_persistency) {}

private:
  void load_refresh_key_seeds(
      const std::string &request_id,
      std::map<uint64_t, byte_vector_t> &player_id_to_seed) const override {
    std::lock_guard<std::mutex> lock(_mutex);
    auto it = _seeds.find(request_id);
    if (it == _seeds.end())
      throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
    player_id_to_seed = it->second;
  }

  void store_refresh_key_seeds(
      const std::string &request_id,
      const std::map<uint64_t, byte_vector_t> &player_id_to_seed) override {
    std::lock_guard<std::mutex> lock(_mutex);
    if (_seeds.find(request_id) != _seeds.end())
      throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
    _seeds[request_id] = player_id_to_seed;
  }

  void transform_preprocessed_data_and_store_temporary(
      const std::string &key_id, const std::string &request_id,
      const cmp_offline_refresh_service::preprocessed_data_handler &fn)
      override {
    std::unique_lock lock(_preprocessing_persistency._mutex);
    auto it = _preprocessing_persistency._preprocessed_data.find(key_id);
    if (it == _preprocessing_persistency._preprocessed_data.end())
      throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
    const auto &preprocessed_data = it->second;
    it = _temp_preprocessed_data.find(key_id);
    if (it != _temp_preprocessed_data.end())
      throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);

    std::vector<cmp_signature_preprocessed_data> temp(preprocessed_data);
    for (size_t i = 0; i < temp.size(); i++) {
      if (memcmp(temp[i].k.data, ZERO,
                 sizeof(cmp_signature_preprocessed_data)) != 0) {
        fn(i, temp[i]);
      }
    }
    std::lock_guard<std::mutex> lg(_mutex);
    _temp_preprocessed_data[key_id] = temp;
  }

  void commit(const std::string &key_id,
              const std::string &request_id) override {
    std::unique_lock lock(_preprocessing_persistency._mutex);
    std::lock_guard<std::mutex> lg(_mutex);
    auto it = _temp_keys.find(request_id);
    if (it == _temp_keys.end())
      throw cosigner_exception(cosigner_exception::BAD_KEY);
    _preprocessing_persistency._preprocessed_data[key_id] =
        _temp_preprocessed_data[key_id];
    _temp_preprocessed_data.erase(key_id);
    _setup_persistency.store_key(key_id, it->second.second, it->second.first);
    _temp_keys.erase(request_id);
  }

  void delete_refresh_key_seeds(const std::string &request_id) override {
    std::lock_guard<std::mutex> lock(_mutex);
    _temp_preprocessed_data.erase(request_id);
  }

  void delete_temporary_key(const std::string &key_id) override {
    std::lock_guard<std::mutex> lock(_mutex);
    _temp_keys.erase(key_id);
  }

  void store_temporary_key(const std::string &key_id,
                           cosigner_sign_algorithm algorithm,
                           const elliptic_curve_scalar &private_key) override {
    std::lock_guard<std::mutex> lock(_mutex);
    if (_temp_keys.find(key_id) != _temp_keys.end())
      throw cosigner_exception(cosigner_exception::BAD_KEY);
    auto &val = _temp_keys[key_id];
    memcpy(val.first, private_key.data, sizeof(elliptic_curve256_scalar_t));
    val.second = algorithm;
  }

  mutable std::mutex _mutex;
  preprocessing_persistency &_preprocessing_persistency;
  cmp_setup_service::setup_key_persistency &_setup_persistency;
  std::map<std::string, std::map<uint64_t, byte_vector_t>> _seeds;
  std::map<std::string, std::vector<cmp_signature_preprocessed_data>>
      _temp_preprocessed_data;
  std::map<std::string,
           std::pair<elliptic_curve256_scalar_t, cosigner_sign_algorithm>>
      _temp_keys;
};

struct offline_siging_info {
  offline_siging_info(uint64_t id, const cmp_key_persistency &key_persistency)
      : platform_service(id),
        signing_service(platform_service, key_persistency, persistency) {}
  sign_platform platform_service;
  preprocessing_persistency persistency;
  cmp_ecdsa_offline_signing_service signing_service;
};

static void ecdsa_preprocess(
    std::map<uint64_t, std::unique_ptr<offline_siging_info>> &services,
    const std::string &keyid, uint32_t start, uint32_t count, uint32_t total) {
  uuid_t uid;
  char request[37] = {0};
  uuid_generate_random(uid);
  uuid_unparse(uid, request);
  std::cout << "request id = " << request << std::endl;

  std::set<uint64_t> players_ids;
  for (auto i = services.begin(); i != services.end(); ++i)
    players_ids.insert(i->first);

  std::map<uint64_t, std::vector<cmp_mta_request>> mta_requests;
  for (auto i = services.begin(); i != services.end(); ++i) {
    auto &mta_request = mta_requests[i->first];
    i->second->signing_service.start_ecdsa_signature_preprocessing(
        TENANT_ID, keyid, request, start, count, total, players_ids,
        mta_request);
  }

  std::map<uint64_t, cmp_mta_responses> mta_responses;
  for (auto i = services.begin(); i != services.end(); ++i) {
    auto &response = mta_responses[i->first];
    i->second->signing_service.offline_mta_response(request, mta_requests,
                                                    response);
  }
  mta_requests.clear();

  std::map<uint64_t, std::vector<cmp_mta_deltas>> deltas;
  for (auto i = services.begin(); i != services.end(); ++i) {
    auto &delta = deltas[i->first];
    i->second->signing_service.offline_mta_verify(request, mta_responses,
                                                  delta);
  }
  mta_responses.clear();

  std::map<uint64_t, std::vector<elliptic_curve_scalar>> sis;
  for (auto i = services.begin(); i != services.end(); ++i) {
    auto &si = sis[i->first];
    std::string key_id;
    i->second->signing_service.store_presigning_data(request, deltas, key_id);
    if (key_id != keyid)
      throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
  }
}

static void ecdsa_sign(
    std::map<uint64_t, std::unique_ptr<offline_siging_info>> &services,
    cosigner_sign_algorithm type, const std::string &keyid,
    uint32_t start_index, uint32_t count,
    const elliptic_curve256_point_t &pubkey, const byte_vector_t &chaincode,
    const std::vector<std::vector<uint32_t>> &paths, bool positive_r = false) {
  uuid_t uid;
  char txid[37] = {0};
  uuid_generate_random(uid);
  uuid_unparse(uid, txid);
  // std::cout << "txid id = " << txid << std::endl;

  std::set<uint64_t> players_ids;
  std::set<std::string> players_str;
  for (auto i = services.begin(); i != services.end(); ++i) {
    players_ids.insert(i->first);
    players_str.insert(std::to_string(i->first));
    i->second->platform_service.set_positive_r(positive_r);
  }

  if (chaincode.size() != sizeof(HDChaincode)) {
    throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
  }
  signing_data data;
  memcpy(data.chaincode, chaincode.data(), sizeof(HDChaincode));
  for (int i = 0; i < count; i++) {
    printf("\n------------Generating block------------\n\n");
    signing_block_data block;
    block.data.insert(block.data.begin(), 32, '0');
    printf("block data: %s\n", HexStr(block.data).c_str());
    block.path = paths[i];
    data.blocks.push_back(block);
  }

  std::map<uint64_t, std::vector<recoverable_signature>> partial_sigs;
  for (auto i = services.begin(); i != services.end(); ++i) {
    auto &sigs = partial_sigs[i->first];
    std::string key_id;
    i->second->signing_service.ecdsa_sign(keyid, txid, data, "", players_str,
                                          players_ids, start_index, sigs);
  }

  std::vector<recoverable_signature> sigs;
  for (auto i = services.begin(); i != services.end(); ++i) {
    i->second->signing_service.ecdsa_offline_signature(keyid, txid, type,
                                                       partial_sigs, sigs);
  }

  std::unique_ptr<elliptic_curve256_algebra_ctx_t,
                  void (*)(elliptic_curve256_algebra_ctx_t *)>
      algebra(create_algebra(type), elliptic_curve256_algebra_ctx_free);

  for (size_t i = 0; i < count; i++) {
    elliptic_curve256_scalar_t msg;
    if (data.blocks[i].data.size() != sizeof(elliptic_curve256_scalar_t)) {
      throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }
    memcpy(msg, data.blocks[i].data.data(), sizeof(elliptic_curve256_scalar_t));
    printf("\n------------Final obtained signature------------\n\n");
    std::cout << "sig r: "
              << HexStr(sigs[i].r,
                        &sigs[i].r[sizeof(elliptic_curve256_scalar_t)])
              << std::endl;
    std::cout << "sig s: "
              << HexStr(sigs[i].s,
                        &sigs[i].s[sizeof(elliptic_curve256_scalar_t)])
              << std::endl;

    PubKey derived_key;
    derive_public_key_generic(algebra.get(), derived_key, pubkey,
                              data.chaincode, paths[i].data(), paths[i].size());
    std::cout << "Derived public key: "
              << HexStr(derived_key, &derived_key[sizeof(PubKey)]) << std::endl;

    printf("\n------------Verifying signature------------\n\n");
    printf("data: %s\n",
           HexStr(msg, &msg[sizeof(elliptic_curve256_scalar_t)]).c_str());
    BN_CTX *bn_ctx = BN_CTX_new();
    BIGNUM *m = BN_CTX_get(bn_ctx);
    BN_bin2bn(msg, sizeof(elliptic_curve256_scalar_t), m);
    printf("m: %s\n", BN_bn2hex(m));
    int status = GFp_curve_algebra_verify_signature(
        (GFp_curve_algebra_ctx_t *)algebra->ctx, &derived_key, &msg, &sigs[i].r,
        &sigs[i].s);
    if (status == 0)
      printf("\n------------Signature verified-------------\n");
  }
}

struct key_refresh_info {
  key_refresh_info(uint64_t id,
                   cmp_setup_service::setup_key_persistency &persistency,
                   preprocessing_persistency &preproc_persistency)
      : platform_service(id),
        refresh_persistency(preproc_persistency, persistency),
        service(platform_service, persistency, refresh_persistency) {}
  sign_platform platform_service;
  key_refresh_persistency refresh_persistency;
  cmp_offline_refresh_service service;
};

static void
key_refresh(std::map<uint64_t, std::unique_ptr<key_refresh_info>> &services,
            const std::string &keyid, const elliptic_curve256_point_t &pubkey) {
  uuid_t uid;
  char request[37] = {0};
  uuid_generate_random(uid);
  uuid_unparse(uid, request);
  std::cout << "request id = " << request << std::endl;

  std::set<uint64_t> players_ids;
  for (auto i = services.begin(); i != services.end(); ++i)
    players_ids.insert(i->first);

  std::map<uint64_t, std::map<uint64_t, byte_vector_t>> encrypted_seeds;
  for (auto i = services.begin(); i != services.end(); ++i) {
    auto &encrypted_seed = encrypted_seeds[i->first];
    i->second->service.refresh_key_request(TENANT_ID, keyid, request,
                                           players_ids, encrypted_seed);
  }

  std::string public_key;
  for (auto i = services.begin(); i != services.end(); ++i) {
    i->second->service.refresh_key(keyid, request, encrypted_seeds, public_key);
    if (memcmp(pubkey, public_key.data(), public_key.size()) != 0) {
      throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
    }
  }
  encrypted_seeds.clear();

  for (auto i = services.begin(); i != services.end(); ++i) {
    i->second->service.refresh_key_fast_ack(TENANT_ID, keyid, request);
  }
}

const uint32_t BLOCK_SIZE = 10;
struct preprocess_thread_data {
  std::map<uint64_t, std::unique_ptr<offline_siging_info>> *services;
  const char *keyid;
  uint32_t index;
  uint32_t total_count;
};

static void *preprocess_thread(void *arg) {
  preprocess_thread_data *param = (preprocess_thread_data *)arg;
  ecdsa_preprocess(*param->services, param->keyid, param->index * BLOCK_SIZE,
                   BLOCK_SIZE, param->total_count);
  return NULL;
}

class platform : public platform_service {
public:
  platform(uint64_t id) : _id(id) {}

private:
  void gen_random(size_t len, uint8_t *random_data) const {
    RAND_bytes(random_data, len);
  }

  const std::string get_current_tenantid() const { return TENANT_ID; }
  uint64_t get_id_from_keyid(const std::string &key_id) const { return _id; }
  void derive_initial_share(const share_derivation_args &derive_from,
                            cosigner_sign_algorithm algorithm,
                            elliptic_curve256_scalar_t *key) const {
    assert(0);
  }
  byte_vector_t encrypt_for_player(uint64_t id,
                                   const byte_vector_t &data) const {
    return data;
  }
  byte_vector_t decrypt_message(const byte_vector_t &encrypted_data) const {
    return encrypted_data;
  }
  bool backup_key(const std::string &key_id, cosigner_sign_algorithm algorithm,
                  const elliptic_curve256_scalar_t &private_key,
                  const cmp_key_metadata &metadata, const auxiliary_keys &aux) {
    return true;
  }
  void start_signing(const std::string &key_id, const std::string &txid,
                     const signing_data &data, const std::string &metadata_json,
                     const std::set<std::string> &players) {}
  void fill_signing_info_from_metadata(const std::string &metadata,
                                       std::vector<uint32_t> &flags) const {
    assert(0);
  }
  bool is_client_id(uint64_t player_id) const override { return false; }

  uint64_t _id;
};

struct setup_info {
  setup_info(uint64_t id, setup_persistency &persistency)
      : platform_service(id), setup_service(platform_service, persistency) {}
  platform platform_service;
  cmp_setup_service setup_service;
};

void create_secret(players_setup_info &players, cosigner_sign_algorithm type,
                   const std::string &keyid,
                   elliptic_curve256_point_t &pubkey) {
  std::unique_ptr<elliptic_curve256_algebra_ctx_t,
                  void (*)(elliptic_curve256_algebra_ctx_t *)>
      algebra(create_algebra(type), elliptic_curve256_algebra_ctx_free);
  const size_t PUBKEY_SIZE = algebra->point_size(algebra.get());

  std::cout << "keyid = " << keyid << std::endl;
  std::vector<uint64_t> players_ids;

  std::map<uint64_t, std::unique_ptr<setup_info>> services;
  for (auto i = players.begin(); i != players.end(); ++i) {
    services.emplace(i->first,
                     std::make_unique<setup_info>(i->first, i->second));
    players_ids.push_back(i->first);
  }

  std::map<uint64_t, commitment> commitments;
  for (auto i = services.begin(); i != services.end(); ++i) {
    commitment &commitment = commitments[i->first];
    i->second->setup_service.generate_setup_commitments(
        keyid, TENANT_ID, type, players_ids, players_ids.size(), 0, {},
        commitment);
  }

  std::map<uint64_t, setup_decommitment> decommitments;
  for (auto i = services.begin(); i != services.end(); ++i) {
    setup_decommitment &decommitment = decommitments[i->first];
    i->second->setup_service.store_setup_commitments(keyid, commitments,
                                                     decommitment);
  }
  commitments.clear();

  std::map<uint64_t, setup_zk_proofs> proofs;
  for (auto i = services.begin(); i != services.end(); ++i) {
    setup_zk_proofs &proof = proofs[i->first];
    i->second->setup_service.generate_setup_proofs(keyid, decommitments, proof);
  }
  decommitments.clear();

  std::map<uint64_t, std::map<uint64_t, byte_vector_t>>
      paillier_large_factor_proofs;
  for (auto i = services.begin(); i != services.end(); ++i) {
    auto &proof = paillier_large_factor_proofs[i->first];

    i->second->setup_service.verify_setup_proofs(keyid, proofs, proof);
  }
  proofs.clear();

  bool first = true;
  for (auto i = services.begin(); i != services.end(); ++i) {
    std::string public_key;
    cosigner_sign_algorithm algorithm;
    i->second->setup_service.create_secret(keyid, paillier_large_factor_proofs,
                                           public_key, algorithm);
    if (algorithm != type) {
      throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
    }
    if (public_key.size() != PUBKEY_SIZE) {
      throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
    }
    if (first) {
      first = false;
      memcpy(pubkey, public_key.data(), PUBKEY_SIZE);
    } else {
      if (memcmp(pubkey, public_key.data(), PUBKEY_SIZE) != 0) {
        throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
      }
    }
  }
  paillier_large_factor_proofs.clear();

  std::cout << "public key: " << HexStr(pubkey, &pubkey[PUBKEY_SIZE])
            << std::endl;
  for (auto i = players.begin(); i != players.end(); ++i) {
    std::cout << "player " << i->first
              << " share: " << i->second.dump_key(keyid) << std::endl;
  }
}

void add_user(players_setup_info &old_players, players_setup_info &new_players,
              cosigner_sign_algorithm type, const std::string &old_keyid,
              const std::string &new_keyid,
              const elliptic_curve256_point_t &pubkey) {
  std::unique_ptr<elliptic_curve256_algebra_ctx_t,
                  void (*)(elliptic_curve256_algebra_ctx_t *)>
      algebra(create_algebra(type), elliptic_curve256_algebra_ctx_free);
  const size_t PUBKEY_SIZE = algebra->point_size(algebra.get());

  std::cout << "new keyid = " << new_keyid << std::endl;
  std::vector<uint64_t> players_ids;
  std::vector<uint64_t> old_players_ids;

  std::map<uint64_t, std::unique_ptr<setup_info>> services;
  for (auto i = old_players.begin(); i != old_players.end(); ++i) {
    services.emplace(i->first,
                     std::make_unique<setup_info>(i->first, i->second));
    old_players_ids.push_back(i->first);
  }
  for (auto i = new_players.begin(); i != new_players.end(); ++i)
    players_ids.push_back(i->first);

  std::map<uint64_t, add_user_data> add_user_request_data;
  for (auto i = services.begin(); i != services.end(); ++i) {
    add_user_data &data = add_user_request_data[i->first];
    i->second->setup_service.add_user_request(
        old_keyid, type, new_keyid, players_ids, players_ids.size(), data);
  }

  services.clear();
  std::map<uint64_t, commitment> commitments;
  for (auto i = new_players.begin(); i != new_players.end(); ++i) {
    auto info = std::make_unique<setup_info>(i->first, i->second);
    commitment &commitment = commitments[i->first];
    info->setup_service.add_user(TENANT_ID, new_keyid, type, players_ids.size(),
                                 add_user_request_data, 0, commitment);
    services.emplace(i->first, std::move(info));
  }

  std::map<uint64_t, setup_decommitment> decommitments;
  for (auto i = services.begin(); i != services.end(); ++i) {
    setup_decommitment &decommitment = decommitments[i->first];
    i->second->setup_service.store_setup_commitments(new_keyid, commitments,
                                                     decommitment);
  }
  commitments.clear();

  std::map<uint64_t, setup_zk_proofs> proofs;
  for (auto i = services.begin(); i != services.end(); ++i) {
    setup_zk_proofs &proof = proofs[i->first];
    i->second->setup_service.generate_setup_proofs(new_keyid, decommitments,
                                                   proof);
  }
  decommitments.clear();

  std::map<uint64_t, std::map<uint64_t, byte_vector_t>>
      paillier_large_factor_proofs;
  for (auto i = services.begin(); i != services.end(); ++i) {
    auto &proof = paillier_large_factor_proofs[i->first];

    i->second->setup_service.verify_setup_proofs(new_keyid, proofs, proof);
  }
  proofs.clear();

  for (auto i = services.begin(); i != services.end(); ++i) {
    std::string public_key;
    cosigner_sign_algorithm algorithm;
    i->second->setup_service.create_secret(
        new_keyid, paillier_large_factor_proofs, public_key, algorithm);
    if (algorithm != type) {
      throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
    }
    if (public_key.size() != PUBKEY_SIZE) {
      throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
    }
    if (memcmp(pubkey, public_key.data(), PUBKEY_SIZE) != 0) {
      throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
    }
  }
  paillier_large_factor_proofs.clear();

  for (auto i = new_players.begin(); i != new_players.end(); ++i) {
    std::cout << "player " << i->first
              << " share: " << i->second.dump_key(new_keyid) << std::endl;
  }
}

int main(int argc, char **argv) {
  int num_players;
  printf("Enter number of players: ");
  scanf("%d", &num_players);
  byte_vector_t chaincode(32, '\0');
  std::vector<uint32_t> path = {44, 0, 0, 0, 0};
  char keyid[37] = {0};
  elliptic_curve256_point_t pubkey;
  players_setup_info players;

  std::cout << "------------Generating keyid and shares------------\n"
            << std::endl;
  uuid_t uid;
  uuid_generate_random(uid);
  uuid_unparse(uid, keyid);
  players.clear();
  for (int i = 0; i < num_players; i++)
    players[i];

  create_secret(players, ECDSA_SECP256R1, keyid, pubkey);

  std::map<uint64_t, std::unique_ptr<offline_siging_info>> services;
  for (auto i = players.begin(); i != players.end(); ++i) {
    auto info = std::make_unique<offline_siging_info>(i->first, i->second);
    services.emplace(i->first, move(info));
  }

  std::cout << "\n------------Preprocessing signatures------------\n"
            << std::endl;
  ecdsa_preprocess(services, keyid, 0, BLOCK_SIZE, BLOCK_SIZE);

  ecdsa_sign(services, ECDSA_SECP256R1, keyid, 0, 1, pubkey, chaincode, {path});
}
