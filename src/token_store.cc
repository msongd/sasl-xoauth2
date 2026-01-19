// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "token_store.h"

#include <errno.h>
#include <inttypes.h>
#include <json/json.h>
#include <sasl/sasl.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <fstream>
#include <sstream>

#include "config.h"
#include "http.h"
#include "log.h"
#include <curl/curl.h>

namespace sasl_xoauth2 {

namespace {

constexpr int kMaxRefreshAttempts = 2;

std::string GetTempSuffix() {
  timeval t = {};
  gettimeofday(&t, nullptr);
  const uint64_t time_ms = t.tv_sec * 1000 + t.tv_usec / 1000;

  char buf[128];
  snprintf(buf, sizeof(buf), "%d.%" PRIu64, getpid(), time_ms);

  return std::string(buf);
}

void ReadOverride(const Json::Value &root, const std::string &key,
                  std::optional<std::string> *output) {
  if (root.isMember(key)) {
    *output = root[key].asString();
  }
}

void WriteOverride(const std::string &key,
                   const std::optional<std::string> &value,
                   Json::Value *output) {
  if (value) {
    (*output)[key] = *value;
  }
}

}  // namespace

/* static */ std::unique_ptr<TokenStore> TokenStore::Create(
    Log *log, const std::string &path, bool enable_updates) {
  std::unique_ptr<TokenStore> store(new TokenStore(log, path, enable_updates));
  if (store->Read() != SASL_OK) return {};
  return store;
}

int TokenStore::GetAccessToken(std::string *token) {
  const int refresh_window =
      override_refresh_window_.value_or(Config::Get()->refresh_window());

  if ((time(nullptr) + refresh_window) >= expiry_) {
    log_->Write("TokenStore::GetAccessToken: token expired. refreshing.");
    int err = Refresh();
    if (err != SASL_OK) return err;
  }

  *token = access_;
  return SASL_OK;
}

int TokenStore::Refresh() {
  if (refresh_attempts_ > kMaxRefreshAttempts) {
    log_->Write("TokenStore::Refresh: exceeded maximum attempts");
    return SASL_BADPROT;
  }
  refresh_attempts_++;
  log_->Write("TokenStore::Refresh: attempt %d", refresh_attempts_);

  const std::string client_id =
      override_client_id_.value_or(Config::Get()->client_id());
  const std::string client_secret =
      override_client_secret_.value_or(Config::Get()->client_secret());
  const std::string token_endpoint =
      override_token_endpoint_.value_or(Config::Get()->token_endpoint());

  const std::string proxy = override_proxy_.value_or(Config::Get()->proxy());

  const std::string ca_bundle_file =
      override_ca_bundle_file_.value_or(Config::Get()->ca_bundle_file());

  const std::string ca_certs_dir =
      override_ca_certs_dir_.value_or(Config::Get()->ca_certs_dir());

  const std::string request =
      std::string("client_id=") + client_id +
      "&client_secret=" + client_secret +
      "&grant_type=refresh_token&refresh_token=" + refresh_;
  std::string response;
  long response_code = 0;
  log_->Write("TokenStore::Refresh: token_endpoint: %s",
              token_endpoint.c_str());
  log_->Write("TokenStore::Refresh: request: %s", request.c_str());

  std::string http_error;
  int err = HttpPost({.url = token_endpoint,
                      .data = request,
                      .proxy = proxy,
                      .ca_bundle_file = ca_bundle_file,
                      .ca_certs_dir = ca_certs_dir,
                      .response_code = &response_code,
                      .response = &response,
                      .error = &http_error});
  if (err != SASL_OK) {
    log_->Write("TokenStore::Refresh: http error: %s", http_error.c_str());
    return err;
  }

  log_->Write("TokenStore::Refresh: code=%d, response=%s", response_code,
              response.c_str());

  if (response_code != 200) {
    log_->Write("TokenStore::Refresh: request failed");
    return SASL_BADPROT;
  }

  try {
    std::stringstream ss(response);
    Json::Value root;
    ss >> root;
    if (!root.isMember("access_token") || !root.isMember("expires_in")) {
      log_->Write("TokenStore::Refresh: response doesn't contain access_token");
      return SASL_BADPROT;
    }
    access_ = root["access_token"].asString();
    int expiry_sec = stoi(root["expires_in"].asString());
    if (expiry_sec <= 0) {
      log_->Write("TokenStore::Refresh: invalid expiry");
      return SASL_BADPROT;
    }
    if (root.isMember("refresh_token")) {
      const std::string refresh_token = root["refresh_token"].asString();
      if (refresh_token != refresh_) {
        log_->Write(
            "TokenStore::Refresh: response includes updated refresh token");
        refresh_ = refresh_token;
      }
    }
    expiry_ = time(nullptr) + expiry_sec;
  } catch (const std::exception &e) {
    log_->Write("TokenStore::Refresh: exception=%s", e.what());
    return SASL_FAIL;
  }

  return Write();
}

// Helper: Curl Write Callback to capture response into a string
static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

TokenStore::TokenStore(Log *log, const std::string &path, bool enable_updates)
    : log_(log), path_(path), enable_updates_(enable_updates) {
        // Detect protocol
            if (path_.find("http://") == 0 || path_.find("https://") == 0) {
                is_remote_backend_ = true;
            } else {
                is_remote_backend_ = false;
            }
    }

int TokenStore::Read(std::string *access_token, long *expiry) {
    if (is_remote_backend_) return ReadFromUrl(access_token, expiry);
    return ReadFromFile(access_token, expiry);
}

int TokenStore::Write(const std::string &access_token, long expiry, const std::string &refresh_token) {
    if (is_remote_backend_) return WriteToUrl(access_token, expiry, refresh_token);
    return WriteToFile(access_token, expiry, refresh_token);
}

int TokenStore::ReadFromFile(std::string *access_token, long *expiry) {
  try {
    log_->Write("TokenStore::Read: file=%s", path_.c_str());

    std::ifstream file(path_);
    if (!file.good()) {
      log_->Write("TokenStore::Read: failed to open file %s: %s", path_.c_str(),
                  strerror(errno));
      return SASL_FAIL;
    }

    Json::Value root;
    file >> root;
    if (!root.isMember("refresh_token")) {
      log_->Write("TokenStore::Read: missing refresh_token");
      return SASL_FAIL;
    }

    ReadOverride(root, "client_id", &override_client_id_);
    ReadOverride(root, "client_secret", &override_client_secret_);
    ReadOverride(root, "token_endpoint", &override_token_endpoint_);
    ReadOverride(root, "proxy", &override_proxy_);
    ReadOverride(root, "ca_bundle_file", &override_ca_bundle_file_);
    ReadOverride(root, "ca_certs_dir", &override_ca_certs_dir_);

    if (root.isMember("refresh_window"))
      override_refresh_window_ = stoi(root["refresh_window"].asString());

    refresh_ = root["refresh_token"].asString();
    if (root.isMember("access_token"))
      access_ = root["access_token"].asString();
    if (root.isMember("expiry")) expiry_ = stoi(root["expiry"].asString());

    ReadOverride(root, "user", &user_);

    log_->Write("TokenStore::Read: refresh=%s, access=%s, user=%s",
                refresh_.c_str(), access_.c_str(), user_.value_or("").c_str());
    return SASL_OK;

  } catch (const std::exception &e) {
    log_->Write("TokenStore::Read: exception=%s", e.what());
    return SASL_FAIL;
  }
}

int TokenStore::WriteToFile(const std::string &access_token, long expiry, const std::string &refresh_token) {
  const std::string new_path = path_ + "." + GetTempSuffix();

  if (!enable_updates_) {
    log_->Write("TokenStore::Write: skipping write to %s", new_path.c_str());
    return SASL_OK;
  }

  try {
    Json::Value root;
    root["refresh_token"] = refresh_;
    root["access_token"] = access_;
    root["expiry"] = std::to_string(expiry_);

    WriteOverride("user", user_, &root);

    WriteOverride("client_id", override_client_id_, &root);
    WriteOverride("client_secret", override_client_secret_, &root);
    WriteOverride("token_endpoint", override_token_endpoint_, &root);
    WriteOverride("proxy", override_proxy_, &root);
    WriteOverride("ca_bundle_file", override_ca_bundle_file_, &root);
    WriteOverride("ca_certs_dir", override_ca_certs_dir_, &root);

    if (override_refresh_window_) {
      root["refresh_window"] = std::to_string(*override_refresh_window_);
    }

    std::ofstream file(new_path);
    if (!file.good()) {
      log_->Write("TokenStore::Write: failed to open file %s for writing: %s",
                  new_path.c_str(), strerror(errno));
      return SASL_FAIL;
    }
    file << root;

  } catch (const std::exception &e) {
    log_->Write("TokenStore::Write: exception=%s", e.what());
    return SASL_FAIL;
  }

  if (rename(new_path.c_str(), path_.c_str()) != 0) {
    log_->Write("TokenStore::Write: rename failed with %s", strerror(errno));
    return SASL_FAIL;
  }

  return 0;
}
// ==========================================
// URL BACKEND (New Feature)
// ==========================================
int TokenStore::ReadFromUrl(std::string *access_token, long *expiry) {
    CURL *curl;
    CURLcode res;
    std::string readBuffer;
    bool success = false;
    log_->Write("TokenStore::ReadFromUrl: file=%s", path_.c_str());
    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, path_.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L); // 10s timeout

        // Handle redirects if necessary
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

        res = curl_easy_perform(curl);

        if (res == CURLE_OK) {
            Json::Value root;
            Json::Reader reader;

            // Parse JSON from the network response string
            if (reader.parse(readBuffer, root)) {
                if (root.isMember("access_token") && root.isMember("expiry")) {
                    *access_token = root["access_token"].asString();
                    *expiry = root["expiry"].asInt64();
                    success = true;
                } else {
                    log_->Write("TokenStore::ReadFromUrl: JSON missing required fields.");
                    //std::cerr << "sasl-xoauth2: JSON missing required fields." << std::endl;
                }
            } else {
                log_->Write("TokenStore::ReadFromUrl: Failed to parse JSON response.");
                //std::cerr << "sasl-xoauth2: Failed to parse JSON response." << std::endl;
            }
        } else {
            log_->Write("TokenStore::ReadFromUrl: GET request failed: %s", curl_easy_strerror(res));
            //std::cerr << "sasl-xoauth2: GET request failed: " << curl_easy_strerror(res) << std::endl;
        }
        curl_easy_cleanup(curl);
    }
    return success;
}

int TokenStore::WriteToUrl(const std::string &access_token, long expiry, const std::string &refresh_token) {
    CURL *curl;
    CURLcode res;
    bool success = false;

    // Construct JSON object
    Json::Value root;
    root["access_token"] = access_token;
    root["expiry"] = (Json::Value::Int64)expiry;
    root["refresh_token"] = refresh_token;

    // Serialize to string (FastWriter creates compact JSON)
    Json::FastWriter writer;
    std::string json_payload = writer.write(root);
    log_->Write("TokenStore::WriteToUrl: file=%s", path_.c_str());
    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, path_.c_str());

        // Set Headers
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        // POST Payload
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_payload.c_str());
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

        // Capture response (optional, but good for debugging errors)
        std::string responseBuffer;
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseBuffer);

        res = curl_easy_perform(curl);

        if (res == CURLE_OK) {
            long http_code = 0;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
            // Accept 200 OK or 201 Created
            if (http_code >= 200 && http_code < 300) {
                success = true;
            } else {
                std::cerr << "sasl-xoauth2: POST failed with HTTP " << http_code << std::endl;
            }
        } else {
            std::cerr << "sasl-xoauth2: POST request failed: " << curl_easy_strerror(res) << std::endl;
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }
    return success;
}
}  // namespace sasl_xoauth2
