#pragma once
#include <cctype>
#include <string>
#include <vector>

namespace cipher {
size_t CountOf(const std::string &str, char sym) {
  size_t count = 0;
  for (size_t i = 0; i < str.size(); ++i) {
    if (str[i] == sym) ++count;
  }
  return count;
}

void StatisticsAlphabet(const std::string &str,
                        std::vector<size_t> &out_statistic) {
  std::string lower_str = str;
  for (size_t i = 0; i < str.size(); ++i) {
    lower_str[i] = std::tolower(lower_str[i]);
  }
  out_statistic.clear();
  out_statistic.resize(26, 0);
  for (size_t i = 0; i < lower_str.size(); ++i) {
    if (out_statistic[lower_str[i] - 'a'] == 0) {
      out_statistic[lower_str[i] - 'a'] = CountOf(lower_str, lower_str[i]);
    }
  }
}

void Find3Max(const std::vector<size_t> &statistics, size_t &max_index,
              size_t &second_max_index, size_t &third_max_index) {
  std::vector<size_t> indexes(statistics.size());
  for (size_t i = 0; i < indexes.size(); ++i) {
    indexes[i] = i;
  }
  for (size_t i = 0; i < statistics.size(); ++i) {
    for (size_t j = 0; j < statistics.size() - i - 1; ++j) {
      if (statistics[indexes[j]] < statistics[indexes[j + 1]]) {
        std::swap(indexes[j], indexes[j + 1]);
      }
    }
  }
  max_index = indexes[0];
  second_max_index = indexes[1];
  third_max_index = indexes[2];
}

char IndexToSymbol(size_t index) { return 'a' + index; }

std::string Decrypt(const std::string &cipher_text, size_t key) {
  std::string decrypted_text = cipher_text;
  for (size_t i = 0; i < decrypted_text.size(); ++i) {
    decrypted_text[i] = std::tolower(cipher_text[i]);
  }
  for (auto &ch : decrypted_text) {
    ch = 'a' + (26 + ch - 'a' - key) % 26;
  }
  return decrypted_text;
}

void GenerateCandidates(const std::string &cipher_text,
                        const std::vector<size_t> &keys,
                        std::vector<std::string> &candidates) {
  candidates.resize(3);
  candidates[0] = Decrypt(cipher_text, keys[0]);
  candidates[1] = Decrypt(cipher_text, keys[1]);
  candidates[2] = Decrypt(cipher_text, keys[2]);
}
}  // namespace cipher
