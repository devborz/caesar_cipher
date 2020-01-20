#include <iostream>
#include <string>
#include <vector>
#include "caesar_cipher.hpp"

using namespace cipher;

int main(/*int argc, char **argv*/) {
  std::string cipher_text = "avilvyuvaavilaohapzaolxblzapvu";

  std::vector<size_t> keys;
  std::vector<std::string> candidates;

  std::vector<size_t> statistics;
  StatisticsAlphabet(cipher_text, statistics);
  size_t max_index;
  size_t second_max_index;
  size_t third_max_index;
  Find3Max(statistics, max_index, second_max_index, third_max_index);

  keys.resize(3);
  candidates.resize(3);

  keys[0] = (26 + IndexToSymbol(max_index) - 'e') % 26;
  keys[1] = (26 + IndexToSymbol(second_max_index) - 'e') % 26;
  keys[2] = (26 + IndexToSymbol(third_max_index) - 'e') % 26;

  GenerateCandidates(cipher_text, keys, candidates);

  for (size_t i = 0; i < candidates.size(); ++i) {
    std::cout << "key №" << i << " = " << keys[i]
              << " decrypted text = " << candidates[i] << std::endl;
  }

  return 0;
}
