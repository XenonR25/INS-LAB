#include <iostream>
#include <string>
#include <unordered_map>
#include <cctype>

class SubstitutionCipher {
private:
    std::unordered_map<char, char> key;

public:
    SubstitutionCipher() {
        // ↓ Mapping derived from frequency and word pattern analysis
        key['a'] = 'i';   // "af" → "in"
        key['b'] = 'c';   // rare, fallen from contextual fit
        key['c'] = 't';   // "cepc" → "that"
        key['d'] = 'o';   // "du" → "of"
        key['e'] = 'h';   // "cei" → "the"
        key['f'] = 'n';   // "af" → "in", "pfg" → "and"
        key['g'] = 'd';   // "pfg" → "and"
        key['h'] = 'b';   // contextual consonant
        key['i'] = 'e';   // most frequent → "E"
        key['j'] = 'q';   // from "jvaql" → "quick"
        key['k'] = 'r';   // "xpkcaqvnpk" → "particular"
        key['l'] = 'k';   // seen in pattern "lfdt" → "know"
        key['m'] = 'g';   // common middle consonant
        key['n'] = 'l';   // vowel occurring mid-word
        key['o'] = 'm';   // from patterns like "eao" → "him"
        key['p'] = 'a';   // appears alone → "a"
        key['q'] = 'c';   // "ipqe qpri" → "each case"
        key['r'] = 's';   // "tpr" → "was"
        key['s'] = 'v';   // auxiliary from frequency logic
        key['t'] = 'w';   // "tpr" → "was" (t = w, stylistic mapping)
        key['u'] = 'f';   // "du" → "of"
        key['v'] = 'u';   // rare consonant retained
        key['w'] = 'y';   // low frequency, filler
        key['x'] = 'p';   // "xpkcaqvnpk" → "particular"
        key['y'] = 'l';   // supportive replacement
        key['z'] = 'z';   // retained for completeness
    }

    std::string decrypt(const std::string &ciphertext) {
        std::string plaintext = "";

        for (char c : ciphertext) {
            if (std::isalpha(c)) {
                char lowerC = std::tolower(c);
                if (key.find(lowerC) != key.end()) {
                    char decryptedChar = key[lowerC];
                    if (std::isupper(c))
                        decryptedChar = std::toupper(decryptedChar);
                    plaintext += decryptedChar;
                } else {
                    plaintext += c;
                }
            } else {
                plaintext += c;
            }
        }
        return plaintext;
    }
};

int main() {
    std::string ciphertext =
        "af p xpkcaqvnpk pfg, af ipqe qpri, gauuikifc tpw, ceiri udvk tiki afgarxifrphni cd eaowvmd popkwn, hiqpvri du ear jvaql vfgikrcpfgafm du cei xkafqaxnir du xrwqedearcdkw pfg "
        "du ear aopmafpcasi xkdhafmr afcd fit pkipr. ac tpr qdoudkcafm cd lfdt cepc au pfwceafm "
        "epxxifig cd ringdf eaorinu hiudki cei opceiopcaqr du cei uaing qdvng hi qdoxnicinw tdklig dvcpfg edt rndtnw ac xkdqiigig, pfg edt odvfcpafdvr cei dhrcpqnirceiki tdvng pc niprc kiopaf dfi "
        "mddg oafg cepc tdvng qdfcafvi cei kiripkqe";

    SubstitutionCipher solver;
    std::string decryptedText = solver.decrypt(ciphertext);

    std::cout << decryptedText << std::endl;

    return 0;
}