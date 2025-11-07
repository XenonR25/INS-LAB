#include <bits/stdc++.h>
using namespace std;


// ↓ English letter frequency (most → least common)
const string englishOrder = "etaonhisrdlcumwfgypbvkjxqz";

// Apply mapping to a ciphertext string
string applySubstitution(const string &text, const map<char,char> &key) {
    string out;
    out.reserve(text.size());
    for (char ch : text) {
        if (isalpha(ch)) {
            char low = tolower(ch);
            auto it = key.find(low);
            char plain = (it != key.end()) ? it->second : low;
            out += isupper(ch) ? toupper(plain) : plain;
        } else out += ch;
    }
    return out;
}

// Count letter frequencies
map<char,int> countFreq(const string &txt) {
    map<char,int> f;
    for (char c : txt)
        if (isalpha(c)) f[tolower(c)]++;
    return f;
}

// Enhanced scoring with more common words and bigrams
int scoreEnglish(const string &text) {
    static const vector<string> common = {
        "the","and","of","to","in","is","it","that","was","he","for",
        "on","as","with","at","his","they","be","by","this","had",
        "not","from","or","she","which","her","all","an","we","were",
        "when","their","more","said","one","you","who","but","been",
        "have","him","has","would","what","will","there","if","can",
        "out","up","now","new","way","may","part","made","after",
        "back","little","only","year","work","being","those","tell",
        "very","well","because","people","some","time","could","them",
        "other","into","any","just","come","know","should","how"
    };
    
    // Common bigrams
    static const vector<string> bigrams = {
        "th","he","in","er","an","ed","nd","to","en","ti",
        "es","or","te","of","ar","ou","it","ha","et","ng",
        "on","at","le","se","de","co","me","hi","ve","re"
    };
    
    int score = 0;
    string lower = text;
    transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    
    // Score common words (weighted by length)
    for (auto &w : common) {
        size_t pos = 0;
        while ((pos = lower.find(w, pos)) != string::npos) {
            // Check word boundaries
            bool valid = true;
            if (pos > 0 && isalpha(lower[pos-1])) valid = false;
            if (pos + w.length() < lower.length() && isalpha(lower[pos + w.length()])) valid = false;
            if (valid) score += w.length() * w.length(); // Square length for weight
            pos += w.length();
        }
    }
    
    // Score bigrams
    for (auto &bg : bigrams) {
        size_t count = 0;
        size_t pos = 0;
        while ((pos = lower.find(bg, pos)) != string::npos) {
            count++;
            pos++;
        }
        score += count * 3;
    }
    
    // Penalize uncommon letter combinations
    for (size_t i = 0; i < lower.length() - 1; i++) {
        if (isalpha(lower[i]) && isalpha(lower[i+1])) {
            string pair = lower.substr(i, 2);
            if (pair == "qq" || pair == "xx" || pair == "zz" || pair == "vv" ||
                pair == "jj" || pair == "kk" || pair == "ww") {
                score -= 10;
            }
        }
    }
    
    return score;
}

// Enhanced hill-climbing with random restarts
void optimise(map<char,char> &key, const string &cipher, int iterations = 100000) {
    mt19937 rng(random_device{}());
    vector<char> alphabet(26);
    iota(alphabet.begin(), alphabet.end(), 'a');
    
    map<char,char> bestGlobal = key;
    int bestGlobalScore = scoreEnglish(applySubstitution(cipher, key));
    
    // Multiple random restarts to avoid local minima
    for (int restart = 0; restart < 5; restart++) {
        map<char,char> currentKey = bestGlobal;
        
        // Random perturbation for restart
        if (restart > 0) {
            for (int swaps = 0; swaps < 5; swaps++) {
                int a = rng() % 26;
                int b = rng() % 26;
                if (a != b) {
                    char ca = alphabet[a];
                    char cb = alphabet[b];
                    for (auto &p : currentKey) {
                        if (p.second == ca) p.second = cb;
                        else if (p.second == cb) p.second = ca;
                    }
                }
            }
        }
        
        int best = scoreEnglish(applySubstitution(cipher, currentKey));
        
        // Hill climbing
        for (int i = 0; i < iterations / 5; ++i) {
            char a = alphabet[rng()%26];
            char b = alphabet[rng()%26];
            if (a == b) continue;
            
            map<char,char> trial = currentKey;
            for (auto &p : trial) {
                if (p.second == a) p.second = b;
                else if (p.second == b) p.second = a;
            }
            
            int sc = scoreEnglish(applySubstitution(cipher, trial));
            if (sc > best) {
                best = sc;
                currentKey.swap(trial);
            }
            
            // Occasionally accept worse solutions (simulated annealing)
            else if (i < iterations / 10 && (rng() % 1000) < 5) {
                currentKey.swap(trial);
                best = sc;
            }
        }
        
        // Update global best
        if (best > bestGlobalScore) {
            bestGlobalScore = best;
            bestGlobal = currentKey;
        }
    }
    
    key = bestGlobal;
}

int main() {
    ios::sync_with_stdio(false);
    cin.tie(nullptr);
    
    // Read ciphertext from stdin
    string cipher, line;
    while (getline(cin, line)) cipher += line + ' ';
    if (cipher.empty()) {
        cerr << "No input detected.\n";
        return 1;
    }
    
    // Initial frequency mapping
    auto freq = countFreq(cipher);
    vector<pair<char,int>> sorted(freq.begin(), freq.end());
    sort(sorted.begin(), sorted.end(),
         [](auto &a, auto &b){ return a.second > b.second; });
    
    map<char,char> key;
    for (size_t i=0; i<sorted.size() && i<englishOrder.size(); ++i)
        key[sorted[i].first] = englishOrder[i];
    
    cout << "Initial mapping generated, now refining...\n";
    
    // Enhanced optimization
    optimise(key, cipher, 150000);
    
    // Final output
    string plain = applySubstitution(cipher, key);
    cout << "\n=== Fully Decrypted Text ===\n";
    cout << plain << "\n";
    
    cout << "\nFinal mapping (cipher → plain):\n";
    for (char c = 'a'; c <= 'z'; c++) {
        if (key.count(c)) {
            cout << c << " → " << key[c] << '\n';
        }
    }
    
    return 0;
}