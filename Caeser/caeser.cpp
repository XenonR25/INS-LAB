#include <string>
#include <cctype>
#include <iostream>
#include <iomanip>
using namespace std;


string caesar_shift(const string &s, int shift) {
    string out;
    for (char ch : s) {
        if (isalpha(ch)) {
            int idx = ch - 'a';                 
            int new_idx = (idx - shift + 26) % 26; 
            out.push_back('a' + new_idx);        
        } else {
            out.push_back(ch);                
        }
    }
    return out;
}

int main() {
    string cipher = "odroboewscdrolocdcwkbdmyxdbkmdzvkdpybwyeddrobo";

    cout << "Brute-force Caesar decryption : All 26 shifts:\n\n";
    for (int shift = 0; shift < 26; ++shift) {
        string plain = caesar_shift(cipher, shift);
        cout << "Shift " << setw(2) << shift << " : " << plain << '\n';
    }

    cout << "\n This is the end of the brute-force output.\n";
    return 0;
}