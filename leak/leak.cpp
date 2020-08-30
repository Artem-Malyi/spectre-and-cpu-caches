#include <iostream>
#include <string>
#include <string_view> 

constexpr std::string_view text_table[] = { "Hello", "Hello, CppCon!", "It's a s3kr3t!" };

int main(int argc, char** argv) {
    int text_index = 0;
    if (argc > 1)
        text_index = std::stoi(argv[1]);
    std::cerr << "Text buffer index: " << text_index << std::endl;
    if (text_index > 1) {
        std::cerr << "ERROR: only two buffers are public!" << std::endl;
        exit(1);
    }

    std::string_view text = text_table[text_index];

    int length = text.size();
    if (argc > 2)
        length = std::stoi(argv[2]);
    std::cerr << "Length: " << length << std::endl;
    if (text.size() - length < 0) {
        std::cerr << "ERROR: buffer is only " << text.size() << " characters!" << std::endl;
        exit(1);
    }

    std::string_view to_print(&text[0], length);
    std::cout << to_print << std::endl;

    return 0;
}