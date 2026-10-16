// C++ runtime features the loader must support: static constructors and
// destructors, exceptions thrown and caught across modules, RTTI,
// thread_local with a destructor, std::thread, and iostreams.
#include <cstdio>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {
struct Global {
    std::string name = "global-ctor-ran";
    ~Global() { std::printf("global dtor\n"); }
} g_global;

struct PerThread {
    int value = 41;
};
thread_local PerThread t_value;
}  // namespace

extern "C" void cxx_throw(int code) {
    if (code) throw std::runtime_error("thrown from libcxx: " + std::to_string(code));
}

extern "C" int cxx_run(void) {
    int score = 0;
    if (g_global.name == "global-ctor-ran") score += 1;
    try {
        cxx_throw(7);
    } catch (const std::runtime_error &e) {
        if (std::string(e.what()) == "thrown from libcxx: 7") score += 2;
    }
    std::vector<int> seen(4);
    std::vector<std::thread> threads;
    for (int i = 0; i < 4; i++)
        threads.emplace_back([i, &seen] { t_value.value += i; seen[i] = t_value.value; });
    for (auto &t : threads) t.join();
    if (seen[0] == 41 && seen[3] == 44 && t_value.value == 41) score += 4;
    std::cout << "iostream ok" << std::endl;
    return score;  // 7 when everything works
}
