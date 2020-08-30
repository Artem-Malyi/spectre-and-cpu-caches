/*
 * side_channel.cpp
 *      Demo of standard CPU cache side channel attack.
 *
 * based on the code from cppcon 2018 chandler carruth spectre talk:
 * https://www.youtube.com/watch?v=_f7O3IfIR2k
 * https://www.youtube.com/watch?v=IPhvL3A-e6E
 * 
 * good explanation on caches:
 * https://manybutfinite.com/post/intel-cpu-caches/
 * https://akkadia.org/drepper/cpumemory.pdf
 *
 * Todo: look into Branch Target Buffer to direct the jumps in kernel ?
 */

#include <algorithm>
#include <numeric>
#include <array>
#include <iostream>
#include <string_view>
#include <tuple>
#include <cstring>
#include <cctype>

#ifdef __linux__
#include <x86intrin.h>
#elif _WIN32
#include <intrin.h>
#endif

static constexpr std::string_view secret = "It's a secret!!!";

static void force_read(uint8_t *p) {
#ifdef __linux__
    asm volatile("" : : "r"(*p) : "memory");
#elif _WIN32
    __asm mov eax, p
    __asm mov eax, [eax]
#endif
}

static int64_t read_tsc() {
    unsigned int junk;
    return __rdtscp(&junk);
}

template <typename RangeT>
static std::pair<int, int> top_two_indices(const RangeT &range) {
    int j{ 0 }, k{ 0 };
    for (unsigned int i{ 0 }; i < range.size(); i++) {
        if (range[i] > range[j]) {
            k = j;
            j = i;
        }
        else if (range[i] > range[k]) {
            k = i;
        }
    }
    return { j, k };
}

//                   way 1           way 2           way 3           way 4           way 5           way 6           way 7           way 8
//               +------------+  +------------+  +------------+  +------------+  +------------+  +------------+  +------------+  +------------+
// cache line 1  | bytes 1-64 |  |            |  |            |  |            |  |            |  |            |  |            |  |            |
//               +------------+  +------------+  +------------+  +------------+  +------------+  +------------+  +------------+  +------------+
//               +------------+  +------------+  +------------+  +------------+  +------------+  +------------+  +------------+  +------------+
// cache line 2  | 64-128     |  |            |  |            |  |            |  |            |  |            |  |            |  |            |
//               +------------+  +------------+  +------------+  +------------+  +------------+  +------------+  +------------+  +------------+
//               +------------+  +------------+  +------------+  +------------+  +------------+  +------------+  +------------+  +------------+
// cache line 3  | 128-192    |  |            |  |            |  |            |  |            |  |            |  |            |  |            |
//               +------------+  +------------+  +------------+  +------------+  +------------+  +------------+  +------------+  +------------+
// ...           ...             ...             ...             ...             ...             ...             ...             ...
//               +------------+  +------------+  +------------+  +------------+  +------------+  +------------+  +------------+  +------------+
// cache line 64 | 4032-4096  |  |            |  |            |  |            |  |            |  |            |  |            |  |            |
//               +------------+  +------------+  +------------+  +------------+  +------------+  +------------+  +------------+  +------------+
//
// This particular cache has 8 ways. Each way is 64 cache lines 64 bytes each. So, 8 * 64 * 64 = 32768 (32kb L1 cache size).
// Each way is capable of containing data from one memory page of 4kb. 64 * 64 = 4096.
// Hence, each L1 data cache can hold up to 8 memory pages of 4kb at a time, different pages or copies of the same one.
//
// 

/*
 * perform cache attack against text[index] byte
 * In a real attack the attacker would be flushing cache and measuring while
 * the victim is doing the data-dependent read. In this demo they are done
 * together in the ideal order for the attacker.
 */
char leak_byte(std::string_view text, int index) {
    constexpr auto stride = 512; // 8 way-associative L1 cache has 8 cache lines in a row, each cache lins is 64 bytes 
    constexpr auto timing_array_size = 256; // this one must be the number of all possible values of a single byte 2^8 = 256
    constexpr auto data_dependent_reads = 100; // at least 1 read is enough to get text[index] byte into CPU cache, but the more the better

    static uint8_t timing_array[timing_array_size * stride];
    memset(timing_array, 1, sizeof(timing_array));

    const char* data = &text[0];

    std::array<int64_t, timing_array_size> latencies{};
    std::array<int, timing_array_size> scores{};
    int best_value = 0, runner_up_value{0};

    for (int run{0}; run < 100; ++run) { // more runs means more precise results
        // flush all of timing array
        for (int i{0}; i < timing_array_size; ++i)
            _mm_clflush(&timing_array[i * stride]);
        
        // perform reads that are data-dependent on the secret
        // as a program being attacked might
        for (int i{0}; i < data_dependent_reads; ++i)
            force_read(&timing_array[data[index] * stride]);
        // on first iteration the text[i] and one cache line of 64 bytes contains a string from buffer text
        // on subsequent iterations another 99 cahe lines are filled with 1s from timing_array, and data[index] each time is taken from 1st cache line 
        
        // now measure read latencies to see if we can detect what data[index] was
        for (int i{0}; i < timing_array_size; ++i) {
            int mixed_i = ((i * 167) + 13) & 0xff; // ???, I guess so we test in pseudo-random order?
            //std::cout << "mixed_i: " << mixed_i << std::endl;
            uint8_t* timing_entry = &timing_array[mixed_i * stride];
            int64_t start = read_tsc();
            force_read(timing_entry);
            latencies[mixed_i] = read_tsc() - start;
        }

        // score anything that stands out
        int64_t avg_latency{ std::accumulate(latencies.begin(), latencies.end(), (int64_t)0) / timing_array_size };
        for (int i{0}; i < timing_array_size; i++) {
            if (latencies[i] < (avg_latency * 3 / 4)) {
                ++scores[i];
            }
        }

        // see if any score is significantly better than the rest
        std::tie(best_value, runner_up_value) = top_two_indices(scores);
        if (scores[best_value] > (2 * scores[runner_up_value] + 400))
            break;        
    }

#if 0
    std::cerr << "Best score is '"
        << (std::isalnum(best_value) ? (char)best_value : '?') << "' ("
        << best_value << "): " << scores[best_value] << std::endl;
    std::cerr << "Runner up is '"
        << (std::isalnum(runner_up_value) ? (char)runner_up_value : '?') << "' ("
        << runner_up_value << "): " << scores[runner_up_value] << std::endl;
#endif

    return char(best_value);
}

int main(int argc, char **argv) {
    std::string leaked_string{};

    for (unsigned long i{0}; i < secret.size(); i++)
        leaked_string.push_back(leak_byte(secret, i));
    
    std::cout << "Leaking the string: " << leaked_string.c_str() << std::endl;

    return 0;
}